"""Gruparea alertelor in cazuri, inaintea modelului (faza 26).

Aici se taie cel mai mult volum: alertele identice (aceeasi regula, acelasi host, acelasi proces /
fisier / IP sursa / mesaj) devin UN caz cu contor, iar o regula care inunda de la aceeasi sursa
devine UN incident de potop in loc de cate o escaladare pe alerta.

Cheia de deduplicare, gruparea, plafonul si memoria cheilor vazute sunt EXACT cele din
orchestrator (mutate aici, nu rescrise); orchestratorul le importa de aici sub aceleasi nume.
Nou: `FloodTracker` si `plan_cycle`, care pune totul cap la cap si tine contabilitatea.

Totul e pur (fara Elasticsearch, fara model, fara retea); ceasul e injectabil.
"""
from __future__ import annotations

import hashlib
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from elasticlab.contracts.messages import AlertaNormalizata, Contabilitate


def _g(d: dict, path: str):
    if path in d:
        return d[path]
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


# --------------------------------------------------------------------------------------------
# Cheia de azi (mutata din orchestrator, neschimbata)
# --------------------------------------------------------------------------------------------


def dedup_key_alert(a: dict) -> str:
    """Doua alerte de la aceeasi regula, pe aceeasi entitate de proces, sunt
    acelasi caz — nu-l investigam de doua ori. Alertele fara proces si fara
    fisier (cereri web, autentificari) se separa dupa IP-ul sursa: altfel un al
    doilea atacator pe aceeasi regula ar fi sarit ca duplicat 24 de ore.
    Alertele din jurnal (YARA, AIDE, MySQL, auditd) n-au nici proces, nici fisier,
    nici IP: se separa dupa hash-ul mesajului, altfel a doua potrivire YARA pe alt
    fisier ar fi sarita ca duplicat 24 de ore (gasit la testul 3.E)."""
    msg = _g(a, "message")
    return "|".join(str(x) for x in [
        _g(a, "kibana.alert.rule.name"),
        _g(a, "host.name"),
        _g(a, "process.entity_id") or _g(a, "file.path") or _g(a, "source.ip")
        or (hashlib.sha256(msg.encode()).hexdigest()[:16] if isinstance(msg, str) and msg else ""),
    ])


CASE_MAX_REFS = 50


def group_alerts(alerts: list[dict]) -> list[tuple[str, list[dict]]]:
    """Pasul 10.2: alertele lotului grupate dupa cheia de deduplicare (aceeasi regula, acelasi
    host, acelasi proces / fisier / IP sursa), in ordinea primei aparitii. Un grup = un caz:
    se judeca o data (prima alerta), iar ID-urile celorlalte devin dovezi ale aceluiasi verdict.
    Alertele de host fara proces/fisier/IP raman separate (cheia lor include hash-ul mesajului).
    Pur."""
    groups: dict[str, list[dict]] = {}
    for a in alerts:
        groups.setdefault(dedup_key_alert(a), []).append(a)
    return list(groups.items())


def take_until_cap(alerts: list[dict], seen, cap: int) -> list[dict]:
    """Prefixul lotului (in ordinea timpului) care contine cel mult `cap` cazuri NOI.
    Duplicatele (cheie deja in `seen`) nu costa nimic si nu consuma plafonul: un flood de
    alerte identice se dreneaza intr-un ciclu, nu in ore. Masurat 2026-11-03: 1797 de alerte
    din auto-atac, cele mai multe duplicate, tineau cursorul 2 h 40 min in urma cu plafonul
    pe alerte brute -> un atac real ar fi fost vazut abia dupa. Pur."""
    if cap <= 0:
        return list(alerts)
    new_keys: set[str] = set()
    out: list[dict] = []
    for a in alerts:
        k = dedup_key_alert(a)
        if k not in seen and k not in new_keys:
            if len(new_keys) >= cap:
                break
            new_keys.add(k)
        out.append(a)
    return out


def case_extra(members: list[dict]) -> dict:
    """Ce se adauga in audit/verdict cand un caz are mai multe alerte. Pur."""
    if len(members) < 2:
        return {}
    ts = sorted(t for t in (_g(a, "@timestamp") for a in members) if t)
    return {"case_alert_count": len(members), "case_first_ts": ts[0] if ts else None,
            "case_last_ts": ts[-1] if ts else None}


# Cat timp ramane o cheie "vazuta". Dupa expirare, acelasi caz (ex. aceeasi
# pereche parinte-copil) se investigheaza din nou: un atac de saptamana viitoare
# nu are voie sa fie sarit doar pentru ca perechea a mai aparut o data.
SEEN_TTL_HOURS = float(os.environ.get("SEEN_TTL_HOURS", "24"))


class BoundedSeen:
    """Chei deja procesate, cu memorie limitata: un proces care ruleaza saptamani
    nu trebuie sa creasca la nesfarsit. Se uita cele mai vechi si cele expirate."""
    def __init__(self, maxlen: int = 5000, ttl_hours: float = SEEN_TTL_HOURS,
                 entries: list[tuple[str, float]] | None = None, clock=time.time):
        self._d: OrderedDict = OrderedDict()   # cheie -> epoch cand a fost marcata
        self.maxlen = maxlen
        self.ttl = ttl_hours * 3600
        self._clock = clock
        for k, t in sorted(entries or [], key=lambda e: e[1]):
            self._put(k, t)
        self._expire()

    def _put(self, k, t: float) -> None:
        self._d[k] = t
        self._d.move_to_end(k)
        if len(self._d) > self.maxlen:
            self._d.popitem(last=False)

    def _expire(self) -> None:
        limit = self._clock() - self.ttl
        while self._d and next(iter(self._d.values())) < limit:
            self._d.popitem(last=False)

    def __contains__(self, k) -> bool:
        self._expire()
        return k in self._d

    def __len__(self) -> int:
        self._expire()
        return len(self._d)

    def add(self, k) -> None:
        self._put(k, self._clock())

    def entries(self) -> list[tuple[str, float]]:
        """Cele mai vechi primele, ca la reincarcare sa se pastreze ordinea."""
        self._expire()
        return list(self._d.items())


# --------------------------------------------------------------------------------------------
# Potop: o regula care produce multe cazuri DISTINCTE de la aceeasi sursa
# --------------------------------------------------------------------------------------------

# Peste FLOOD_THRESHOLD cazuri noi pe (regula, sursa) in aceeasi fereastra de FLOOD_WINDOW_MIN
# minute (dupa momentul alertei, nu al prelucrarii), restul cazurilor din fereastra se strang
# intr-un singur incident de potop, escaladat la om din cod. 0 = oprit. Pragul se dimensioneaza
# dupa marimea rafalei stabilita cu firma; 20 = vechiul prag de restanta din degraded.py.
FLOOD_THRESHOLD = int(os.environ.get("FLOOD_THRESHOLD", "20"))
FLOOD_WINDOW_MIN = int(os.environ.get("FLOOD_WINDOW_MIN", "10"))


def flood_source(a: dict) -> str:
    """Sursa unui potop: IP-ul sursa daca alerta il are, altfel hostul. Pur."""
    return str(_g(a, "source.ip") or _g(a, "host.name") or "-")


class FloodTracker:
    """Numara cazurile noi pe (regula, sursa, fereastra). Primele `threshold` sunt cazuri
    obisnuite; de la al `threshold + 1`-lea, fereastra e in potop. Tine cel mult `maxlen`
    ferestre (cele mai vechi se uita: in cel mai rau caz un potop reincepe cu cazuri normale,
    adica mai multa munca, nu alerte pierdute)."""

    def __init__(self, threshold: int = FLOOD_THRESHOLD, window_min: int = FLOOD_WINDOW_MIN,
                 maxlen: int = 10_000):
        self.threshold = threshold
        self.window = timedelta(minutes=max(1, window_min))
        self.maxlen = maxlen
        self._n: OrderedDict[tuple[str, str, str], int] = OrderedDict()

    @property
    def enabled(self) -> bool:
        return self.threshold > 0

    def window_of(self, t: datetime | None) -> str:
        if t is None:
            return "fara-moment"
        t = t.astimezone(timezone.utc)
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        w = int((t - epoch) / self.window)
        return (epoch + w * self.window).strftime("%Y-%m-%dT%H:%M:%SZ")

    def flooding(self, key: tuple[str, str, str]) -> bool:
        return self.enabled and self._n.get(key, 0) >= self.threshold

    def count(self, key: tuple[str, str, str]) -> None:
        self._n[key] = self._n.get(key, 0) + 1
        self._n.move_to_end(key)
        while len(self._n) > self.maxlen:
            self._n.popitem(last=False)


@dataclass
class FloodCase:
    """Un incident de potop: o regula, o sursa, o fereastra; alertele absorbite in el."""
    key: str
    rule: str | None
    source: str
    window: str
    host: str | None
    members: list[dict] = field(default_factory=list)
    distinct_keys: set[str] = field(default_factory=set)


def flood_key(rule: str | None, source: str, window: str) -> str:
    return f"potop|{rule}|{source}|{window}"


# --------------------------------------------------------------------------------------------
# Un ciclu de intrare, cap la cap
# --------------------------------------------------------------------------------------------


@dataclass
class PlanCiclu:
    """Ce iese din intrare pentru un ciclu.

    `alerts` = prefixul consumat, fara alertele absorbite in potop, in ordinea timpului; merge
    in `process_alerts` exact cum mergea iesirea lui `take_until_cap`. `floods` = incidentele de
    potop NOI (cele deja emise intr-un ciclu anterior nu se mai emit). `critical` = alertele din
    clasele critice care deschid un caz nou, din TOT ce s-a citit (si din partea amanata): ele se
    notifica la intrare, indiferent de plafon. `last_ts` = @timestamp-ul ultimei alerte consumate."""
    alerts: list[dict]
    floods: list[FloodCase]
    critical: list[AlertaNormalizata]
    acct: Contabilitate
    last_ts: str | None


def plan_cycle(alerts: list[dict], seen, cap: int, *,
               normalize: Callable[[dict], AlertaNormalizata | None],
               flood: FloodTracker | None = None, truncated: bool = False,
               pages: int = 0) -> PlanCiclu:
    """Alertele citite (cele mai vechi intai) -> cazuri, potop, contabilitate. Pur.

    Fara potop (`flood=None` sau prag 0), `alerts` din rezultat e identic cu
    `take_until_cap(alerts, seen, cap)`: aceleasi cazuri ca pe calea veche.
    Clasele critice nu intra niciodata in potop."""
    acct = Contabilitate(citite=len(alerts), trunchiat=truncated, pagini=pages)
    norm: list[AlertaNormalizata | None] = []
    for a in alerts:
        n = normalize(a)
        if n is None:
            acct.respinse += 1
        norm.append(n)

    # Clasele critice: din tot lotul, inainte de plafon (notificarea nu asteapta coada).
    crit_keys: set[str] = set()
    critical: list[AlertaNormalizata] = []
    for n in norm:
        if n is not None and n.critical is not None:
            acct.critice += 1
            if n.dedup_key not in seen and n.dedup_key not in crit_keys:
                crit_keys.add(n.dedup_key)
                critical.append(n)

    out: list[dict] = []
    case_keys: set[str] = set()
    absorbed: dict[str, str] = {}          # cheia alertei -> cheia potopului in care a intrat
    floods: dict[str, FloodCase] = {}
    consumed = 0
    for a, n in zip(alerts, norm):
        k = n.dedup_key if n is not None else dedup_key_alert(a)
        if k in case_keys or k in seen:
            acct.grupate += 1
            out.append(a)
            consumed += 1
            continue
        if k in absorbed:
            floods[absorbed[k]].members.append(a)
            acct.in_potop += 1
            consumed += 1
            continue
        is_critical = n is not None and n.critical is not None
        fk = None
        if flood is not None and flood.enabled and not is_critical:
            rule = _g(a, "kibana.alert.rule.name")
            fk = (str(rule), flood_source(a), flood.window_of(n.event_at if n else None))
            if flood.flooding(fk):
                key = flood_key(*fk)
                fc = floods.get(key)
                if fc is None:
                    fc = floods[key] = FloodCase(key=key, rule=rule, source=fk[1], window=fk[2],
                                                 host=_g(a, "host.name"))
                fc.members.append(a)
                fc.distinct_keys.add(k)
                absorbed[k] = key
                acct.in_potop += 1
                consumed += 1
                continue
        if cap > 0 and len(case_keys) >= cap:
            break                               # plafonul de cazuri: restul ramane pentru ciclul urmator
        case_keys.add(k)
        if fk is not None:
            flood.count(fk)
        acct.cazuri += 1
        out.append(a)
        consumed += 1

    acct.consumate = consumed
    acct.amanate = len(alerts) - consumed
    new_floods = [fc for key, fc in floods.items() if key not in seen]
    acct.incidente_potop = len(new_floods)
    last_ts = max((_g(a, "@timestamp") or "" for a in alerts[:consumed]), default="") or None
    return PlanCiclu(alerts=out, floods=new_floods, critical=critical, acct=acct, last_ts=last_ts)

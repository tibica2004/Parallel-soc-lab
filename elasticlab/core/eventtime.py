"""
TIMPUL ALERTEI — ferestrele logicii de verdict se socotesc fata de momentul alertei,
nu fata de momentul prelucrarii (faza 25, docs/plan-refactorizare.md).

De ce: pe cozi (faza 29) o alerta poate fi prelucrata cu intarziere. O fereastra
`NOW() - 15 minutes` socotita la prelucrare ar cadea langa eveniment, nu pe el, si
verdictul ar depinde de cat a stat alerta in coada.

Regula: fereastra pentru o ancora `t` si un pas inapoi `b` e [t - b, t + DUPA_EVENIMENT].
`DUPA_EVENIMENT` lasa sa intre ce urmeaza imediat evenimentului (conexiunea unui shell
invers, copilul unui proces). La prelucrare imediata limita de sus e oricum in viitor,
deci se vede tot ce exista, ca inainte; la prelucrare intarziata nu intra ce s-a
intamplat dupa.

Fara ancora (None) functiile intorc EXACT forma veche, relativa la NOW(): apelurile care
nu au un moment (sweep-urile programate, Tier 3, uneltele chemate din afara Tier 2)
raman neschimbate.

Timeout-urile pe caz si ceasul de garda raman pe timpul real; nu trec pe aici.

Functiile sunt pure (primesc ancora explicit). Singura stare e `_ANCHOR`: ancora cazului
pe care o citesc uneltele Tier 2. Uneltele le cheama modelul cu argumentele lui, deci
ancora nu poate fi argument fara sa schimbe schema uneltelor (si setul de prompturi);
o variabila de context se copiaza de LangGraph in firele care ruleaza uneltele.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from typing import Iterator

# Cat dupa eveniment intra in fereastra. Prelucrarea imediata de azi vede evenimentele cu
# cateva minute dupa alerta (regulile ruleaza la 5 minute, orchestratorul la un ciclu dupa);
# 10 minute acopera intarzierea obisnuita fara sa lase sa intre ora urmatoare.
DUPA_EVENIMENT = timedelta(minutes=10)

# Unitatile folosite in interogari: nume ES|QL -> sufix pentru Query DSL ("now-15m").
_UNITS = {"minutes": "m", "hours": "h", "days": "d"}

_ANCHOR: ContextVar[datetime | None] = ContextVar("soc_event_anchor", default=None)


def _g(d: dict, path: str):
    """Camp din alerta, plat ('a.b.c') sau imbricat."""
    if not isinstance(d, dict):
        return None
    if path in d:
        return d[path]
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def parse(v) -> datetime | None:
    """ISO 8601 sau datetime -> datetime in UTC. None pentru orice altceva (fara exceptie):
    un timp care nu se poate citi inseamna fara ancora, deci forma veche."""
    if isinstance(v, datetime):
        t = v
    elif isinstance(v, str) and v:
        try:
            t = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t.astimezone(timezone.utc)


def alert_time(alert: dict) -> datetime | None:
    """Momentul alertei = ora evenimentului care a declansat-o (kibana.alert.original_time),
    altfel @timestamp. Acelasi camp ca fast_path.event_time (fereastra de mentenanta)."""
    return parse(_g(alert, "kibana.alert.original_time")) or parse(_g(alert, "@timestamp"))


def iso(t: datetime) -> str:
    """Forma pe care o accepta TO_DATETIME din ES|QL: yyyy-MM-ddTHH:mm:ss.SSSZ, in UTC."""
    t = t.astimezone(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _delta(amount: int, unit: str) -> timedelta:
    if unit not in _UNITS:
        raise ValueError(f"unitate necunoscuta: {unit!r} (minutes, hours, days)")
    return timedelta(**{unit: int(amount)})


def bounds(anchor: datetime, back: timedelta, after: timedelta = DUPA_EVENIMENT) -> tuple[datetime, datetime]:
    """[ancora - back, ancora + after]."""
    return anchor - back, anchor + after


def esql_window(anchor: datetime | None, amount: int, unit: str) -> tuple[str, list[str]]:
    """Conditia pe @timestamp pentru ES|QL si parametrii ei (pozitionali, in ordine).
    Fara ancora: textul vechi `@timestamp >= NOW() - N unit`, fara parametri.
    Numarul e int (nu text din afara); timpii merg ca parametri, nu in textul interogarii."""
    amount = int(amount)
    d = _delta(amount, unit)
    if anchor is None:
        return f"@timestamp >= NOW() - {amount} {unit}", []
    lo, hi = bounds(anchor, d)
    return "@timestamp >= TO_DATETIME(?) AND @timestamp <= TO_DATETIME(?)", [iso(lo), iso(hi)]


def dsl_range(anchor: datetime | None, amount: int, unit: str) -> dict:
    """Intervalul pe @timestamp pentru Query DSL / EQL. Fara ancora: {"gte": "now-15m"} ca inainte."""
    amount = int(amount)
    d = _delta(amount, unit)
    if anchor is None:
        return {"gte": f"now-{amount}{_UNITS[unit]}"}
    lo, hi = bounds(anchor, d)
    return {"gte": iso(lo), "lte": iso(hi)}


def until(anchor: datetime | None) -> dict | None:
    """Doar documentele scrise pana la momentul alertei (istoricul de verdicte): ce se
    stia cand a aparut alerta, nu ce s-a scris in timp ce astepta in coada.
    Fara ancora: None (fara filtru, ca inainte)."""
    return None if anchor is None else {"range": {"@timestamp": {"lte": iso(anchor)}}}


@contextmanager
def anchored(anchor: datetime | None) -> Iterator[None]:
    """Ancora cazului pentru uneltele chemate in interiorul blocului."""
    tok = _ANCHOR.set(anchor)
    try:
        yield
    finally:
        _ANCHOR.reset(tok)


def current() -> datetime | None:
    """Ancora cazului in curs (None in afara unei investigatii Tier 2 = forma veche)."""
    return _ANCHOR.get()

"""
TIER 3 — GRUPAREA IN INCIDENTE. Determinista; modelul scrie doar naratiunea.

Intrarea: verdictele din verdicts-history care NU au fost inchise (cel putin un
verdict non-benign pe lant), cate un membru per chain_id (Tier 1 + Tier 2 ale
aceluiasi lant sunt acelasi membru). Liniajul procesului (entity_id, parinte,
process.Ext.ancestry) vine din alerta trimisa de evidence_refs.

Legaturile (decizia lui Tiberiu, 2026-10-13):
  1. TIMP: acelasi host, cel mult GAP_MIN intre membri consecutivi, plafon
     SPAN_H per segment.
  2. STRAMOSI: doua segmente se unesc daca au un stramos comun SPECIFIC si sunt
     la cel mult ANCESTRY_H unul de altul. Nu leaga nimic: procesele de serviciu
     de lunga durata (SERVICE_ROOTS, dupa nume: systemd, sshd, apache2 - master
     si workeri) si stramosii prezenti la peste jumatate din membrii hostului.
Un incident are minimum MIN_MEMBERS membri.

Tier 3 deschide si uneste incidente; NU le inchide (principiul 6). Un incident
inchis de om nu se redeschide: lanturile lui nu mai intra in altul.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas import MITRE_RE

VERDICTS_IDX = "verdicts-history"
ALERTS_IDX = ".alerts-security.alerts-*"
INCIDENTS_IDX = "soc-incidents"

GAP_MIN = 30
SPAN_H = 6
ANCESTRY_H = 24
COMMON_ROOT_FRAC = 0.5
# Procese de serviciu de lunga durata: stramosi ai aproape a tot ce ruleaza pe
# host (webshell -> worker apache -> master apache -> systemd), deci nu leaga
# doua actiuni intre ele. sshd-session NU e aici: e o sesiune de login anume.
SERVICE_ROOTS = frozenset({
    "systemd", "init", "sshd", "apache2", "httpd", "nginx", "php-fpm", "php-fpm8.3", "php-fpm8.4",
    "cron", "crond", "containerd", "dockerd", "elastic-agent", "elastic-endpoint",
    "rsyslogd", "systemd-journald", "dbus-daemon", "agetty", "login",
})
PROC_IDX = "logs-endpoint.events.process-*"
MIN_MEMBERS = 2
MAX_MEMBERS = 200
MAX_VERDICTS = 5000
OPEN_CLASSES = ("suspicious", "malicious", "undetermined")
SEVERITY = {"undetermined": 1, "suspicious": 2, "malicious": 3}
ENTITY_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{4,128}$")
CHAIN_RE = re.compile(r"^[A-Za-z0-9\-]{8,64}$")


class LinkKind(str, Enum):
    TIME = "time"
    ANCESTRY = "ancestry"


class IncidentStatus(str, Enum):
    OPEN = "open"
    CLOSED = "closed"   # doar omul il pune (interfata); Tier 3 nu scrie niciodata valoarea asta


class Incident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    host: str = Field(min_length=1, max_length=255)
    status: IncidentStatus = IncidentStatus.OPEN
    first_seen: datetime
    last_seen: datetime
    chain_ids: list[str] = Field(min_length=MIN_MEMBERS, max_length=MAX_MEMBERS)
    verdict_ids: list[str] = Field(max_length=4 * MAX_MEMBERS)
    rules: list[str] = Field(max_length=50)
    techniques: list[str] = Field(max_length=50)
    max_classification: str
    links: list[LinkKind]
    created_by: str = "tier3"
    # text liber al modelului: DOAR pentru om / audit, nu trece in nicio actiune
    narrative: str | None = Field(default=None, max_length=4000)
    narrative_model: str | None = None

    @field_validator("chain_ids")
    @classmethod
    def _chains(cls, v):
        for c in v:
            if not CHAIN_RE.match(c):
                raise ValueError(f"chain_id invalid: {c!r}")
        return v

    @field_validator("techniques")
    @classmethod
    def _tech(cls, v):
        return [t for t in v if MITRE_RE.match(t)]

    @field_validator("max_classification")
    @classmethod
    def _cls(cls, v):
        if v not in SEVERITY:
            raise ValueError(f"clasificare invalida: {v!r}")
        return v


@dataclass(frozen=True)
class Member:
    """Un lant (chain_id) cu tot ce trebuie pentru grupare si naratiune."""
    chain_id: str
    host: str
    ts: datetime
    verdict_ids: tuple[str, ...]
    rules: tuple[str, ...]
    classification: str
    techniques: tuple[str, ...]
    lineage: frozenset = field(default_factory=frozenset)   # entity_id, parinte, stramosi
    process: dict = field(default_factory=dict)              # pentru naratiune, trunchiat


# ------------------------------------------------------------------------------
# Functii pure
# ------------------------------------------------------------------------------

def _ts(s) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _g(d: dict, path: str):
    if path in d:
        return d[path]
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def lineage_of(alert: dict) -> frozenset:
    ids = [_g(alert, "process.entity_id"), _g(alert, "process.parent.entity_id")]
    anc = _g(alert, "process.Ext.ancestry")
    if isinstance(anc, list):
        ids += anc[:20]
    return frozenset(i for i in ids if isinstance(i, str) and ENTITY_RE.match(i))


def process_summary(alert: dict) -> dict:
    return {"user": str(_g(alert, "user.name") or "")[:64],
            "parent": str(_g(alert, "process.parent.name") or "")[:64],
            "process": str(_g(alert, "process.name") or "")[:64],
            "command_line": str(_g(alert, "process.command_line") or "")[:200]}


def members_from(verdicts: list[dict], alerts_by_id: dict[str, dict]) -> list[Member]:
    """Verdicte (cu _id) -> un membru per chain_id. Lantul intra doar daca are
    cel putin un verdict neinchis; timpul = cea mai veche dovada (evenimentul)."""
    by_chain: dict[str, list[dict]] = {}
    for v in verdicts:
        c = v.get("chain_id")
        if isinstance(c, str) and CHAIN_RE.match(c) and v.get("entity_type") == "host":
            by_chain.setdefault(c, []).append(v)
    out = []
    for c, vs in by_chain.items():
        if not any(v.get("classification") in OPEN_CLASSES for v in vs):
            continue
        times, alert = [], None
        for v in vs:
            for r in v.get("evidence_refs") or []:
                t = _ts(r.get("timestamp"))
                if t:
                    times.append(t)
                if alert is None and r.get("doc_id") in alerts_by_id:
                    alert = alerts_by_id[r["doc_id"]]
            t = _ts(v.get("@timestamp"))
            if t and not times:
                times.append(t)
        if not times:
            continue
        cls = max((v.get("classification") for v in vs if v.get("classification") in SEVERITY),
                  key=SEVERITY.get, default="undetermined")
        techs = sorted({t for v in vs for t in (v.get("mitre_techniques") or [])
                        if isinstance(t, str) and MITRE_RE.match(t)})
        out.append(Member(
            chain_id=c, host=str(vs[0].get("entity_id") or ""), ts=min(times),
            verdict_ids=tuple(sorted(v["_id"] for v in vs if v.get("_id"))),
            rules=tuple(sorted({str(v.get("rule_name"))[:256] for v in vs if v.get("rule_name")})),
            classification=cls, techniques=tuple(techs),
            lineage=lineage_of(alert) if alert else frozenset(),
            process=process_summary(alert) if alert else {}))
    return sorted(out, key=lambda m: (m.host, m.ts, m.chain_id))


def common_roots(members: list[Member], frac: float = COMMON_ROOT_FRAC) -> set[str]:
    """Stramosii prea comuni ca sa insemne ceva: prezenti la peste `frac` din
    membrii aceluiasi host."""
    out: set[str] = set()
    hosts: dict[str, list[Member]] = {}
    for m in members:
        hosts.setdefault(m.host, []).append(m)
    for ms in hosts.values():
        counts: dict[str, int] = {}
        for m in ms:
            for i in m.lineage:
                counts[i] = counts.get(i, 0) + 1
        out |= {i for i, n in counts.items() if n > frac * len(ms)}
    return out


def _segments(ms: list[Member], gap: timedelta, span: timedelta) -> list[list[Member]]:
    segs: list[list[Member]] = []
    for m in sorted(ms, key=lambda x: (x.ts, x.chain_id)):
        if segs and m.ts - segs[-1][-1].ts <= gap and m.ts - segs[-1][0].ts <= span:
            segs[-1].append(m)
        else:
            segs.append([m])
    return segs


def _distance(a: list[Member], b: list[Member]) -> timedelta:
    if a[-1].ts < b[0].ts:
        return b[0].ts - a[-1].ts
    if b[-1].ts < a[0].ts:
        return a[0].ts - b[-1].ts
    return timedelta(0)


def cluster(members: list[Member], gap_min: int = GAP_MIN, span_h: int = SPAN_H,
            ancestry_h: int = ANCESTRY_H, generic: set[str] | frozenset = frozenset()
            ) -> list[tuple[list[Member], set[LinkKind]]]:
    """Grupurile (membri, tipurile de legatura folosite). Determinist: aceeasi
    intrare -> aceleasi grupuri, in aceeasi ordine. `generic` = entity_id-urile
    proceselor de serviciu (vezi generic_ids)."""
    roots = common_roots(members) | set(generic)
    out = []
    hosts: dict[str, list[Member]] = {}
    for m in members:
        hosts.setdefault(m.host, []).append(m)
    for host in sorted(hosts):
        segs = _segments(hosts[host], timedelta(minutes=gap_min), timedelta(hours=span_h))
        parent = list(range(len(segs)))

        def find(i):
            while parent[i] != i:
                parent[i] = parent[parent[i]]
                i = parent[i]
            return i

        spec = [set().union(*(m.lineage for m in s)) - roots for s in segs]
        for i in range(len(segs)):
            for j in range(i + 1, len(segs)):
                if (spec[i] & spec[j]) and _distance(segs[i], segs[j]) <= timedelta(hours=ancestry_h):
                    ri, rj = find(i), find(j)
                    if ri != rj:
                        parent[max(ri, rj)] = min(ri, rj)
        groups: dict[int, list[Member]] = {}
        links: dict[int, set[LinkKind]] = {}
        n_segs: dict[int, int] = {}
        for i, s in enumerate(segs):
            r = find(i)
            groups.setdefault(r, []).extend(s)
            n_segs[r] = n_segs.get(r, 0) + 1
            if len(s) > 1:
                links.setdefault(r, set()).add(LinkKind.TIME)
        for r, ms in groups.items():
            if len(ms) < MIN_MEMBERS:
                continue
            ks = set(links.get(r, set()))
            if n_segs[r] > 1:
                ks.add(LinkKind.ANCESTRY)
            ms = sorted(ms, key=lambda x: (x.ts, x.chain_id))
            out.append((ms[:MAX_MEMBERS], ks))
    return sorted(out, key=lambda g: (g[0][0].host, g[0][0].ts))


def incident_id(host: str, first_chain: str) -> str:
    return hashlib.sha256(f"{host}|{first_chain}".encode()).hexdigest()[:32]


def build_incident(ms: list[Member], links: set[LinkKind]) -> Incident:
    return Incident(
        incident_id=incident_id(ms[0].host, ms[0].chain_id),
        host=ms[0].host,
        first_seen=ms[0].ts, last_seen=ms[-1].ts,
        chain_ids=[m.chain_id for m in ms],
        verdict_ids=sorted({v for m in ms for v in m.verdict_ids}),
        rules=sorted({r for m in ms for r in m.rules})[:50],
        techniques=sorted({t for m in ms for t in m.techniques})[:50],
        max_classification=max((m.classification for m in ms), key=SEVERITY.get),
        links=sorted(links, key=lambda k: k.value),
    )


def closed_chains(existing: list[dict]) -> set[str]:
    return {c for e in existing if e.get("status") == IncidentStatus.CLOSED.value
            for c in e.get("chain_ids") or []}


def without_closed(members: list[Member], existing: list[dict]) -> list[Member]:
    """Lanturile dintr-un incident inchis de om nu mai intra in grupare deloc."""
    done = closed_chains(existing)
    return [m for m in members if m.chain_id not in done]


def reconcile(new: list[Incident], existing: list[dict]) -> list[Incident]:
    """Incidentele noi fata de cele deja scrise:
      - suprapunere cu un incident DESCHIS -> se unesc sub id-ul existent (membrii
        doar se adauga, nu se scot; first/last se extind);
      - lanturile dintr-un incident INCHIS de om nu mai intra nicaieri; daca raman
        sub MIN_MEMBERS, incidentul nou nu se mai deschide."""
    done = closed_chains(existing)
    closed_ids = {e.get("incident_id") for e in existing if e.get("status") == IncidentStatus.CLOSED.value}
    open_by_chain = {c: e for e in existing if e.get("status") == IncidentStatus.OPEN.value
                     for c in e.get("chain_ids") or []}
    out: dict[str, Incident] = {}
    for inc in new:
        chains = [c for c in inc.chain_ids if c not in done]
        if len(chains) < MIN_MEMBERS:
            continue
        base = next((open_by_chain[c] for c in chains if c in open_by_chain), None)
        if base is not None:
            prev = out.get(base["incident_id"])
            old_chains = list(prev.chain_ids) if prev else list(base.get("chain_ids") or [])
            merged_chains = old_chains + [c for c in chains if c not in old_chains]
            old_verdicts = set(prev.verdict_ids if prev else base.get("verdict_ids") or [])
            first = min(inc.first_seen, prev.first_seen if prev else _ts(base["first_seen"]))
            last = max(inc.last_seen, prev.last_seen if prev else _ts(base["last_seen"]))
            old_rules = set(prev.rules if prev else base.get("rules") or [])
            old_tech = set(prev.techniques if prev else base.get("techniques") or [])
            old_links = set(prev.links if prev else [LinkKind(x) for x in base.get("links") or []])
            old_cls = prev.max_classification if prev else base.get("max_classification", "undetermined")
            inc = inc.model_copy(update={
                "incident_id": base["incident_id"],
                "chain_ids": merged_chains[:MAX_MEMBERS],
                "verdict_ids": sorted(old_verdicts | set(inc.verdict_ids)),
                "first_seen": first, "last_seen": last,
                "rules": sorted(old_rules | set(inc.rules))[:50],
                "techniques": sorted(old_tech | set(inc.techniques))[:50],
                "links": sorted(old_links | set(inc.links), key=lambda k: k.value),
                "max_classification": max(old_cls, inc.max_classification, key=SEVERITY.get),
            })
        elif chains != inc.chain_ids:
            # id-ul vine din primul lant; daca acela era al unui incident inchis,
            # pastrarea lui ar suprascrie decizia omului
            inc = inc.model_copy(update={"chain_ids": chains,
                                         "incident_id": incident_id(inc.host, chains[0])})
        if inc.incident_id in closed_ids:
            # acelasi prim lant ca un incident inchis, dar membri noi: incident nou,
            # cu alt id (vizibilitatea nu se pierde, decizia omului ramane neatinsa)
            inc = inc.model_copy(update={"incident_id": incident_id(inc.host, "|".join(chains))})
        out[inc.incident_id] = Incident.model_validate(inc.model_dump())
    return list(out.values())


# ------------------------------------------------------------------------------
# Elasticsearch (doar citire aici; scrierea e in tier3.py)
# ------------------------------------------------------------------------------

def fetch_verdicts(es, since: datetime, until: datetime) -> list[dict]:
    r = es.search(index=VERDICTS_IDX, size=MAX_VERDICTS, sort=[{"@timestamp": "asc"}],
                  query={"bool": {"filter": [
                      {"term": {"entity_type.keyword": "host"}},
                      {"range": {"@timestamp": {"gte": since.isoformat(), "lte": until.isoformat()}}},
                  ]}})
    return [{**h["_source"], "_id": h["_id"]} for h in r["hits"]["hits"]]


def fetch_alerts(es, doc_ids: list[str]) -> dict[str, dict]:
    ids = sorted({d for d in doc_ids if isinstance(d, str) and re.fullmatch(r"[A-Za-z0-9_\-]{8,128}", d)})
    out: dict[str, dict] = {}
    for i in range(0, len(ids), 500):
        chunk = ids[i:i + 500]
        r = es.search(index=ALERTS_IDX, size=len(chunk), query={"ids": {"values": chunk}},
                      source=["process.entity_id", "process.parent.entity_id", "process.Ext.ancestry",
                              "process.name", "process.parent.name", "process.command_line", "user.name"])
        out.update({h["_id"]: h["_source"] for h in r["hits"]["hits"]})
    return out


def fetch_existing(es) -> list[dict]:
    """Incidentele deja scrise. Indexul lipsa sau fara drepturi -> lista goala
    (in dry-run nu e o problema; la scriere, eroarea apare acolo)."""
    try:
        r = es.search(index=INCIDENTS_IDX, size=1000, query={"match_all": {}}, seq_no_primary_term=True)
    except Exception:
        return []
    # _seq_no/_primary_term: scrierea foloseste controlul de concurenta, ca un
    # incident inchis de om intre citire si scriere sa nu fie suprascris
    return [{**h["_source"], "_seq_no": h["_seq_no"], "_primary_term": h["_primary_term"]}
            for h in r["hits"]["hits"]]


def generic_ids(names: dict[str, str]) -> set[str]:
    """Functie pura: entity_id -> nume proces => cele care sunt servicii."""
    return {i for i, n in names.items() if isinstance(n, str) and n in SERVICE_ROOTS}


def fetch_process_names(es, ids: set[str]) -> dict[str, str]:
    """Numele proceselor dupa entity_id (filtru terms, fara text interpolat)."""
    ids = sorted(i for i in ids if ENTITY_RE.match(i))
    out: dict[str, str] = {}
    for i in range(0, len(ids), 1000):
        chunk = ids[i:i + 1000]
        r = es.search(index=PROC_IDX, size=0, query={"terms": {"process.entity_id": chunk}},
                      aggs={"e": {"terms": {"field": "process.entity_id", "size": len(chunk)},
                                  "aggs": {"n": {"terms": {"field": "process.name", "size": 1}}}}})
        for b in r["aggregations"]["e"]["buckets"]:
            if b["n"]["buckets"]:
                out[b["key"]] = b["n"]["buckets"][0]["key"]
    return out


def collect(es, since: datetime, until: datetime) -> tuple[list[Member], set[str]]:
    """Membrii si entity_id-urile proceselor de serviciu dintre stramosii lor."""
    vs = fetch_verdicts(es, since, until)
    refs = [r.get("doc_id") for v in vs for r in v.get("evidence_refs") or []]
    ms = members_from(vs, fetch_alerts(es, refs))
    names = fetch_process_names(es, set().union(*(m.lineage for m in ms)) if ms else set())
    return ms, generic_ids(names)

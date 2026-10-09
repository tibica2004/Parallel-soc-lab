"""
Stratul de unelte. Se construieste si se testeaza INAINTEA agentilor.
Daca astea nu returneaza ce trebuie cand le apelezi de mana, agentul n-are nicio sansa.

Doua categorii, tinute strict separate:

  LOOKUP  — determinist, fara LLM, preadus. Interogare previzibila cu una-doua
            variabile. Nu bagi agent aici: e mai lent si mai scump degeaba.
  TOOL    — expus agentului de hunting prin tool calling, pentru cand NU stii
            dinainte ce sa ceri.

Cheia API e read-only, cu privilegii pe indici anume. Nu superuser.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

from elasticsearch import Elasticsearch
from langchain_core.tools import tool

from schemas import ContextPack, EntityType, EvidenceRef, RarityFinding
from tracing import traced_tool


def _traced(fn):
    """Fiecare apel al uneltei ajunge in urma cazului (tracing.py): argumente,
    durata, ID-urile documentelor. Modelul primeste rezultatul fara _id/_index."""
    return traced_tool(fn.__name__, fn)

ES = Elasticsearch(
    os.environ.get("ES_URL", "http://localhost:9200"),
    # rol: read pe logs-*, .alerts-*, baseline-*, asset-inventory, verdicts-history
    api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"],
    request_timeout=30,
)

PROC_IDX = "logs-endpoint.events.process-*"
NET_IDX = "logs-endpoint.events.network-*"
FILE_IDX = "logs-endpoint.events.file-*"
APACHE_IDX = "logs-apache.access-*"
SURICATA_IDX = "logs-suricata.eve-*"
BASELINE_IDX = "baseline-entity-*"  # produs de transforms, vezi transforms/ in README

WEB_PARENTS = ["apache2", "httpd", "php-fpm", "nginx"]
SHELLS = ["sh", "bash", "dash", "zsh", "python3", "perl", "curl", "wget", "nc", "ncat"]


def _refs(hits: list[dict]) -> list[EvidenceRef]:
    """Doar identificatori. Niciodata continut."""
    return [
        EvidenceRef(
            index=h["_index"],
            doc_id=h["_id"],
            timestamp=datetime.fromisoformat(h["_source"]["@timestamp"].replace("Z", "+00:00")),
        )
        for h in hits[:50]
    ]


def _esql(query: str, params: list[Any] | None = None) -> list[dict]:
    resp = ES.esql.query(query=query, params=params or [], format="json")
    cols = [c["name"] for c in resp["columns"]]
    return [dict(zip(cols, row)) for row in resp["values"]]


# --------------------------------------------------------------------------
# LOOKUP-uri — preaduse, deterministe, fara LLM
# --------------------------------------------------------------------------


def lookup_investigation_guide(rule_id: str) -> str | None:
    """
    Ghidul per-regula pe care il scrii TU, in git, langa regula.
    Instructiune primara pentru agent; protocolul generic e doar fallback.
    Cea mai buna investitie de timp din proiect, si e gratis daca o faci din start.
    """
    path = f"detections/{rule_id}/investigation_guide.md"
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


def lookup_asset_context(host_id: str) -> dict:
    """Echivalentul lookup-ului lor in Workday: cine detine, cat de critic, ce e expus."""
    rows = _esql(
        """
        FROM asset-inventory
        | WHERE host.id == ?
        | KEEP criticality, owner, exposed_services, open_cves
        | LIMIT 1
        """,
        params=[host_id],
    )
    return rows[0] if rows else {}


def lookup_entity_baseline(entity_type: EntityType, entity_id: str) -> dict:
    """
    Din indexul de baseline intretinut de transform. NU calculat la runtime —
    ar dura secunde bune si l-ai plati la fiecare investigatie.
    """
    rows = _esql(
        """
        FROM baseline-entity-*
        | WHERE entity_type == ? AND entity_id == ?
        | KEEP first_seen, events_90d, common_parents, common_destinations
        | LIMIT 1
        """,
        params=[entity_type.value, entity_id],
    )
    return rows[0] if rows else {}


def lookup_past_verdicts(rule_id: str, days: int = 30) -> tuple[list[dict], float | None]:
    """
    Bucla de feedback. Daca regula a tras de 50 de ori si 48 au fost fals pozitive,
    ala e cel mai important context pe care il poate primi agentul.

    ATENTIE: la Elastic adevarul de referinta vine de la analistul care inchide cazul.
    Tu n-ai analist. Aici trebuie sa pui verdictele confirmate din laborator
    plus esantionul revizuit periodic — altfel bucla se auto-confirma.
    """
    rows = _esql(
        """
        FROM verdicts-history
        | WHERE rule_id == ? AND @timestamp >= NOW() - 30 days
        | KEEP classification, confidence, ground_truth, notes
        | LIMIT 50
        """,
        params=[rule_id],
    )
    if not rows:
        return [], None
    labelled = [r for r in rows if r.get("ground_truth")]
    if not labelled:
        return rows, None
    fp = sum(1 for r in labelled if r["ground_truth"] == "benign")
    return rows, fp / len(labelled)


def build_context_pack(
    entity_type: EntityType, entity_id: str, rule_id: str | None = None
) -> ContextPack:
    """Tot ce stim despre entitate. Preadus intr-un singur pas, inainte de orice model."""
    asset = lookup_asset_context(entity_id) if entity_type == EntityType.HOST else {}
    base = lookup_entity_baseline(entity_type, entity_id)
    past, fp_rate = lookup_past_verdicts(rule_id) if rule_id else ([], None)

    return ContextPack(
        entity_type=entity_type,
        entity_id=entity_id,
        investigation_guide=lookup_investigation_guide(rule_id) if rule_id else None,
        asset_criticality=asset.get("criticality"),
        asset_owner=asset.get("owner"),
        exposed_services=asset.get("exposed_services") or [],
        open_cves=asset.get("open_cves") or [],
        first_seen=base.get("first_seen"),
        events_last_90d=base.get("events_90d") or 0,
        common_parents=base.get("common_parents") or [],
        common_destinations=base.get("common_destinations") or [],
        past_verdicts_same_rule=past,
        fp_rate_same_rule=fp_rate,
    )


# --------------------------------------------------------------------------
# SWEEP-ul de raritate — al treilea punct de intrare, cel programat
#
# Un 0-day care nu genereaza nicio alerta nu intra NICIODATA intr-un sistem
# declansat de evenimente. Asta e singura cale pe care il gasesti.
# Zero ipoteze despre cum arata un atac. Doar: ce e nou fata de 90 de zile.
# --------------------------------------------------------------------------


def sweep_new_parent_child(window_hours: int = 1) -> list[RarityFinding]:
    """Perechi parinte-copil nevazute in baseline. Semnalul numarul unu pentru RCE."""
    # FARA filtru pe event.type / event.action: la Elastic Defend sunt campuri
    # multi-valoare si `==` esueaza in ES|QL (descoperit pe date reale).
    recent = _esql(
        f"""
        FROM {PROC_IDX}
        | WHERE @timestamp >= NOW() - {window_hours} hours
        | WHERE process.parent.name IS NOT NULL AND process.name IS NOT NULL
        | STATS cnt = COUNT(*) BY host.name, process.parent.name, process.name
        | LIMIT 5000
        """
    )
    # Comparatia se face in Python: indexul transformului e in mod standard,
    # deci LOOKUP JOIN nu merge pe el.
    known = {
        (r["host.name"], r["process.parent.name"], r["process.name"])
        for r in _esql(
            """
            FROM baseline-entity-parentchild
            | KEEP host.name, process.parent.name, process.name
            | LIMIT 10000
            """
        )
    }
    out = []
    for r in recent:
        key = (r["host.name"], r["process.parent.name"], r["process.name"])
        if key in known:
            continue
        # Raritatea e agnostica, dar ponderam ce e structural mai grav
        score = 1.0 if r["process.parent.name"] in WEB_PARENTS else 0.8
        out.append(
            RarityFinding(
                kind="new_parent_child",
                entity_type=EntityType.HOST,
                entity_id=r["host.name"],
                detail={
                    "parent": r["process.parent.name"],
                    "child": r["process.name"],
                    "count": r["cnt"],
                },
                rarity_score=score,
            )
        )
    return out


def sweep_new_destinations(window_hours: int = 1) -> list[RarityFinding]:
    """ASN-uri de destinatie nevazute pentru procesul asta. Exfiltrare / C2."""
    recent = _esql(
        f"""
        FROM {NET_IDX}
        | WHERE @timestamp >= NOW() - {window_hours} hours
          AND network.direction == "egress"
        | STATS cnt = COUNT(*) BY host.name, process.name, destination.ip
        | LIMIT 5000
        """
    )
    # In productie cheia ar fi destination.as.number. In laborator ASN-ul e gol,
    # asa ca transformul grupeaza pe dest_ip.
    known = {
        (r["host.name"], r["process.name"], r["dest_ip"])
        for r in _esql(
            "FROM baseline-entity-egress | KEEP host.name, process.name, dest_ip | LIMIT 10000"
        )
    }
    return [
        RarityFinding(
            kind="new_destination_asn",
            entity_type=EntityType.HOST,
            entity_id=r["host.name"],
            detail={
                "process": r["process.name"],
                "destination_ip": r["destination.ip"],
                "count": r["cnt"],
            },
            rarity_score=1.0,
        )
        for r in recent
        if (r["host.name"], r["process.name"], r["destination.ip"]) not in known
    ]


def sweep_webroot_writes(window_hours: int = 1) -> list[RarityFinding]:
    """Fisiere executabile-web nou scrise in webroot. Webshell = drift, prin definitie."""
    rows = _esql(
        f"""
        FROM {FILE_IDX}
        | WHERE @timestamp >= NOW() - {window_hours} hours
          AND event.action == "creation"
          AND STARTS_WITH(file.path, "/var/www/")
          AND file.extension IN ("php", "phtml", "jsp", "aspx", "cgi", "pl")
        | KEEP host.name, file.path, process.name, user.name, @timestamp
        """
    )
    return [
        RarityFinding(
            kind="new_webroot_write",
            entity_type=EntityType.HOST,
            entity_id=r["host.name"],
            detail={"path": r["file.path"], "written_by": r["process.name"]},
            rarity_score=1.0,
        )
        for r in rows
    ]


def run_full_sweep(window_hours: int = 1) -> list[RarityFinding]:
    findings: list[RarityFinding] = []
    for fn in (sweep_new_parent_child, sweep_new_destinations, sweep_webroot_writes):
        try:
            findings.extend(fn(window_hours))
        except Exception as exc:  # un sweep cazut nu trebuie sa omoare restul
            print(f"[sweep] {fn.__name__} a esuat: {exc}")
    findings.sort(key=lambda f: f.rarity_score, reverse=True)
    return findings


# --------------------------------------------------------------------------
# TOOL-uri expuse agentului de hunting.
# Aici NU preaduci — tocmai fiindca nu stii dinainte ce va vrea sa intrebe.
# Toate read-only. Toate cu LIMIT. Toate cu fereastra maxima.
# --------------------------------------------------------------------------


@tool
@_traced
def tool_process_tree(host_name: str, entity_id: str, minutes: int = 30) -> dict:
    """
    Arborele de procese in jurul unui proces.

    NU corela dupa PID brut — PID-urile se refolosesc si la volum vei atribui
    actiuni procesului gresit. process.entity_id e stabil.
    """
    rows = _esql(
        f"""
        FROM {PROC_IDX} METADATA _id, _index
        | WHERE host.name == ? AND @timestamp >= NOW() - {int(minutes)} minutes
          AND (process.entity_id == ? OR process.parent.entity_id == ?)
        | KEEP _id, _index, @timestamp, process.name, process.command_line, process.entity_id,
               process.parent.name, process.parent.entity_id, user.name
        | SORT @timestamp ASC
        | LIMIT 200
        """,
        params=[host_name, entity_id, entity_id],
    )
    return {"rows": rows, "count": len(rows)}


@tool
@_traced
def tool_egress_for_host(host_name: str, minutes: int = 30) -> dict:
    """Conexiunile outbound (egress) ale unui host in ultimele N minute, agregate
    pe destinatie si proces. Foloseste asta ca sa vezi cu ce IP-uri externe a
    comunicat hostul — util pentru a depista C2 sau exfiltrare."""
    rows = _esql(
        f"""
        FROM {NET_IDX}
        | WHERE host.name == ? AND @timestamp >= NOW() - {int(minutes)} minutes
          AND network.direction == "egress"
        | STATS bytes = SUM(network.bytes), cnt = COUNT(*)
            BY destination.ip, destination.port, destination.as.organization.name, process.name
        | SORT bytes DESC
        | LIMIT 50
        """,
        params=[host_name],
    )
    return {"rows": rows}


@tool
@_traced
def tool_apache_requests(host_name: str, minutes: int = 30, status: int | None = None) -> dict:
    """Cereri catre serverul web. Pentru corelarea request -> proces."""
    extra = "AND http.response.status_code == ?" if status else ""
    params: list[Any] = [host_name] + ([status] if status else [])
    rows = _esql(
        f"""
        FROM {APACHE_IDX} METADATA _id, _index
        | WHERE host.name == ? AND @timestamp >= NOW() - {int(minutes)} minutes {extra}
        | KEEP _id, _index, @timestamp, source.ip, url.path, http.request.method,
               http.response.status_code, http.response.body.bytes, user_agent.original
        | SORT @timestamp DESC
        | LIMIT 200
        """,
        params=params,
    )
    return {"rows": rows}


@tool
@_traced
def tool_eql_sequence(query: str, index: str = PROC_IDX) -> dict:
    """
    Secvente corelate — asta e ce KQL nu poate face si de ce ai nevoie de EQL.

    Exemplu de scriere de webshell urmata de acces la ea:

        sequence by host.id with maxspan=10m
          [ file where event.action == "creation"
              and file.path : "/var/www/*" and file.extension in ("php","jsp") ]
          [ process where event.type == "start"
              and process.parent.name in ("apache2","httpd","php-fpm") ]
    """
    resp = ES.eql.search(index=index, query=query, size=50)
    return {
        "sequences": resp["hits"].get("sequences", []),
        "events": resp["hits"].get("events", []),
    }


@tool
@_traced
def tool_suricata_alerts(source_ip: str, minutes: int = 60) -> dict:
    """Alertele Suricata (IDS) generate de un IP sursa in ultimele N minute.
    Foloseste asta ca sa vezi daca traficul de la un IP a declansat semnaturi
    de retea cunoscute."""
    rows = _esql(
        f"""
        FROM {SURICATA_IDX} METADATA _id, _index
        | WHERE source.ip == ? AND @timestamp >= NOW() - {int(minutes)} minutes
          AND event.kind == "alert"
        | KEEP _id, _index, @timestamp, rule.name, rule.category, destination.ip, destination.port
        | LIMIT 100
        """,
        params=[source_ip],
    )
    return {"rows": rows}


@tool
@_traced
def tool_rarity_of(field: str, value: str, host_name: str | None = None) -> dict:
    """
    Cat de neobisnuit e X aici? Intrebarea pe care agentul trebuie s-o poata pune
    despre orice, nu doar despre ce am precalculat eu in sweep.
    """
    where = f"WHERE {field} == ?"
    params = [value]
    if host_name:
        where += " AND host.name == ?"
        params.append(host_name)
    rows = _esql(
        f"""
        FROM {PROC_IDX}
        | {where} AND @timestamp >= NOW() - 90 days
        | STATS cnt = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
        """,
        params=params,
    )
    r = rows[0] if rows else {"cnt": 0}
    cnt = r.get("cnt") or 0
    return {
        "occurrences_90d": cnt,
        "first_seen": r.get("first_seen"),
        "rarity_score": 1.0 if cnt == 0 else min(1.0, 1.0 / (1.0 + cnt / 10.0)),
    }


HUNT_TOOLS = [
    tool_process_tree,
    tool_egress_for_host,
    tool_apache_requests,
    tool_eql_sequence,
    tool_suricata_alerts,
    tool_rarity_of,
]

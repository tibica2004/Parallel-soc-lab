"""
ENRICH (Tier 1) — context determinist, adus de cod inaintea modelului.

  - alerte corelate: alte alerte pe ACELASI host in fereastra din jurul alertei
    (Query DSL cu term/range, fara valori interpolate), rezumate pe regula;
  - threat intel: indicatorii din alerta cautati exact in lista locala.

Rezultatele intra in context ca FAPTE calculate de cod. Numele regulilor vin din
Kibana (ale noastre sau native Defend), nu din telemetria atacatorului.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import threat_intel

ALERTS_IDX = ".alerts-security.alerts-*"
CORRELATION_WINDOW_MIN = 30
MAX_CORRELATED = 100
MAX_RULES = 10
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _ts(s) -> datetime | None:
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _tree_ids(a: dict) -> set[str]:
    return {x for x in (threat_intel._g(a, "process.entity_id"), threat_intel._g(a, "process.parent.entity_id"))
            if isinstance(x, str) and x}


def summarize_correlated(sources: list[dict], self_uuid: str | None, tree: set[str] | frozenset = frozenset()) -> dict:
    """Functie pura: rezumatul alertelor corelate (fara alerta curenta).
    `same_process_tree` = cate impart procesul sau parintele cu alerta curenta:
    legatura directa, spre deosebire de simpla vecinatate in timp pe host."""
    by_rule: dict[str, int] = {}
    max_sev, n, same_tree = None, 0, 0
    for s in sources:
        if self_uuid and threat_intel._g(s, "kibana.alert.uuid") == self_uuid:
            continue
        n += 1
        if tree and _tree_ids(s) & tree:
            same_tree += 1
        name = str(threat_intel._g(s, "kibana.alert.rule.name") or "necunoscuta")[:256]
        by_rule[name] = by_rule.get(name, 0) + 1
        sev = threat_intel._g(s, "kibana.alert.severity")
        if sev in SEVERITY_RANK and (max_sev is None or SEVERITY_RANK[sev] > SEVERITY_RANK[max_sev]):
            max_sev = sev
    rules = sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_RULES]
    return {"window_min": CORRELATION_WINDOW_MIN, "count": n, "same_process_tree": same_tree,
            "max_severity": max_sev,
            "rules": [{"rule": r, "count": c} for r, c in rules]}


def correlated_alerts(es, alert: dict, window_min: int = CORRELATION_WINDOW_MIN) -> dict | None:
    """Alte alerte pe acelasi host in [t - fereastra, t + fereastra].
    None = nu s-a putut afla (lipsesc host/timp sau interogarea a esuat)."""
    host = threat_intel._g(alert, "host.name")
    t = _ts(threat_intel._g(alert, "@timestamp"))
    if not host or t is None:
        return None
    w = timedelta(minutes=int(window_min))
    try:
        r = es.search(index=ALERTS_IDX, size=MAX_CORRELATED,
                      source=["kibana.alert.uuid", "kibana.alert.rule.name", "kibana.alert.severity",
                              "process.entity_id", "process.parent.entity_id"],
                      query={"bool": {"filter": [
                          {"term": {"host.name": host}},
                          {"range": {"@timestamp": {"gte": (t - w).isoformat(), "lte": (t + w).isoformat()}}},
                      ]}})
    except Exception:
        return None
    return summarize_correlated([h["_source"] for h in r["hits"]["hits"]],
                                threat_intel._g(alert, "kibana.alert.uuid"), _tree_ids(alert))


def enrich(es, alert: dict) -> dict:
    return {"correlated_alerts": correlated_alerts(es, alert),
            "threat_intel_matches": threat_intel.lookup(threat_intel.extract_indicators(alert))}

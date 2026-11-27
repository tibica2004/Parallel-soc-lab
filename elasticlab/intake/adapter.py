"""Adaptorul de intrare (faza 26): citeste alertele, le normalizeaza, muta cursorul.

- Citire PAGINATA (`search_after`), fara plafonul de 500 de alerte pe ciclu al caii vechi: se
  citeste toata fereastra, pana la `max_alerts` (plasa de memorie). Daca plasa se atinge,
  `trunchiat=True` si cursorul ramane la ultima alerta consumata, deci nimic nu e sarit.
- Cursorul si marja de indexare raman cele din `store.state` (LAG_SECONDS, soc-state).
- Normalizarea: un singur mesaj (`contracts.messages.AlertaNormalizata`, extra="forbid") cu cheia
  de deduplicare de azi si clasa critica, daca e una.

Clientul Elasticsearch se primeste ca parametru (cel de citire al orchestratorului), deci modulul
se testeaza cu un fals si nu deschide conexiuni la import.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import ValidationError

from elasticlab.contracts.messages import AlertaNormalizata, CriticalClass
from elasticlab.core import eventtime, honeytokens
from elasticlab.intake.grouping import _g, dedup_key_alert, flood_source
from elasticlab.tier1 import defend_native, sensor_rules

ALERTS_IDX = ".alerts-security.alerts-*"
# Regulile Tier 3 in shadow alerteaza, dar nu intra in coada Tier 1 (ca pe calea veche).
SHADOW_RULE_TAG = "tier3-shadow"
PAGE_SIZE = 500
MAX_ALERTS = 20_000          # plasa de memorie pe ciclu; restul se citeste la ciclul urmator


def critical_class(alert: dict) -> CriticalClass | None:
    """Clasa critica a alertei, decisa de cod. Momeala atinsa de pe un IP propriu
    (honeytoken_config_error) NU e critica: merge la om, dar fara paginare (ca azi)."""
    from elasticlab.contracts.schemas import EscalationReason
    if honeytokens.escalation_reason(alert) is EscalationReason.HONEYTOKEN:
        return CriticalClass.HONEYTOKEN
    if sensor_rules.is_sensor_alert(alert):
        return CriticalClass.SENSOR_DETECTION
    if defend_native.is_native(alert):
        return CriticalClass.NATIVE_DETECTION
    return None


def _cut(v: Any, n: int) -> str | None:
    if v is None:
        return None
    if isinstance(v, list):
        v = v[0] if v else None
        if v is None:
            return None
    return str(v)[:n]


def normalize(alert: dict) -> AlertaNormalizata | None:
    """Plicul alertei, sau None daca nu se poate valida (alerta merge totusi mai departe pe
    calea de verdict, cu cheia calculata din documentul brut; doar se numara ca respinsa)."""
    ref = alert.get("_soc_ref") or {}
    try:
        return AlertaNormalizata(
            ref_index=ref.get("index") or "", ref_id=ref.get("id") or "",
            indexed_at=eventtime.parse(_g(alert, "@timestamp")),
            event_at=eventtime.alert_time(alert),
            rule_name=_cut(_g(alert, "kibana.alert.rule.name"), 512),
            rule_id=_cut(honeytokens.rule_id_of(alert), 255),
            host=_cut(_g(alert, "host.name"), 255),
            source=_cut(flood_source(alert), 255),
            severity=_cut(_g(alert, "kibana.alert.severity"), 32),
            dedup_key=dedup_key_alert(alert)[:2048],
            critical=critical_class(alert),
            raw=alert,
        )
    except (ValidationError, ValueError, TypeError):
        return None


def _query(since: datetime, until: datetime) -> dict:
    """Aceeasi interogare ca pe calea veche (orchestrator.fetch_alerts_between)."""
    return {"bool": {"filter": [
        {"range": {"@timestamp": {"gte": since.isoformat(), "lte": until.isoformat()}}},
    ], "must_not": [
        {"term": {"kibana.alert.workflow_status": "closed"}},
        {"term": {"kibana.alert.rule.tags": SHADOW_RULE_TAG}},
    ]}}


# Ordinea paginarii: dupa @timestamp (ca pe calea veche), apoi dupa identificatorul alertei, ca
# alertele cu acelasi @timestamp sa nu se piarda intre pagini. kibana.alert.uuid e keyword in
# indicii de alerte; documentele fara el ies ultimele la acelasi @timestamp.
SORT = [{"@timestamp": "asc"}, {"kibana.alert.uuid": {"order": "asc", "missing": "_last"}}]


def read_window(es, since: datetime, until: datetime, *, page_size: int = PAGE_SIZE,
                max_alerts: int = MAX_ALERTS, index: str = ALERTS_IDX) -> tuple[list[dict], int, bool]:
    """Toate alertele deschise din [since, until], cele mai vechi intai, pagina cu pagina.
    Intoarce (alerte, pagini citite, trunchiat). Fiecare alerta primeste `_soc_ref`
    (referinta opaca la document, ca pe calea veche)."""
    out: list[dict] = []
    after = None
    pages = 0
    query = _query(since, until)
    while len(out) < max_alerts:
        size = min(page_size, max_alerts - len(out))
        kw = {"index": index, "size": size, "sort": SORT, "query": query}
        if after is not None:
            kw["search_after"] = after
        hits = es.search(**kw)["hits"]["hits"]
        pages += 1
        for h in hits:
            out.append({**h["_source"], "_soc_ref": {"index": h["_index"], "id": h["_id"]}})
        if len(hits) < size:
            return out, pages, False
        after = hits[-1].get("sort")
        if after is None:            # fara valori de sortare nu se poate continua sigur
            return out, pages, True
    return out, pages, True


def next_cursor(since: datetime, until: datetime, last_ts: str | None, deferred: int,
                truncated: bool) -> datetime:
    """Unde ramane cursorul dupa ciclu. Pur.

    Fereastra golita -> capatul ei (`until`). Altfel (alerte amanate de plafon sau citire
    trunchiata) -> @timestamp-ul ultimei alerte consumate; interogarea e `gte`, deci alertele cu
    acelasi @timestamp se recitesc si se recunosc ca vazute. Niciodata dincolo de ce s-a consumat:
    fara un @timestamp citibil, cursorul ramane pe loc (`since`)."""
    if not (deferred or truncated):
        return until
    t = eventtime.parse(last_ts)
    if t is None:
        return since
    return max(since, min(t, until))

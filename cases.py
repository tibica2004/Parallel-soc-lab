"""
CICLUL DE VIATA AL CAZULUI (plann.md A1 + A2) — unitatea de lucru a SOC-ului e cazul, nu alerta.

Un caz = un chain_id (acelasi prin Tier 1 -> 2 -> 3). Stari (enumerare inchisa):
  open -> investigating (Tier 2 a inceput) -> escalated (asteapta omul) -> closed (DOAR omul).
Codul doar deschide, avanseaza si ataseaza verdicte, motive si playbook-ul (planul dry-run al
executorului, A2: "ce ai de rulat, in ce ordine, cum anulezi"). Inchiderea, motivul inchiderii si
eticheta raman la om (principiile 5 si 6), din interfata de etichetare (coada de cazuri).

Scriere: index soc-cases, _id = chain_id (upsert read-modify-write), cheia ES_CASES_WRITER_API_KEY
(create_doc/index/read/view_index_metadata, fara delete). Fara cheie: orchestratorul merge ca
inainte (cazurile sunt o vedere peste audit, nu o conditie a lui).
"""
from __future__ import annotations

import os
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from schemas import CHAIN_ID_RE, ActionPlan, EntityType, EscalationReason, Verdict

INDEX = "soc-cases"
MAX_VERDICTS = 20
MAX_ALERTS = 50
# Hostul monitorizat: cazurile pe entitati non-host (user, IP sursa din entity_risk, A3) se
# leaga de hostul pe care au fost observate alertele (laboratorul are un singur host monitorizat).
MONITORED_HOST = os.environ.get("MONITORED_HOST", "web-prod")


class CaseState(str, Enum):
    open = "open"
    investigating = "investigating"
    escalated = "escalated"
    closed = "closed"


class CloseReason(str, Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    benign_confirmed = "benign_confirmed"
    duplicate = "duplicate"
    inconclusive = "inconclusive"


class CaseVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tier: Literal[1, 2, 3]
    investigation_id: str = Field(max_length=64)
    classification: str = Field(max_length=16)
    confidence: int = Field(ge=0, le=100)
    proposed_action: str = Field(max_length=32)
    at: datetime


class CaseRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str = Field(pattern=CHAIN_ID_RE)
    host: str = Field(max_length=253)
    entity_type: EntityType = EntityType.HOST   # A3: user / source_ip pentru cazurile entity_risk
    entity: str = Field(default="", max_length=128)   # gol = hostul insusi
    state: CaseState = CaseState.open
    origin: str = Field(max_length=32)
    opened_at: datetime
    updated_at: datetime
    current_tier: Literal[1, 2, 3] = 1
    rule_names: list[str] = Field(default_factory=list, max_length=10)
    alert_ids: list[str] = Field(default_factory=list, max_length=MAX_ALERTS)
    escalation_reasons: list[EscalationReason] = Field(default_factory=list, max_length=10)
    verdicts: list[CaseVerdict] = Field(default_factory=list, max_length=MAX_VERDICTS)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    playbook: ActionPlan | None = None          # A2: planul dry-run al executorului
    closed_at: datetime | None = None
    closed_by: Literal["human"] | None = None   # NICIODATA "code"
    close_reason: CloseReason | None = None
    close_notes: str = Field(default="", max_length=1000)   # audit, text liber al omului


CRITICAL_REASONS = frozenset({EscalationReason.HONEYTOKEN, EscalationReason.SENSOR_DETECTION,
                              EscalationReason.NATIVE_DETECTION, EscalationReason.BEHAVIORAL})


def severity_of(classification: str, reasons: list[EscalationReason]) -> str:
    if classification == "malicious" or CRITICAL_REASONS & set(reasons):
        return "critical"
    if classification == "suspicious":
        return "high"
    if classification == "undetermined":
        return "medium"
    return "low"


def open_case(chain_id: str, host: str, origin: str, now: datetime, rule_name: str | None = None,
              alert_ids: list[str] | None = None, entity_type: EntityType = EntityType.HOST,
              entity: str = "") -> CaseRecord:
    return CaseRecord(case_id=chain_id, host=host, origin=origin, opened_at=now, updated_at=now,
                      entity_type=entity_type, entity="" if entity_type is EntityType.HOST else entity[:128],
                      rule_names=[rule_name] if rule_name else [],
                      alert_ids=list(alert_ids or [])[:MAX_ALERTS])


def record_verdict(rec: CaseRecord, verdict: Verdict, tier: Literal[1, 2, 3], now: datetime,
                   reasons: list[EscalationReason] | None = None, escalate: bool | None = None,
                   plan: ActionPlan | None = None) -> CaseRecord:
    """Tranzitiile pe care le face CODUL. Un caz inchis de om nu se mai redeschide de cod:
    verdictul se adauga, starea ramane closed (omul vede ca a venit ceva nou). Pur."""
    r = rec.model_copy(deep=True)
    r.verdicts = (r.verdicts + [CaseVerdict(
        tier=tier, investigation_id=verdict.investigation_id, classification=verdict.classification.value,
        confidence=verdict.confidence, proposed_action=verdict.proposed_action.value, at=now)])[-MAX_VERDICTS:]
    for x in reasons or []:
        if x not in r.escalation_reasons and len(r.escalation_reasons) < 10:
            r.escalation_reasons.append(x)
    r.current_tier = max(r.current_tier, tier)
    r.severity = max((r.severity, severity_of(verdict.classification.value, r.escalation_reasons)),
                     key=["low", "medium", "high", "critical"].index)
    if plan is not None:
        r.playbook = plan
    if r.state is not CaseState.closed:
        # Un caz ajuns la om nu se intoarce in "investigating" (Tier 2 doar adauga); orice actiune
        # propusa in afara de none/enrich_only cere un om, deci escaladeaza.
        if tier >= 2 and r.state is CaseState.open:
            r.state = CaseState.investigating
        if escalate or verdict.proposed_action.value not in ("none", "enrich_only"):
            r.state = CaseState.escalated
    r.updated_at = now
    return r


def close_by_human(rec: CaseRecord, reason: CloseReason, notes: str, now: datetime) -> CaseRecord:
    """Singura cale spre closed: actiunea unui om in interfata."""
    r = rec.model_copy(deep=True)
    r.state, r.closed_at, r.closed_by = CaseState.closed, now, "human"
    r.close_reason, r.close_notes, r.updated_at = reason, notes[:1000], now
    return r


# ---------------- I/O ----------------

def client():
    key = os.environ.get("ES_CASES_WRITER_API_KEY")
    if not key:
        return None
    from elasticsearch import Elasticsearch
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"), api_key=key, request_timeout=20)


def load(es, chain_id: str) -> CaseRecord | None:
    try:
        return CaseRecord.model_validate(es.get(index=INDEX, id=chain_id)["_source"])
    except Exception:  # noqa: BLE001 — lipsa sau invalid: se deschide unul nou
        return None


def save(es, rec: CaseRecord) -> None:
    es.index(index=INDEX, id=rec.case_id, document=rec.model_dump(mode="json"))


def upsert_from_verdict(es, verdict: Verdict, tier: Literal[1, 2, 3], now: datetime, *, host: str,
                        origin: str, rule_name: str | None, alert_ids: list[str],
                        reasons: list[EscalationReason] | None, escalate: bool | None,
                        plan: ActionPlan | None) -> CaseRecord | None:
    if es is None or not verdict.chain_id:
        return None
    # Entitatea cazului vine din verdict (host, user, source_ip); hostul e cel observat.
    rec = load(es, verdict.chain_id) or open_case(verdict.chain_id, host, origin, now, rule_name, alert_ids,
                                                  entity_type=verdict.entity_type, entity=verdict.entity_id)
    for a in alert_ids:
        if a not in rec.alert_ids and len(rec.alert_ids) < MAX_ALERTS:
            rec.alert_ids.append(a)
    if rule_name and rule_name not in rec.rule_names and len(rec.rule_names) < 10:
        rec.rule_names.append(rule_name)
    rec = record_verdict(rec, verdict, tier, now, reasons, escalate, plan)
    save(es, rec)
    return rec

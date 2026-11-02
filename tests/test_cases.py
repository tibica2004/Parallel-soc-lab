"""plann.md A1/A2: ciclul de viata al cazului — tranzitii pure, inchiderea doar de om."""
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

import cases as C
from schemas import ActionType, EntityType, EscalationReason, Verdict

T0 = datetime(2026, 11, 2, 16, 0, tzinfo=timezone.utc)
CID = "11111111-1111-1111-1111-111111111111"


def _v(cls="suspicious", conf=70, action="escalate_human", path="fast"):
    return Verdict(investigation_id="inv-1", source_path=path, chain_id=CID, entity_type=EntityType.HOST,
                   entity_id="web-prod", classification=cls, confidence=conf, rarity_score=1.0,
                   mitre_techniques=[], proposed_action=ActionType(action), model_id="m")


def test_deschidere_si_verdict_tier1():
    r = C.open_case(CID, "web-prod", "tier1_alert", T0, "RCE", ["a1"])
    r = C.record_verdict(r, _v(), 1, T0 + timedelta(seconds=5),
                         reasons=[EscalationReason.SUSPICIOUS], escalate=True)
    assert r.state is C.CaseState.escalated and r.current_tier == 1 and r.severity == "high"
    assert r.verdicts[0].classification == "suspicious" and r.alert_ids == ["a1"]


def test_tier2_investigheaza_apoi_escaladeaza_cu_playbook():
    from schemas import ActionPlan, PlanStep, Reversibility
    plan = ActionPlan(action=ActionType.QUARANTINE_FILE, host="web-prod", target="/var/www/html/x.php",
                      reversibility=Reversibility.CHEAP,
                      steps=[PlanStep(kind="ssh_argv", argv=["mv", "/var/www/html/x.php", "/var/lib/soc-quarantine/"])])
    r = C.open_case(CID, "web-prod", "tier1_alert", T0)
    r = C.record_verdict(r, _v(action="none"), 1, T0, escalate=True)
    r = C.record_verdict(r, _v("malicious", 95, "quarantine_file", "hunt"), 2, T0 + timedelta(minutes=1),
                         reasons=[EscalationReason.BEHAVIORAL], plan=plan)
    assert r.current_tier == 2 and r.severity == "critical" and r.playbook.action is ActionType.QUARANTINE_FILE
    assert r.state is C.CaseState.escalated           # escaladat de Tier 1 ramane la om
    assert len(r.verdicts) == 2


def test_inchiderea_doar_de_om_si_codul_nu_redeschide():
    r = C.open_case(CID, "web-prod", "tier1_alert", T0)
    r = C.close_by_human(r, C.CloseReason.false_positive, "admin cunoscut", T0)
    assert r.state is C.CaseState.closed and r.closed_by == "human"
    r2 = C.record_verdict(r, _v("malicious", 95), 2, T0 + timedelta(hours=1))
    assert r2.state is C.CaseState.closed and len(r2.verdicts) == 1
    with pytest.raises(ValidationError):
        C.CaseRecord(case_id=CID, host="h", origin="o", opened_at=T0, updated_at=T0, closed_by="code")


def test_schema_stricta_si_plafoane():
    with pytest.raises(ValidationError):
        C.CaseRecord(case_id="nu-e-uuid", host="h", origin="o", opened_at=T0, updated_at=T0)
    with pytest.raises(ValidationError):
        C.CaseRecord(case_id=CID, host="h", origin="o", opened_at=T0, updated_at=T0, payload="x")
    r = C.open_case(CID, "web-prod", "tier1_alert", T0)
    for i in range(C.MAX_VERDICTS + 5):
        r = C.record_verdict(r, _v(), 1, T0 + timedelta(seconds=i))
    assert len(r.verdicts) == C.MAX_VERDICTS


def test_severitate():
    assert C.severity_of("benign", []) == "low"
    assert C.severity_of("undetermined", []) == "medium"
    assert C.severity_of("suspicious", []) == "high"
    assert C.severity_of("benign", [EscalationReason.HONEYTOKEN]) == "critical"


def test_upsert_cu_es_fals():
    store = {}
    class ES:
        def get(self, index, id):
            if id not in store:
                raise KeyError(id)
            return {"_source": store[id]}
        def index(self, index, id, document):
            store[id] = document
    r = C.upsert_from_verdict(ES(), _v(), 1, T0, host="web-prod", origin="tier1_alert", rule_name="RCE",
                              alert_ids=["a1"], reasons=[EscalationReason.SUSPICIOUS], escalate=True, plan=None)
    r = C.upsert_from_verdict(ES(), _v("malicious", 95, "escalate_human", "hunt"), 2, T0, host="web-prod",
                              origin="tier1_alert", rule_name="RCE", alert_ids=["a1", "a2"], reasons=None,
                              escalate=None, plan=None)
    assert r.alert_ids == ["a1", "a2"] and r.rule_names == ["RCE"] and len(r.verdicts) == 2
    assert C.upsert_from_verdict(None, _v(), 1, T0, host="h", origin="o", rule_name=None, alert_ids=[],
                                 reasons=None, escalate=None, plan=None) is None

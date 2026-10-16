"""Honeytokens (faza 12): multime inchisa de reguli, escaladare mereu, podele pe
ambele niveluri. Fara model si fara Elasticsearch."""
import sys
import types

import pytest

import degraded
import fast_path
import honeytokens as H
import hunt_path
import orchestrator
from escalation import should_escalate
from schemas import ActionType as A, Case, EscalationReason as R, Verdict
from tests.test_tier1_tier2 import CID, FakeHunt, _alert, rec  # noqa: F401  (fixture)


def V(cls="benign", conf=99):
    return Verdict(investigation_id="i", source_path="fast", entity_type="host", entity_id="web-prod",
                   classification=cls, confidence=conf, rarity_score=0.0, model_id="m")


def HT(rid="soc-honeytoken-http", **kw):
    return _alert(**{"kibana.alert.rule.rule_id": rid,
                     "kibana.alert.rule.name": H.RULES.get(rid, {}).get("name", "x"), **kw})


# ---------------- recunoasterea: doar dupa rule_id ----------------

@pytest.mark.parametrize("rid", list(H.RULES))
def test_recunoscut_dupa_rule_id(rid):
    assert H.is_honeytoken({"kibana.alert.rule.rule_id": rid})
    assert H.is_honeytoken({"kibana": {"alert": {"rule": {"rule_id": rid}}}})


@pytest.mark.parametrize("a", [
    {}, {"kibana.alert.rule.rule_id": None}, {"kibana.alert.rule.rule_id": ["soc-honeytoken-http"]},
    {"kibana.alert.rule.rule_id": "b19f70b1-2dc8-4f01-baf1-d3733fcf8642"},
    # numele sau eticheta nu ajung: le poate schimba oricine din interfata
    {"kibana.alert.rule.name": "Honeytoken: cerere web", "kibana.alert.rule.tags": [H.TAG]},
])
def test_nerecunoscut(a):
    assert not H.is_honeytoken(a)


# ---------------- escaladare ----------------

def test_benign_sigur_pe_honeytoken_escaladeaza():
    d = should_escalate(V("benign", 99), floor_applied=False, pair_in_baseline=True, honeytoken=True)
    assert d.escalate and d.reasons == [R.HONEYTOKEN]


def test_fara_honeytoken_neschimbat():
    d = should_escalate(V("benign", 99), floor_applied=False, pair_in_baseline=True)
    assert not d.escalate and d.reasons == []


def test_restanta_honeytoken_e_grav_si_cu_severitate_schimbata():
    assert degraded.is_severe(HT(**{"kibana.alert.severity": "low"}))
    assert not degraded.is_severe(_alert(**{"kibana.alert.severity": "low"}))


# ---------------- podeaua pe calea rapida ----------------

def _ctx(**kw):
    return {"host": "web-prod", "ran_by_web_service_account": False, "sensitive_action": False,
            "in_maintenance_window": True, "ran_by_known_admin": True, "pair_in_baseline": True, **kw}


def test_podea_rapida_benign_devine_suspicious():
    out = fast_path.node_finalize({"raw_verdict": {"classification": "benign", "confidence": 99,
                                                   "proposed_action": "none"},
                                   "context": _ctx(honeytoken=True)})
    v = out["verdict"]
    assert out["floor_applied"] and v.classification.value == "suspicious"
    assert v.proposed_action is A.ESCALATE_HUMAN and v.confidence <= 60


def test_podea_rapida_suspicious_nu_ramane_pe_none():
    out = fast_path.node_finalize({"raw_verdict": {"classification": "suspicious", "confidence": 80,
                                                   "proposed_action": "none"},
                                   "context": _ctx(honeytoken=True)})
    assert out["verdict"].proposed_action is A.ESCALATE_HUMAN


def test_contextul_marcheaza_doar_honeytoken(monkeypatch):
    monkeypatch.setattr(fast_path, "lookup_asset", lambda h: {})
    monkeypatch.setattr(fast_path, "pair_in_baseline", lambda *a: None)
    monkeypatch.setattr(fast_path, "alert_facts", lambda a: {
        "executable": "", "command_line": "", "user": "", "sudo_invoked_by": None,
        "process": "", "parent": ""})
    assert fast_path.build_context(HT(), history=False)["honeytoken"] is True
    assert "honeytoken" not in fast_path.build_context(_alert(), history=False)
    assert "Honeytoken" in fast_path.build_context(HT(), history=False)["investigation_guide"]


# ---------------- Tier 2 ----------------

def _t2(monkeypatch, reasons, cls):
    monkeypatch.setattr(hunt_path, "prefetch_context", lambda x: {})
    case = Case(chain_id=CID, origin="tier1_alert", host="web-prod", rule_name="R",
                escalation_reasons=reasons, rarity_score=1.0)
    return hunt_path.node_finalize({"case": case, "investigation_id": "i", "merged_draft": {
        "classification": cls, "confidence": 95, "proposed_action": "none"}})["verdict"]


def test_tier2_nu_inchide_honeytoken(monkeypatch):
    v = _t2(monkeypatch, [R.HONEYTOKEN], "benign")
    assert v.classification.value == "suspicious" and v.proposed_action is A.ESCALATE_HUMAN


def test_tier2_fara_honeytoken_neschimbat(monkeypatch):
    v = _t2(monkeypatch, [R.LOW_CONFIDENCE], "benign")
    assert v.classification.value == "benign" and v.proposed_action is A.NONE


# ---------------- orchestratorul: motivul ajunge si pe caile fara model ----------------

def test_model_cazut_pastreaza_motivul(rec):
    hunt = FakeHunt()
    orchestrator.process_alerts([HT()], orchestrator.BoundedSeen(), model_ok=False, t2_limit=1, hunt=hunt)
    (inp, _, _), = hunt.runs
    assert R.HONEYTOKEN in inp["case"].escalation_reasons
    assert R.HONEYTOKEN in rec[0][1]["escalation"].reasons


def test_benign_de_la_model_tot_escaladeaza(monkeypatch, rec):
    monkeypatch.setitem(sys.modules, "fast_path", types.SimpleNamespace(
        build_fast_path=lambda: types.SimpleNamespace(invoke=lambda inp, config=None: {
            "verdict": V("benign", 99), "narrative": "", "context": {"pair_in_baseline": True}}),
        lookup_asset=lambda h: {}))
    orchestrator.process_alerts([HT()], orchestrator.BoundedSeen(), t2_limit=0, hunt=FakeHunt())
    esc = rec[0][1]["escalation"]
    assert esc.escalate and esc.reasons == [R.HONEYTOKEN]


# ---------------- regulile pentru Kibana ----------------

@pytest.mark.parametrize("rid", list(H.RULES))
def test_payload(rid):
    p = H.kibana_payload(rid)
    assert p["rule_id"] == rid and p["severity"] == "critical" and p["tags"] == [H.TAG]
    assert p["enabled"] and "exceptions_list" not in p
    t = p["threat"][0]
    assert t["tactic"]["id"].startswith("TA") and t["technique"][0]["id"].startswith("T")


def test_regulile_contin_momelile():
    q = H.RULES["soc-honeytoken-host"]["query"]
    assert H.DECOY_FILE in q and H.DECOY_USER in q and q.count("(") == q.count(")")
    assert all(u in H.RULES["soc-honeytoken-http"]["query"] for u in H.DECOY_URLS)
    assert H.DECOY_USER in H.RULES["soc-honeytoken-user"]["query"]
    assert H.kibana_payload("soc-honeytoken-host")["threat"][0]["technique"][0]["subtechnique"][0]["id"] == "T1552.001"

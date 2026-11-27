"""action_target invalid (decizia omului, faza 0, 2026-11-23): tinta respinsa -> None + escalate_human,
in loc de exceptie in Verdict. Fara model, fara Elasticsearch."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

import fast_path
import hunt_path
from schemas import ActionType, Case, EscalationReason, RarityFinding, Verdict, screen_action_target

# entity_id de proces din Elastic Defend (base64): cazul real din poarta din 2026-11-17 13:28
B64_ENTITY = "Kw1Y4COo3NG/M4W+r5fQ=="
CID = "11111111-2222-3333-4444-555555555555"


@pytest.mark.parametrize("raw,exp", [
    (None, (None, False)),
    ("", (None, False)),
    ("null", (None, False)),
    (" None ", (None, False)),
    ("8.8.8.8", ("8.8.8.8", False)),
    ("web-prod", ("web-prod", False)),
    ("1234", ("1234", False)),
    (B64_ENTITY, (None, True)),
    ("web-prod; rm -rf /", (None, True)),
    ("a" * 254, (None, True)),
    (1234, (None, True)),
    (["8.8.8.8"], (None, True)),
])
def test_screen_action_target(raw, exp):
    assert screen_action_target(raw) == exp


def test_verdict_respinge_in_continuare_tinta_invalida():
    """Granita Pydantic ramane: doar apelantii cern tinta inainte."""
    with pytest.raises(ValidationError):
        Verdict(investigation_id="i", source_path="hunt", entity_type="host", entity_id="web-prod",
                classification="malicious", confidence=90, rarity_score=1.0,
                proposed_action="isolate_host", action_target=B64_ENTITY, model_id="m")


# ---------------- calea rapida ----------------

def _fast(raw):
    ctx = {"host": "web-prod", "ran_by_web_service_account": False, "sensitive_action": False,
           "in_maintenance_window": False, "ran_by_known_admin": True, "pair_in_baseline": True}
    return fast_path.node_finalize({"raw_verdict": raw, "context": ctx})["verdict"]


def test_fast_tinta_invalida_escaladeaza():
    v = _fast({"classification": "malicious", "confidence": 90, "proposed_action": "isolate_host",
               "action_target": B64_ENTITY})
    assert v.action_target is None
    assert v.proposed_action is ActionType.ESCALATE_HUMAN
    assert v.classification.value == "malicious" and v.confidence == 90


def test_fast_tinta_valida_neschimbata():
    v = _fast({"classification": "malicious", "confidence": 90, "proposed_action": "block_ip_ttl",
               "action_target": "8.8.8.8"})
    assert v.action_target == "8.8.8.8"


def test_fast_actiune_none_ignora_tinta():
    """Ca inainte: cu actiunea none tinta nu se citeste, deci nu escaladeaza."""
    v = _fast({"classification": "benign", "confidence": 90, "proposed_action": "none",
               "action_target": B64_ENTITY})
    assert v.action_target is None and v.proposed_action is ActionType.NONE


# ---------------- calea lenta ----------------

def _hunt(monkeypatch, state_input, draft):
    monkeypatch.setattr(hunt_path, "prefetch_context", lambda x: {})
    state = {**state_input, "investigation_id": "i",
             "merged_draft": {"confidence": 80, **draft}}
    return hunt_path.node_finalize(state)["verdict"]


def _finding():
    return RarityFinding(kind="new_parent_child", entity_type="host", entity_id="web-prod",
                         detail={"parent": "cron", "child": "sed"}, rarity_score=1.0)


def _case():
    return Case(chain_id=CID, origin="tier1_alert", host="web-prod", entity_id=B64_ENTITY,
                parent="cron", child="sed", rule_name="R",
                escalation_reasons=[EscalationReason.SUSPICIOUS], rarity_score=1.0)


@pytest.mark.parametrize("state_input", [{"finding": _finding()}, {"case": _case()}])
def test_hunt_tinta_invalida_escaladeaza(monkeypatch, state_input):
    v = _hunt(monkeypatch, state_input, {"classification": "malicious", "proposed_action": "isolate_host",
                                          "action_target": B64_ENTITY})
    assert v.action_target is None
    assert v.proposed_action is ActionType.ESCALATE_HUMAN
    assert v.classification.value == "malicious"


def test_hunt_benign_cu_tinta_invalida_escaladeaza(monkeypatch):
    """Inainte, exceptia ducea cazul la om (PROCESSING_ERROR); acum ajunge tot la om, fara exceptie."""
    v = _hunt(monkeypatch, {"finding": _finding()}, {"classification": "benign", "proposed_action": "none",
                                                     "action_target": B64_ENTITY})
    assert v.proposed_action is ActionType.ESCALATE_HUMAN and v.action_target is None


def test_hunt_tinta_null_ca_sir_nu_escaladeaza(monkeypatch):
    v = _hunt(monkeypatch, {"finding": _finding()}, {"classification": "benign", "proposed_action": "none",
                                                     "action_target": "null"})
    assert v.proposed_action is ActionType.NONE and v.action_target is None

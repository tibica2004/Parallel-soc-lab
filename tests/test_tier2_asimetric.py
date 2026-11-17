"""Faza 23, etapa 5: regula asimetrica la Tier 2. Un finding de sweep ramane benign doar cu dovezi
(un rezultat de unealta cu randuri) sau cu un fapt determinist benign; cazurile din Tier 1 raman
neatinse. Fara model si fara Elasticsearch."""
from __future__ import annotations

import json

from langchain_core.messages import AIMessage, ToolMessage

import hunt_path
from schemas import ActionType, Case, EntityType, RarityFinding


def _finding() -> RarityFinding:
    return RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                         detail={"parent": "bash", "child": "ls"}, rarity_score=1.0)


def _state(ctx=None, a=None, b=None, cls="benign", **extra):
    s = {"finding": _finding(), "investigation_id": "i", "prefetch_ctx": ctx or {},
         "merged_draft": {"classification": cls, "confidence": 90, "proposed_action": "none", "narrative": "n"}}
    if a is not None:
        s["nonempty_a"] = a
    if b is not None:
        s["nonempty_b"] = b
    s.update(extra)
    return s


def test_result_has_rows():
    R = hunt_path.result_has_rows
    assert R(json.dumps({"rows": [{"a": 1}], "count": 1})) and R({"events": [{"_id": "x"}]})
    assert not R(json.dumps({"rows": []})) and not R({"events": []})
    # nedeterminabil = fara randuri: eroare, text liber, JSON stricat, alt format, count fara rows
    for bad in ("Unealta a esuat sau sursa nu exista.", "{stricat", json.dumps({"error": "x"}),
                json.dumps({"count": 7}), json.dumps([1, 2]), None, 5, {"rows": "multe"}):
        assert not R(bad)


def test_functia_pura_a_regulii():
    S = hunt_path.sweep_benign_supported
    assert not S(0, {}) and not S(0, None) and not S(None, {}) and not S(True, {}) and not S("3", {})
    assert S(1, {})
    assert S(0, {"pair_in_baseline": True}) and not S(0, {"pair_in_baseline": None})
    assert S(0, {"in_maintenance_window": True, "ran_by_known_admin": True})
    assert not S(0, {"in_maintenance_window": True}) and not S(0, {"ran_by_known_admin": True})
    assert not S(0, {"in_maintenance_window": "da", "ran_by_known_admin": 1})


def test_fara_dovezi_benign_devine_undetermined_escaladat():
    for st in (_state(), _state(a=0, b=0), _state(a="2")):
        out = hunt_path.node_finalize(st)
        v = out["verdict"]
        assert v.classification.value == "undetermined" and v.proposed_action is ActionType.ESCALATE_HUMAN
        assert v.confidence <= 40 and out["narrative"].startswith("Inchidere benign fara dovezi")


def test_cu_randuri_ramane_benign():
    for st in (_state(a=1), _state(a=0, b=2)):
        v = hunt_path.node_finalize(st)["verdict"]
        assert v.classification.value == "benign" and v.proposed_action is ActionType.NONE and v.confidence == 90


def test_cu_fapt_determinist_ramane_benign():
    for ctx in ({"pair_in_baseline": True}, {"in_maintenance_window": True, "ran_by_known_admin": True}):
        v = hunt_path.node_finalize(_state(ctx=ctx))["verdict"]
        assert v.classification.value == "benign" and v.proposed_action is ActionType.NONE


def test_verdictele_nebenigne_nu_sunt_atinse():
    for cls in ("suspicious", "malicious"):
        out = hunt_path.node_finalize(_state(cls=cls))
        assert out["verdict"].classification.value == cls and out["narrative"] == "n"


def test_podelele_existente_au_intaietate():
    # serverul web a executat: podeaua il face suspicious/malicious inainte; regula noua nu-l coboara
    v = hunt_path.node_finalize(_state(ctx={"ran_by_web_service_account": True}))["verdict"]
    assert v.classification.value in ("suspicious", "malicious")
    assert v.proposed_action is ActionType.ESCALATE_HUMAN


def test_cazul_din_tier1_ramane_neatins():
    # constructie minima independenta de campurile obligatorii ale lui Case: model_construct
    case = Case.model_construct(host="web-prod", origin="tier1", evidence_refs=[], escalation_reasons=[],
                                rarity_score=None, hunt_match=None)
    st = {"case": case, "investigation_id": "i", "prefetch_ctx": {},
          "merged_draft": {"classification": "benign", "confidence": 90, "proposed_action": "none", "narrative": "n"}}
    out = hunt_path.node_finalize(st)
    assert out["verdict"].classification.value == "benign" and out["narrative"] == "n"
    assert out["verdict"].proposed_action is ActionType.NONE


def test_wrap_numara_in_starea_grafului():
    msgs = [AIMessage(content="", tool_calls=[{"name": "t", "args": {}, "id": "1"}, {"name": "t", "args": {}, "id": "2"},
                                               {"name": "t", "args": {}, "id": "3"}]),
            ToolMessage(content=json.dumps({"rows": [{"x": 1}]}), tool_call_id="1", id="m1"),
            ToolMessage(content=json.dumps({"rows": []}), tool_call_id="2", id="m2"),
            ToolMessage(content="Unealta a esuat sau sursa nu exista.", tool_call_id="3", id="m3")]
    out = hunt_path._i_wrap_tools({"messages": msgs, "nonempty_results": 2})
    assert out["nonempty_results"] == 3 and len(out["messages"]) == 3
    # a doua trecere peste aceleasi mesaje (deja delimitate) nu numara din nou
    assert hunt_path._i_wrap_tools({"messages": [msgs[0]] + out["messages"], "nonempty_results": 3}) == {}


def test_primary_si_secondary_propaga_numarul(monkeypatch):
    class _Inv:
        def __init__(self, n):
            self.n = n

        def invoke(self, inp, config=None):
            return {"draft": {"classification": "benign"}, "nonempty_results": self.n}
    monkeypatch.setattr(hunt_path, "INVESTIGATOR_A", _Inv(2))
    monkeypatch.setattr(hunt_path, "INVESTIGATOR_B", _Inv(None))
    assert hunt_path.node_primary({"finding": _finding()})["nonempty_a"] == 2
    assert hunt_path.node_secondary({"finding": _finding()})["nonempty_b"] == 0

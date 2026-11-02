"""Faza 6: case_adapter, seed din entity_id, Tier 2 din orchestrator cu buget,
acelasi chain_id pe tot lantul, verdictul Tier 1 nu ajunge la Tier 2."""
import json
import sys
import types
import uuid

import pytest
from pydantic import ValidationError

import case_adapter
import hunt_path
import orchestrator
from escalation import EscalationDecision
from schemas import Case, EntityType, EscalationReason as R, RarityFinding, Verdict

CID = str(uuid.uuid4())
ESC = EscalationDecision(escalate=True, reasons=[R.SUSPICIOUS, R.LOW_CONFIDENCE])
T1_FIELDS = ("classification", "confidence", "narrative", "verdict")


def _alert(n=1, **kw):
    a = {"@timestamp": f"2026-10-09T00:00:0{n}Z", "host": {"name": "web-prod"},
         "kibana.alert.rule.name": "RCE: Web server spawns shell",
         "process": {"entity_id": f"Kw{n}Y4COo3NG/M4W+r5fQ==", "name": "id", "parent": {"name": "dash"}},
         "_soc_ref": {"index": "i", "id": f"AL{n}"}}
    a.update(kw)
    return a


# ---------------- case_adapter ----------------

def test_from_alert_fara_verdict_tier1():
    facts = {"execution": {"parent": "dash", "process": "id", "entity_id": "Kw1Y4COo3NG/M4W+r5fQ=="},
             "pair_in_baseline": False, "ran_by_web_service_account": True}
    c = case_adapter.from_alert(_alert(), ESC, CID, facts=facts, refs=[None])
    assert (c.origin, c.host, c.parent, c.child, c.rarity_score) == ("tier1_alert", "web-prod", "dash", "id", 1.0)
    assert c.escalation_reasons == [R.SUSPICIOUS, R.LOW_CONFIDENCE] and c.evidence_refs == []
    dumped = c.model_dump()
    assert not any(k in dumped for k in T1_FIELDS)


def test_from_alert_parintele_reconstruit_din_fapte():
    a = _alert()
    del a["process"]["parent"]          # alerta de fisier: fara parinte
    c = case_adapter.from_alert(a, ESC, CID, facts={"execution": {"parent": "apache2"}, "pair_in_baseline": True})
    assert c.parent == "apache2" and c.rarity_score == 0.0


def test_from_alert_curata_telemetria():
    a = _alert()
    a["process"].update(name="id\n| DROP x" + "a" * 400, entity_id='x" OR true')
    c = case_adapter.from_alert(a, ESC, CID)
    assert "\n" not in c.child and len(c.child) == 255
    assert c.entity_id is None          # forma invalida -> lasat deoparte, cade pe parinte-copil


def test_from_alert_host_invalid_respins():
    with pytest.raises(ValidationError):
        case_adapter.from_alert(_alert(host={"name": "web; rm -rf /"}), ESC, CID)


def test_from_alert_fara_motive_respins():
    with pytest.raises(ValidationError):
        case_adapter.from_alert(_alert(), EscalationDecision(escalate=False, reasons=[]), CID)


def test_from_finding():
    f = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                      detail={"parent": "bash", "child": "crontab", "count": 2}, rarity_score=0.9)
    c = case_adapter.from_finding(f, CID)
    assert (c.origin, c.parent, c.child, c.rarity_score, c.escalation_reasons) == ("rarity_sweep", "bash", "crontab", 0.9, [])


# ---------------- hunt_path cu Case ----------------

class Rec:
    def __init__(self, responses):
        self.calls, self._r = [], list(responses)

    def __call__(self, query, params=None):
        self.calls.append((query, list(params or [])))
        return self._r.pop(0) if self._r else []


ROW = {"user.name": "www-data", "process.executable": "/usr/bin/id", "process.command_line": "id",
       "process.parent.name": "dash", "process.working_directory": "/var/www/html",
       "process.parent.entity_id": "P1", "process.entity_id": "Kw1Y4COo3NG/M4W+r5fQ=="}


def _case(**kw):
    base = dict(chain_id=CID, origin="tier1_alert", host="web-prod", entity_id="Kw1Y4COo3NG/M4W+r5fQ==",
                parent="dash", child="id", rule_name="R", escalation_reasons=[R.SUSPICIOUS], rarity_score=1.0)
    base.update(kw)
    return Case(**base)


def test_seed_din_entity_id(monkeypatch):
    rec = Rec([[ROW]])
    monkeypatch.setattr(hunt_path, "_esql", rec)
    facts = hunt_path.execution_facts(_case())
    assert facts["resolved"] and facts["matched_by"] == "entity_id" and facts["ran_as_user"] == "www-data"
    q, params = rec.calls[0]
    assert "process.entity_id == ?" in q and params == ["web-prod", "Kw1Y4COo3NG/M4W+r5fQ=="]
    assert "Kw1Y4" not in q


def test_entity_negasit_nu_ghiceste_dupa_nume(monkeypatch):
    """Bug gasit in proba live: fallback-ul pe nume a potrivit un `dash` pornit de cron
    ca root in locul celui pornit de apache2 ca www-data. Cu entity_id cunoscut,
    lipsa evenimentului inseamna fapte nerezolvate, nu un proces ghicit."""
    rec = Rec([[], [ROW], [ROW]])
    monkeypatch.setattr(hunt_path, "_esql", rec)
    facts = hunt_path.execution_facts(_case())
    assert facts == {"resolved": False, "matched_by": "entity_id_not_found"}
    assert len(rec.calls) == 1


def test_caz_fara_entity_cade_pe_parinte_copil(monkeypatch):
    rec = Rec([[ROW]])
    monkeypatch.setattr(hunt_path, "_esql", rec)
    assert hunt_path.execution_facts(_case(entity_id=None))["matched_by"] == "exact_pair"


def test_finding_nu_cauta_dupa_entity(monkeypatch):
    rec = Rec([[ROW]])
    monkeypatch.setattr(hunt_path, "_esql", rec)
    f = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                      detail={"parent": "dash", "child": "id"}, rarity_score=1.0)
    assert hunt_path.execution_facts(f)["matched_by"] == "exact_pair"
    assert "process.entity_id == ?" not in rec.calls[0][0]


def test_mesajul_tier2_pentru_caz(monkeypatch):
    monkeypatch.setattr(hunt_path, "prefetch_context", lambda x: {"host": "web-prod"})
    msgs = hunt_path._i_seed({"case": _case(), "role_note": hunt_path.PRIMARY_NOTE})["messages"]
    assert hunt_path.TIER1_NOTE in msgs[0].content and "romana" in msgs[0].content
    payload = json.loads(msgs[1].content)
    assert payload["escalation_reasons"] == ["suspicious"] and payload["process"]["name"] == "id"
    assert not any(k in payload for k in T1_FIELDS)


def test_mesajul_pentru_finding_fara_nota_tier1(monkeypatch):
    monkeypatch.setattr(hunt_path, "prefetch_context", lambda x: {"host": "web-prod"})
    f = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                      detail={"parent": "dash", "child": "id"}, rarity_score=1.0)
    msgs = hunt_path._i_seed({"finding": f, "role_note": hunt_path.PRIMARY_NOTE})["messages"]
    assert hunt_path.TIER1_NOTE not in msgs[0].content
    assert json.loads(msgs[1].content)["anomaly_type"] == "new_parent_child"


# ---------------- orchestrator ----------------

def _verdict(cls, source="fast"):
    return Verdict(investigation_id=str(uuid.uuid4()), source_path=source, entity_type="host",
                   entity_id="web-prod", classification=cls, confidence=60, rarity_score=1.0, model_id="m")


class FakeHunt:
    def __init__(self):
        self.runs = []

    def run(self, inp, kind, entity, host, refs=(), chain_id=None):
        self.runs.append((inp, kind, chain_id))
        return None


@pytest.fixture
def rec(monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrator, "show", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "persist", lambda *a, **k: calls.append((a, k)))
    monkeypatch.setattr(orchestrator, "persist_trace", lambda doc: None)
    return calls


def _fast(monkeypatch, classes):
    it = iter(classes)
    monkeypatch.setitem(sys.modules, "fast_path", types.SimpleNamespace(
        build_fast_path=lambda: types.SimpleNamespace(invoke=lambda inp, config=None: {
            "verdict": _verdict(next(it)), "narrative": "T1 crede ca e suspect",
            "context": {"pair_in_baseline": True, "execution": {"parent": "dash", "process": "id"}}}),
        lookup_asset=lambda h: {}))


def test_tier2_cu_buget(monkeypatch, rec):
    _fast(monkeypatch, ["suspicious", "benign", "malicious", "suspicious"])
    hunt = FakeHunt()
    stats = {"total": 0, "escalated": 0, "no_model": 0}
    alerts = [_alert(1), _alert(2), _alert(3), _alert(4)]
    alerts[1]["kibana.alert.rule.name"] = "alt"     # cheie de dedup diferita
    orchestrator.process_alerts(alerts, orchestrator.BoundedSeen(), stats, t2_limit=2, hunt=hunt)
    # 3 escaladate (benign/60 escaladeaza si el pe low_confidence) -> 2 la Tier 2, 2 peste buget
    tier2 = [k["tier2"] for _, k in rec]
    assert tier2 == ["investigated", "investigated", "skipped_budget", "skipped_budget"]
    assert len(hunt.runs) == 2 and stats["tier2"] == 2 and stats["tier2_skipped"] == 2
    t1_chains = [a[0].chain_id for a, _ in rec]
    for (inp, kind, chain), t1 in zip(hunt.runs, t1_chains):
        assert kind == "TIER2" and chain == t1 and isinstance(inp["case"], Case)
        assert inp["case"].chain_id == t1 and set(inp) == {"case"}


def test_neescaladat_nu_merge_la_tier2(monkeypatch, rec):
    monkeypatch.setitem(sys.modules, "fast_path", types.SimpleNamespace(
        build_fast_path=lambda: types.SimpleNamespace(invoke=lambda inp, config=None: {
            "verdict": Verdict(investigation_id="x", source_path="fast", entity_type="host",
                               entity_id="web-prod", classification="benign", confidence=95,
                               rarity_score=0.0, model_id="m"),
            "narrative": "", "context": {"pair_in_baseline": True}}), lookup_asset=lambda h: {}))
    hunt = FakeHunt()
    orchestrator.process_alerts([_alert()], orchestrator.BoundedSeen(), t2_limit=3, hunt=hunt)
    assert hunt.runs == [] and rec[0][1]["tier2"] is None


def test_esecul_tier1_merge_la_tier2(monkeypatch, rec):
    hunt = FakeHunt()
    orchestrator.process_alerts([_alert()], orchestrator.BoundedSeen(), model_ok=False, t2_limit=1, hunt=hunt)
    (inp, _, chain), = hunt.runs
    assert inp["case"].escalation_reasons == [R.UNDETERMINED, R.TIER1_FAILURE]
    assert inp["case"].parent == "dash"   # din alerta, fara fapte de la model


def test_huntrunner_pastreaza_lantul(monkeypatch, rec):
    monkeypatch.setitem(sys.modules, "hunt_path", types.SimpleNamespace(build_hunt_path=lambda: types.SimpleNamespace(
        invoke=lambda inp, config=None: {"verdict": _verdict("benign", "hunt"), "narrative": "benign"})))
    r = orchestrator.HuntRunner(model_ok=True)
    assert r.run({"case": _case()}, "TIER2", "e", "web-prod", chain_id=CID) is None
    (v, *_), k = rec[0]
    assert v.chain_id == CID and v.source_path == "hunt" and k["escalation"] is None


def test_huntrunner_model_cazut(monkeypatch, rec):
    r = orchestrator.HuntRunner(model_ok=False)
    assert r.run({"case": _case()}, "TIER2", "e", "web-prod", chain_id=CID).value == "model_unavailable"
    (v, *_), k = rec[0]
    assert v.chain_id == CID and v.classification.value == "undetermined" and k["failure"].value == "model_unavailable"


# ---------------- podeaua pe actiune pentru cazurile din Tier 1 ----------------

from schemas import ActionType as A


@pytest.mark.parametrize("cls,act,exp", [
    ("suspicious", A.ENRICH_ONLY, A.ESCALATE_HUMAN),
    ("malicious", A.NONE, A.ESCALATE_HUMAN),
    ("undetermined", A.NONE, A.ESCALATE_HUMAN),
    ("malicious", A.ISOLATE_HOST, A.ISOLATE_HOST),        # continerea ramane, o filtreaza decide()
    ("suspicious", A.ESCALATE_HUMAN, A.ESCALATE_HUMAN),
    ("benign", A.NONE, A.NONE),                            # Tier 2 poate inchide (decis cu Tiberiu)
])
def test_podea_tier2(cls, act, exp):
    assert hunt_path.tier1_case_action_floor(cls, act) is exp


def _finalize(monkeypatch, state_input, cls, act):
    monkeypatch.setattr(hunt_path, "prefetch_context", lambda x: {})
    state = {**state_input, "investigation_id": "i",
             "merged_draft": {"classification": cls, "confidence": 70, "proposed_action": act}}
    return hunt_path.node_finalize(state)["verdict"]


def test_finalize_aplica_podeaua_pe_caz(monkeypatch):
    v = _finalize(monkeypatch, {"case": _case()}, "suspicious", "enrich_only")
    assert v.proposed_action is A.ESCALATE_HUMAN and v.entity_id == "web-prod"


def test_finalize_nu_atinge_findings(monkeypatch):
    f = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                      detail={"parent": "dash", "child": "id"}, rarity_score=1.0)
    v = _finalize(monkeypatch, {"finding": f}, "suspicious", "enrich_only")
    assert v.proposed_action is A.ENRICH_ONLY


# ---------------- faza 7: investigatorul B cazut ----------------

def test_b_cazut_nu_crapa_investigatia(monkeypatch):
    def boom(*a, **k):
        raise ConnectionError("tunel 11435 cazut")
    monkeypatch.setattr(hunt_path, "INVESTIGATOR_B", types.SimpleNamespace(invoke=boom))
    out = hunt_path.node_secondary({"case": _case(), "queries_run": []})
    assert out == {"draft_b": None, "secondary_failed": True}


def test_zona_gri_fara_b_escaladeaza():
    draft_a = {"classification": "benign", "confidence": 85, "proposed_action": "none",
               "evidence": {"process_chain": True, "file_write": True}}   # suport 2 = zona gri
    out = hunt_path.node_corroborate({"draft_a": draft_a, "draft_b": None, "secondary_failed": True})
    md = out["merged_draft"]
    assert out["corroboration_status"] == "secondary_unavailable"
    assert md["classification"] == "undetermined" and md["proposed_action"] == "escalate_human"
    assert md["confidence"] <= 40
    # criticul e sters (plann S3): dupa coroborare se merge direct la finalize
    edges = {(e.source, e.target) for e in hunt_path.build_hunt_path().get_graph().edges}
    assert ("corroborate", "finalize") in edges and not any("critic" in e for e in edges)


def test_verdict_accepta_noul_status():
    v = Verdict(investigation_id="i", source_path="hunt", entity_type="host", entity_id="web-prod",
                classification="undetermined", confidence=0, rarity_score=1.0, model_id="m",
                corroboration_status="secondary_unavailable")
    assert v.corroboration_status == "secondary_unavailable"


def test_podea4_tier2_finding_webshell_injectat(monkeypatch):
    # cazul din poarta 2026-11-02: dash -> whoami ca www-data, modelul a zis suspicious/enrich_only
    monkeypatch.setattr(hunt_path, "prefetch_context",
                        lambda x: {"ran_by_web_service_account": True, "via_sudo_by": None})
    f = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                      detail={"parent": "dash", "child": "whoami"}, rarity_score=1.0)
    state = {"finding": f, "investigation_id": "i",
             "merged_draft": {"classification": "suspicious", "confidence": 75, "proposed_action": "enrich_only"}}
    v = hunt_path.node_finalize(state)["verdict"]
    assert v.classification.value == "malicious" and v.proposed_action is A.ESCALATE_HUMAN


def test_podea4_tier2_wp_cli_prin_sudo_neatins(monkeypatch):
    monkeypatch.setattr(hunt_path, "prefetch_context",
                        lambda x: {"ran_by_web_service_account": True, "via_sudo_by": "tiberiu"})
    f = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                      detail={"parent": "dash", "child": "php8.3"}, rarity_score=1.0)
    state = {"finding": f, "investigation_id": "i",
             "merged_draft": {"classification": "benign", "confidence": 90, "proposed_action": "none"}}
    v = hunt_path.node_finalize(state)["verdict"]
    assert v.classification.value != "malicious"

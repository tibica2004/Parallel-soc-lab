"""fast_path: potrivire exacta pe regula in istoric si floor_applied din finalize."""
import fast_path


class FakeES:
    def __init__(self):
        self.query = None

    def search(self, index, size, query, sort):
        self.query = query
        return {"hits": {"hits": [
            {"_source": {"ground_truth": "benign", "notes": "n"}},
            {"_source": {"ground_truth": "attack", "notes": ""}},
        ]}}


def test_lookup_history_term_exact(monkeypatch):
    es = FakeES()
    monkeypatch.setattr(fast_path, "ES", es)
    past, fp = fast_path.lookup_history('RCE: Web server spawns shell')
    filt = es.query["bool"]["filter"]
    assert {"term": {"rule_name.keyword": "RCE: Web server spawns shell"}} in filt
    assert {"exists": {"field": "ground_truth"}} in filt
    assert "must" not in es.query["bool"]
    assert fp == 0.5 and len(past) == 2


def test_lookup_history_fara_regula(monkeypatch):
    es = FakeES()
    monkeypatch.setattr(fast_path, "ES", es)
    assert fast_path.lookup_history("") == ([], None)
    assert es.query is None


def _ctx(**kw):
    base = {"host": "web-prod", "ran_by_web_service_account": False,
            "sensitive_action": False, "in_maintenance_window": False,
            "ran_by_known_admin": True, "pair_in_baseline": True}
    base.update(kw)
    return base


def _finalize(raw, ctx):
    return fast_path.node_finalize({"raw_verdict": raw, "context": ctx})


def test_floor_applied_cont_web():
    out = _finalize({"classification": "benign", "confidence": 95}, _ctx(ran_by_web_service_account=True))
    assert out["floor_applied"] is True
    assert out["verdict"].classification.value == "suspicious"
    assert out["verdict"].confidence <= 60


def test_floor_applied_actiune_sensibila():
    out = _finalize({"classification": "benign", "confidence": 95}, _ctx(sensitive_action=True))
    assert out["floor_applied"] is True


def test_floor_neaplicat_benign_curat():
    out = _finalize({"classification": "benign", "confidence": 95}, _ctx())
    assert out["floor_applied"] is False
    assert out["verdict"].classification.value == "benign"


def test_floor_neaplicat_pe_suspicious():
    out = _finalize({"classification": "suspicious", "confidence": 80}, _ctx(ran_by_web_service_account=True))
    assert out["floor_applied"] is False
    assert out["verdict"].proposed_action.value == "escalate_human"


def test_podea4_serverul_web_a_pornit_un_proces():
    ctx = _ctx(ran_by_web_service_account=True, execution={"parent": "apache2", "sudo_invoked_by": None})
    out = _finalize({"classification": "suspicious", "confidence": 80, "proposed_action": "enrich_only"}, ctx)
    v = out["verdict"]
    assert v.classification.value == "malicious" and v.proposed_action.value == "escalate_human"
    assert v.confidence == 60 and out["floor_applied"] is True     # plafonata ca la podelele 1-2 (faza 22 L)


def test_podea4_nu_se_aplica_prin_sudo():
    ctx = _ctx(ran_by_web_service_account=True, execution={"parent": "dash", "sudo_invoked_by": "tiberiu"})
    out = _finalize({"classification": "suspicious", "confidence": 80}, ctx)
    assert out["verdict"].classification.value == "suspicious"

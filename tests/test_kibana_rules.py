"""Scrierea regulilor Tier 3 in Kibana: fara retea, fara ES."""

from datetime import datetime, timedelta, timezone

import pytest

import kibana_rules as K
import rules as R

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
CHAIN = "54049f6e-4336-4c8b-b361-0c69902d38ea"


def payload(**kw):
    d = R.RuleDraft.model_validate({"template": "arg_prefix", "parent": "bash", "child": "dash",
                                    "dir": "/home/tiberiu/.cache/.kw/", "technique": "T1059.004"})
    q = R.render_eql(d)
    p = R.RuleProposal(rule_id=R.rule_id(q), created_at=NOW, gap_source=R.GapSource.HUMAN, chain_id=CHAIN,
                       host="web-prod", case_event_ids=["evt00001"], case_time=NOW, draft=d, eql=q,
                       status=R.RuleStatus.PROPOSED)
    return {**R.kibana_payload(p), **kw}


def rule(rule_id="t3-0123456789abcdef", tags=(R.TAG, R.SHADOW_TAG), enabled=True, days=8, name="Tier3: x"):
    return {"rule_id": rule_id, "tags": list(tags), "enabled": enabled, "name": name,
            "created_at": (NOW - timedelta(days=days)).isoformat()}


# ---------------- doar regulile proprii ----------------

def test_regula_straina_refuzata():
    for r in (rule(rule_id="rce-web-shell"), rule(tags=("Data Source: Elastic Defend",))):
        with pytest.raises(K.NotOwnRule):
            K.disable_patch(r)
        with pytest.raises(K.NotOwnRule):
            K.promotion_patch(r)


def test_payload_cu_exceptii_refuzat():
    with pytest.raises(K.NotOwnRule):
        K.check_payload(payload(exceptions_list=[{"id": "x"}]))


def test_payload_strain_sau_fara_shadow_refuzat():
    with pytest.raises(K.NotOwnRule):
        K.check_payload(payload(rule_id="custom-1"))
    with pytest.raises(K.NotOwnRule):
        K.check_payload(payload(tags=[R.TAG]))


def test_payload_valid_trece():
    K.check_payload(payload())


def test_promovare_scoate_doar_shadow():
    p = K.promotion_patch(rule(tags=(R.TAG, "T1059.004", R.SHADOW_TAG)))
    assert p["tags"] == [R.TAG, "T1059.004"] and p["severity"] == "medium"
    assert set(p) == {"rule_id", "severity", "risk_score", "tags"}     # nimic altceva modificat


def test_oprire_doar_enabled_false():
    assert K.disable_patch(rule()) == {"rule_id": "t3-0123456789abcdef", "enabled": False}


def test_dry_run_nu_iese_in_retea(monkeypatch):
    import requests
    monkeypatch.setattr(requests, "request", lambda *a, **k: pytest.fail("cerere in dry-run"))
    kb = K.Kibana(dry_run=True)
    assert kb.create(payload()) is None
    assert kb.calls[0][0] == "POST" and "/s/tier3/api/detection_engine/rules" in kb.calls[0][1]


def test_status():
    assert K.status_of(rule()) is R.RuleStatus.SHADOW
    assert K.status_of(rule(tags=(R.TAG,))) is R.RuleStatus.PROMOTED
    assert K.status_of(rule(enabled=False)) is R.RuleStatus.DISABLED


# ---------------- ciclul shadow -> promovare / oprire ----------------

class FakeES:
    def __init__(self, hour=0, total=0, fp=0):
        self.n = {"hour": hour, "total": total, "fp": fp}

    def count(self, index, query):
        f = query["bool"]["filter"]
        if index == R.VERDICTS_IDX:
            return {"count": self.n["fp"]}
        gte = f[1]["range"]["@timestamp"]["gte"]
        return {"count": self.n["hour"] if gte == (NOW - timedelta(hours=1)).isoformat() else self.n["total"]}


class FakeKB(K.Kibana):
    def __init__(self, rules):
        super().__init__(dry_run=True)
        self._rules = rules

    def find_own(self):
        return [r for r in self._rules if K.is_own(r)]


def test_ciclu_promoveaza_dupa_7_zile():
    kb = FakeKB([rule(days=8)])
    res = K.lifecycle(FakeES(total=4), kb, now=NOW)
    assert res[0]["to"] == "promoted" and kb.calls[0][2]["severity"] == "medium"


def test_ciclu_opreste_regula_zgomotoasa():
    kb = FakeKB([rule(days=1)])
    res = K.lifecycle(FakeES(hour=25, total=25), kb, now=NOW)
    assert res[0]["to"] == "disabled" and kb.calls[0][2] == {"rule_id": "t3-0123456789abcdef", "enabled": False}


def test_ciclu_ignora_regulile_straine():
    kb = FakeKB([rule(rule_id="rce-web-shell", days=30)])
    assert K.lifecycle(FakeES(), kb, now=NOW) == [] and kb.calls == []


def test_oprire_globala():
    kb = FakeKB([rule(days=1), rule(rule_id="t3-fedcba9876543210", tags=(R.TAG,))])
    res = K.lifecycle(FakeES(), kb, now=NOW, kill_switch=True)
    assert [r["to"] for r in res] == ["disabled", "disabled"] and len(kb.calls) == 2


def test_fara_schimbare_fara_cerere():
    kb = FakeKB([rule(days=2)])
    K.lifecycle(FakeES(total=1), kb, now=NOW)
    assert kb.calls == []


# ---------------- orchestratorul ignora alertele din shadow ----------------

def test_orchestrator_exclude_alertele_shadow(monkeypatch):
    import orchestrator
    seen = {}

    def search(**kw):
        seen.update(kw)
        return {"hits": {"hits": []}}
    monkeypatch.setattr(orchestrator.ES, "search", search)
    orchestrator.fetch_alerts_between(NOW - timedelta(minutes=5), NOW, 10)
    assert {"term": {"kibana.alert.rule.tags": R.SHADOW_TAG}} in seen["query"]["bool"]["must_not"]
    assert orchestrator.SHADOW_RULE_TAG == R.SHADOW_TAG

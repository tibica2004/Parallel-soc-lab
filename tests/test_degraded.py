"""Modul degradat: esecul escaladeaza, restanta prioritizeaza, plafonul de timp taie."""
import sys
import time
import types
import uuid
from datetime import datetime, timezone

import pytest

import degraded
import orchestrator
from degraded import llm_healthy as real_llm_healthy   # inainte de fixture-ul autouse
from schemas import EscalationReason as R, FailureKind as F, Verdict


def _alert(n, sev="high", host="web-prod"):
    return {"@timestamp": f"2026-10-09T00:00:{n:02d}Z", "host": {"name": host},
            "kibana.alert.rule.name": f"R{n}", "kibana.alert.severity": sev,
            "process": {"entity_id": f"E{n}"}}


def _verdict(cls="benign"):
    return Verdict(investigation_id=str(uuid.uuid4()), source_path="fast", entity_type="host",
                   entity_id="web-prod", classification=cls, confidence=95, rarity_score=0.0, model_id="m")


class Rec:
    def __init__(self):
        self.calls = []

    def __call__(self, *a, **k):
        self.calls.append((a, k))


@pytest.fixture
def rec(monkeypatch):
    r = Rec()
    monkeypatch.setattr(orchestrator, "persist", r)
    monkeypatch.setattr(orchestrator, "show", lambda *a, **k: None)
    return r


def _fast_module(monkeypatch, invoke, crit="high"):
    built = []
    def build():
        built.append(1)
        return types.SimpleNamespace(invoke=invoke)
    monkeypatch.setitem(sys.modules, "fast_path", types.SimpleNamespace(
        build_fast_path=build, lookup_asset=lambda h: {"criticality": crit}))
    return built


def _never(inp, config=None):
    raise AssertionError("modelul nu trebuia apelat")


def _assert_nothing_closed(rec):
    for (v, *_), k in rec.calls:
        assert v.classification.value != "benign" and v.proposed_action.value != "none"


# ---------------- functii pure ----------------

def test_prag_restanta():
    assert not degraded.is_backlog(20, threshold=20) and degraded.is_backlog(21, threshold=20)


def test_ordine_restanta():
    alerts = [_alert(1, "high", "a"), _alert(2, "critical", "b"), _alert(3, "high", "c"), _alert(4, "low", "a")]
    crit = {"a": "low", "b": "low", "c": "critical"}
    out = degraded.order_backlog(alerts, crit.get)
    assert [x["kibana.alert.rule.name"] for x in out] == ["R2", "R3", "R1", "R4"]


@pytest.mark.parametrize("sev,exp", [("critical", True), ("CRITICAL", True), ("high", False), (None, False)])
def test_grava(sev, exp):
    a = _alert(1)
    a["kibana.alert.severity"] = sev
    assert degraded.is_severe(a) is exp


@pytest.mark.parametrize("ent", ["web-prod", 'web"; DROP', None])
def test_verdict_fara_model(ent):
    v = degraded.no_model_verdict(ent, "fast")
    assert v.classification.value == "undetermined" and v.confidence == 0
    assert v.proposed_action.value == "escalate_human" and v.model_id == "none"
    assert v.entity_id == (ent if ent == "web-prod" else "unknown")


def test_timeout():
    assert degraded.run_with_timeout(lambda: 42, 1) == 42
    t0 = time.monotonic()
    with pytest.raises(degraded.CaseTimeout):
        degraded.run_with_timeout(lambda: time.sleep(2), 0.1)
    assert time.monotonic() - t0 < 1
    with pytest.raises(ValueError):
        degraded.run_with_timeout(lambda: (_ for _ in ()).throw(ValueError("x")), 1)


def test_sanatate(monkeypatch):
    monkeypatch.setenv("MODEL_FAST", "redsage")
    ok = lambda url, t: {"data": [{"id": "redsage"}, {"id": "qwen3:14b"}]}
    assert real_llm_healthy("fast", fetch=ok) is True
    assert real_llm_healthy("fast", fetch=lambda url, t: {"data": [{"id": "qwen3:14b"}]}) is False
    def down(url, t):
        raise ConnectionRefusedError()
    assert real_llm_healthy("fast", fetch=down) is False
    assert real_llm_healthy("fast", fetch=lambda url, t: {"neasteptat": 1}) is False


# ---------------- orchestrator ----------------

def test_model_cazut_totul_escaladeaza(monkeypatch, rec):
    built = _fast_module(monkeypatch, _never)
    stats = {"total": 0, "escalated": 0, "no_model": 0}
    seen = orchestrator.BoundedSeen()
    orchestrator.process_alerts([_alert(1), _alert(2)], seen, stats, model_ok=False)
    assert built == [] and {k: stats[k] for k in ("total", "escalated", "no_model")} == {"total": 2, "escalated": 2, "no_model": 2}
    assert stats["tier2_skipped"] == 2   # t2_limit=0 implicit: escaladate doar la om
    for (v, *_), k in rec.calls:
        assert k["failure"] is F.MODEL_UNAVAILABLE
        assert k["escalation"].reasons == [R.UNDETERMINED, R.TIER1_FAILURE]
    _assert_nothing_closed(rec)
    assert all(orchestrator.dedup_key_alert(_alert(n)) in seen for n in (1, 2))


def test_model_cade_in_mijlocul_lotului(monkeypatch, rec):
    calls = []
    def invoke(inp, config=None):
        calls.append(1)
        raise ConnectionError("tunel cazut")
    _fast_module(monkeypatch, invoke)
    monkeypatch.setattr(degraded, "llm_healthy", lambda role, fetch=None: False)
    orchestrator.process_alerts([_alert(1), _alert(2), _alert(3)], orchestrator.BoundedSeen())
    assert len(calls) == 1   # dupa prima cadere, restul nu mai asteapta modelul
    assert [k["failure"] for _, k in rec.calls] == [F.MODEL_UNAVAILABLE] * 3
    _assert_nothing_closed(rec)


def test_eroare_cu_model_sanatos(monkeypatch, rec):
    outs = iter([ValueError("graf"), {"verdict": _verdict("benign"), "narrative": "",
                                      "floor_applied": False, "context": {"pair_in_baseline": True}}])
    def invoke(inp, config=None):
        o = next(outs)
        if isinstance(o, Exception):
            raise o
        return o
    _fast_module(monkeypatch, invoke)
    orchestrator.process_alerts([_alert(1), _alert(2)], orchestrator.BoundedSeen())
    assert rec.calls[0][1]["failure"] is F.PROCESSING_ERROR
    assert rec.calls[1][1]["failure"] is None and rec.calls[1][1]["escalation"].escalate is False


def test_plafon_de_timp(monkeypatch, rec):
    monkeypatch.setattr(degraded, "CASE_TIMEOUT_FAST_S", 0.1)
    _fast_module(monkeypatch, lambda inp, config=None: time.sleep(2))
    t0 = time.monotonic()
    orchestrator.process_alerts([_alert(1)], orchestrator.BoundedSeen())
    assert time.monotonic() - t0 < 1.5
    assert rec.calls[0][1]["failure"] is F.CASE_TIMEOUT
    _assert_nothing_closed(rec)


def test_restanta_gravele_fara_model_si_primele(monkeypatch, rec):
    monkeypatch.setattr(degraded, "BACKLOG_THRESHOLD", 3)
    judged = []
    def invoke(inp, config=None):
        judged.append(inp["alert"]["kibana.alert.rule.name"])
        return {"verdict": _verdict("suspicious"), "narrative": "", "floor_applied": False,
                "context": {"pair_in_baseline": True}}
    _fast_module(monkeypatch, invoke)
    alerts = [_alert(1), _alert(2, "critical"), _alert(3), _alert(4, "critical"), _alert(5)]
    last = orchestrator.process_alerts(alerts, orchestrator.BoundedSeen())
    assert last == "2026-10-09T00:00:05Z"            # pozitia avanseaza la cea mai noua, nu la ultima procesata
    assert judged == ["R1", "R3", "R5"]              # cele critical n-au ajuns la model
    first_two = rec.calls[:2]
    assert [k["escalation"].reasons for _, k in first_two] == [[R.BACKLOG_SEVERE]] * 2
    assert all(k["failure"] is None for _, k in first_two)


def test_fara_restanta_gravele_trec_prin_model(monkeypatch, rec):
    judged = []
    _fast_module(monkeypatch, lambda inp, config=None: (judged.append(1), {
        "verdict": _verdict("malicious"), "narrative": "", "context": {"pair_in_baseline": True}})[1])
    orchestrator.process_alerts([_alert(1, "critical")], orchestrator.BoundedSeen())
    assert judged == [1]


def test_finding_cu_model_cazut_neinvestigat_si_nemarcat(monkeypatch, rec):
    from schemas import EntityType, RarityFinding
    f = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                      detail={"parent": "dash", "child": "id"}, rarity_score=1.0)
    monkeypatch.setitem(sys.modules, "hunt_path", types.SimpleNamespace(
        build_hunt_path=lambda: (_ for _ in ()).throw(AssertionError("nu trebuia construit"))))
    seen = orchestrator.BoundedSeen()
    orchestrator.process_findings([f], seen, limit=5, model_ok=False)
    (v, *_), k = rec.calls[0]
    assert v.source_path == "hunt" and v.classification.value == "undetermined"
    assert k["failure"] is F.MODEL_UNAVAILABLE and k["escalation"] is None
    assert orchestrator.dedup_key_finding(f) not in seen


def test_persist_scrie_tipul_de_esec(monkeypatch):
    docs = []
    monkeypatch.setattr(orchestrator, "WRITER", types.SimpleNamespace(
        index=lambda index, document, id=None: docs.append((index, document))))
    v = orchestrator.with_chain(degraded.no_model_verdict("web-prod", "fast"))
    now = datetime.now(timezone.utc)
    orchestrator.persist(v, degraded.NARRATIVE[F.CASE_TIMEOUT], orchestrator.decide(v), now, now,
                         escalation=degraded.failure_escalation(), failure=F.CASE_TIMEOUT)
    adoc = docs[1][1]
    assert adoc["failure"] == "case_timeout" and adoc["escalate"] is True
    assert adoc["escalation_reasons"] == ["undetermined", "tier1_failure"]
    assert adoc["action_executed"] == "escalate_human"

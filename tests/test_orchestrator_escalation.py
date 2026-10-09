"""Orchestratorul: escaladarea decisa dupa Tier 1 ajunge in audit; modul manual
foloseste aceleasi functii; sweep-ul manual trece prin decide() si persist()."""
import sys
import types
import uuid

import orchestrator
from escalation import EscalationDecision
from schemas import AuditRecord, EscalationReason as R, Verdict


def _verdict(cls="benign", conf=95, source="fast"):
    return Verdict(investigation_id=str(uuid.uuid4()), source_path=source, entity_type="host",
                   entity_id="web-prod", classification=cls, confidence=conf,
                   rarity_score=0.0, model_id="m")


def _alert(n):
    return {"@timestamp": f"2026-10-09T00:00:0{n}Z", "host": {"name": "web-prod"},
            "kibana.alert.rule.name": "R", "process": {"entity_id": f"E{n}"}}


class Rec:
    def __init__(self):
        self.calls = []

    def __call__(self, *a, **k):
        self.calls.append((a, k))


def _fast(outs):
    it = iter(outs)
    return types.SimpleNamespace(build_fast_path=lambda: types.SimpleNamespace(invoke=lambda inp, config=None: next(it)))


def test_escaladarea_ajunge_in_persist(monkeypatch):
    outs = [
        {"verdict": _verdict("benign", 95), "narrative": "", "floor_applied": False,
         "context": {"pair_in_baseline": True}},
        {"verdict": _verdict("suspicious", 60), "narrative": "", "floor_applied": True,
         "context": {"pair_in_baseline": True}},
    ]
    monkeypatch.setitem(sys.modules, "fast_path", _fast(outs))
    monkeypatch.setattr(orchestrator, "show", lambda *a, **k: None)
    rec = Rec()
    monkeypatch.setattr(orchestrator, "persist", rec)
    stats = {"total": 0, "escalated": 0}
    orchestrator.process_alerts([_alert(1), _alert(2)], orchestrator.BoundedSeen(), stats)
    assert stats == {"total": 2, "escalated": 1, "no_model": 0}
    e1, e2 = (c[1]["escalation"] for c in rec.calls)
    assert e1.escalate is False and e1.reasons == []
    assert e2.escalate is True and R.FLOOR_OVERRIDE in e2.reasons and R.SUSPICIOUS in e2.reasons
    v1, v2 = (c[0][0] for c in rec.calls)
    assert v1.chain_id and v2.chain_id and v1.chain_id != v2.chain_id


def test_lipsa_faptelor_nu_inchide(monkeypatch):
    # Fara context/floor_applied in iesire, pair_in_baseline=None -> benign escaladeaza.
    monkeypatch.setitem(sys.modules, "fast_path", _fast([{"verdict": _verdict("benign", 95), "narrative": ""}]))
    monkeypatch.setattr(orchestrator, "show", lambda *a, **k: None)
    rec = Rec()
    monkeypatch.setattr(orchestrator, "persist", rec)
    orchestrator.process_alerts([_alert(1)], orchestrator.BoundedSeen())
    assert rec.calls[0][1]["escalation"].reasons == [R.BENIGN_UNSEEN_PAIR]


class FakeWriter:
    def __init__(self):
        self.docs = []

    def index(self, index, document, id=None):
        self.docs.append((index, document))


def test_persist_scrie_chain_si_motivele(monkeypatch):
    w = FakeWriter()
    monkeypatch.setattr(orchestrator, "WRITER", w)
    v = orchestrator.with_chain(_verdict("suspicious", 70))
    d = orchestrator.decide(v)
    esc = EscalationDecision(escalate=True, reasons=[R.SUSPICIOUS, R.LOW_CONFIDENCE])
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    orchestrator.persist(v, "text", d, now, now, {"rule_name": "R"}, escalation=esc)
    (vi, vdoc), (ai, adoc) = w.docs
    assert vi == "verdicts-history" and vdoc["chain_id"] == v.chain_id and vdoc["ground_truth"] is None
    assert ai == "soc-audit" and adoc["chain_id"] == v.chain_id
    assert adoc["escalate"] is True and adoc["escalation_reasons"] == ["suspicious", "low_confidence"]
    AuditRecord.model_validate({k: x for k, x in adoc.items() if k != "@timestamp"})


def test_persist_cale_lenta_fara_escaladare(monkeypatch):
    w = FakeWriter()
    monkeypatch.setattr(orchestrator, "WRITER", w)
    v = orchestrator.with_chain(_verdict("malicious", 90, source="hunt"))
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    orchestrator.persist(v, "", orchestrator.decide(v), now, now)
    adoc = w.docs[1][1]
    assert adoc["escalate"] is None and adoc["escalation_reasons"] == []


def test_main_manual_foloseste_aceleasi_functii(monkeypatch):
    calls = {}
    monkeypatch.setattr(orchestrator, "fetch_new_alerts", lambda m, l: [_alert(1)])
    monkeypatch.setattr(orchestrator, "process_alerts",
                        lambda alerts, seen, stats=None, model_ok=True: calls.setdefault("alerts", (alerts, seen)))
    monkeypatch.setattr(orchestrator, "process_findings",
                        lambda findings, seen, limit, model_ok=True: calls.setdefault("findings", (findings, limit)))
    monkeypatch.setitem(sys.modules, "elastic_tools",
                        types.SimpleNamespace(sweep_new_parent_child=lambda h: ["F"]))
    monkeypatch.setattr(sys, "argv", ["orchestrator.py", "--minutes", "60", "--sweep", "--limit", "7"])
    assert orchestrator.main() == 0
    assert calls["alerts"][0] == [_alert(1)]
    assert isinstance(calls["alerts"][1], orchestrator.BoundedSeen)
    assert calls["findings"] == (["F"], 7)


def test_sweep_trece_prin_decide_si_persist(monkeypatch):
    from schemas import EntityType, RarityFinding
    f = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                      detail={"parent": "dash", "child": "id"}, rarity_score=1.0)
    monkeypatch.setitem(sys.modules, "hunt_path", types.SimpleNamespace(
        build_hunt_path=lambda: types.SimpleNamespace(
            invoke=lambda inp, config=None: {"verdict": _verdict("malicious", 95, "hunt"), "narrative": ""})))
    decided = Rec()
    real_decide = orchestrator.decide
    monkeypatch.setattr(orchestrator, "decide", lambda v: (decided(v), real_decide(v))[1])
    monkeypatch.setattr(orchestrator, "show", lambda *a, **k: None)
    rec = Rec()
    monkeypatch.setattr(orchestrator, "persist", rec)
    orchestrator.process_findings([f], orchestrator.BoundedSeen(), limit=5)
    assert len(decided.calls) == 1 and len(rec.calls) == 1
    assert rec.calls[0][0][0].chain_id

"""Deduplicarea: persistenta, expirarea si marcarea doar dupa succes."""
import types

import orchestrator
from schemas import Verdict
import state
from orchestrator import BoundedSeen


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def test_ordine_si_limita():
    c = Clock()
    s = BoundedSeen(maxlen=3, ttl_hours=24, clock=c)
    for k in "abcd":
        s.add(k); c.t += 1
    assert [k for k, _ in s.entries()] == ["b", "c", "d"]
    assert "a" not in s


def test_expirare():
    c = Clock()
    s = BoundedSeen(ttl_hours=1, clock=c)
    s.add("vechi")
    c.t += 1800
    s.add("nou")
    c.t += 2000          # "vechi" are 3800s > 1h, "nou" are 2000s
    assert "vechi" not in s
    assert "nou" in s


def test_reincarcare_pastreaza_si_expira():
    c = Clock()
    entries = [("b", c.t - 10), ("a", c.t - 100), ("expirat", c.t - 90_000)]
    s = BoundedSeen(ttl_hours=24, entries=entries, clock=c)
    assert [k for k, _ in s.entries()] == ["a", "b"]


class FakeWriter:
    def __init__(self):
        self.docs = {}

    def index(self, index, id, document):
        self.docs[(index, id)] = document

    def get(self, index, id):
        if (index, id) not in self.docs:
            raise KeyError(id)
        return {"_source": self.docs[(index, id)]}


def test_save_load_dus_intors(monkeypatch):
    w = FakeWriter()
    monkeypatch.setattr(state, "_writer", lambda: w)
    state.save_seen([("k1", 1.0), ("k2", 2.5)])
    assert state.load_seen() == [("k1", 1.0), ("k2", 2.5)]


def test_load_esec_lista_goala(monkeypatch):
    def boom():
        raise RuntimeError("ES cazut")
    monkeypatch.setattr(state, "_writer", boom)
    assert state.load_seen() == []


def test_load_ignora_intrari_stricate(monkeypatch):
    w = FakeWriter()
    w.docs[(state.STATE_IDX, state.SEEN_ID)] = {"entries": [
        {"k": "ok", "t": 5}, {"k": 3, "t": 1}, "text", {"k": "fara_t"}]}
    monkeypatch.setattr(state, "_writer", lambda: w)
    assert state.load_seen() == [("ok", 5.0)]


def _verdict():
    return Verdict(investigation_id="t", source_path="fast", entity_type="host", entity_id="web-prod",
                   classification="benign", confidence=95, rarity_score=0.0, model_id="m")


def _fake_alert(n):
    return {"@timestamp": f"2026-10-09T00:00:0{n}Z", "host": {"name": "web-prod"},
            "kibana.alert.rule.name": "R", "process": {"entity_id": f"E{n}"}}


def test_alerta_esuata_nu_e_marcata(monkeypatch):
    def invoke(inp, config=None):
        if inp["alert"]["process"]["entity_id"] == "E1":
            raise RuntimeError("model cazut")
        return {"verdict": _verdict(), "narrative": ""}
    monkeypatch.setitem(__import__("sys").modules, "fast_path",
                        types.SimpleNamespace(build_fast_path=lambda: types.SimpleNamespace(invoke=invoke)))
    monkeypatch.setattr(orchestrator, "decide", lambda v: None)
    monkeypatch.setattr(orchestrator, "show", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "persist", lambda *a, **k: None)
    seen = BoundedSeen()
    orchestrator.process_alerts([_fake_alert(1), _fake_alert(2)], seen)
    assert orchestrator.dedup_key_alert(_fake_alert(1)) not in seen
    assert orchestrator.dedup_key_alert(_fake_alert(2)) in seen


def test_finding_esuat_nu_e_marcat(monkeypatch):
    from schemas import EntityType, RarityFinding
    f_ok = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                         detail={"parent": "bash", "child": "ps"}, rarity_score=0.5)
    f_bad = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                          detail={"parent": "dash", "child": "id"}, rarity_score=1.0)

    def invoke(inp, config=None):
        if inp["finding"] is f_bad:
            raise TimeoutError("timeout")
        return {"verdict": _verdict(), "narrative": ""}
    monkeypatch.setitem(__import__("sys").modules, "hunt_path",
                        types.SimpleNamespace(build_hunt_path=lambda: types.SimpleNamespace(invoke=invoke)))
    monkeypatch.setattr(orchestrator, "decide", lambda v: None)
    monkeypatch.setattr(orchestrator, "show", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "persist", lambda *a, **k: None)
    seen = BoundedSeen()
    orchestrator.process_findings([f_bad, f_ok], seen, limit=5)
    assert orchestrator.dedup_key_finding(f_bad) not in seen
    assert orchestrator.dedup_key_finding(f_ok) in seen

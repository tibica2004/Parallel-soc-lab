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


def test_alerta_esuata_e_escaladata_si_marcata(monkeypatch):
    """Faza 4: o alerta pe care modelul n-o poate judeca devine undetermined +
    escalate_human, scrisa in audit; e rezolvata (a ajuns la om), deci marcata."""
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
    assert orchestrator.dedup_key_alert(_fake_alert(1)) in seen
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


# --- pasul 10.2: alertele lotului grupate in cazuri --------------------------------------
import orchestrator as _o


def _web(ip, rule="Suricata: tentativa de atac web (IDS)", ts="2026-11-02T10:00:00Z"):
    return {"kibana.alert.rule.name": rule, "host": {"name": "web-prod"}, "source": {"ip": ip},
            "@timestamp": ts}


def test_rafala_de_la_un_ip_e_un_caz():
    alerts = [_web("172.30.6.133", ts=f"2026-11-02T10:00:{i:02d}Z") for i in range(30)] + [_web("9.9.9.9")]
    g = _o.group_alerts(alerts)
    assert [len(m) for _, m in g] == [30, 1]
    ex = _o.case_extra(g[0][1])
    assert ex["case_alert_count"] == 30 and ex["case_first_ts"] < ex["case_last_ts"]
    assert _o.case_extra(g[1][1]) == {}


def test_reguli_diferite_raman_cazuri_separate():
    g = _o.group_alerts([_web("172.30.6.133"), _web("172.30.6.133", rule="Alta regula")])
    assert len(g) == 2


def test_alertele_de_jurnal_diferite_nu_se_unesc():
    a = {"kibana.alert.rule.name": "YARA", "host": {"name": "web-prod"}, "message": "fisier A"}
    b = {"kibana.alert.rule.name": "YARA", "host": {"name": "web-prod"}, "message": "fisier B"}
    assert len(_o.group_alerts([a, b])) == 2

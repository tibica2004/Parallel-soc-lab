"""Faza 24: cascada in orchestrator. L5 (off = verdicte identice, cascada nici nu ruleaza), umbra
(verdicte identice, decizia doar inregistrata), on (inchide doar ce are voie), L2 (fara ground_truth),
L6 (eroarea -> pasul 4), Tier 1 -> Tier 2 prin magistrala cu identificatorul grupului."""
import types
import uuid

import pytest

import orchestrator
from elasticlab.contracts.learning import CascadeMode, ModelDecision, ModelState, Prediction
from elasticlab.core import cascade as K, pipelines
from elasticlab.tier1 import cascade as T
from modswap import swap_module
from schemas import Verdict

CFG = pipelines.load()
P = pipelines.pipeline_for(CFG, "RCE: Web server spawns shell")


def _verdict(cls, conf):
    return Verdict(investigation_id=str(uuid.uuid4()), source_path="fast", entity_type="host",
                   entity_id="web-prod", classification=cls, confidence=conf, rarity_score=0.0,
                   model_id="m")


def _alert(n, rule="RCE: Web server spawns shell"):
    return {"@timestamp": f"2026-11-27T00:00:{n:02d}Z", "host": {"name": "web-prod"},
            "kibana.alert.rule.name": rule, "process": {"entity_id": f"E{n}"},
            "_soc_ref": {"index": ".alerts-security.alerts-default", "id": f"A{n}"}}


OUTS = [("benign", 95, True), ("suspicious", 60, True), ("benign", 97, True), ("malicious", 80, True)]


def _outs():
    return [{"verdict": _verdict(c, conf), "narrative": "n", "floor_applied": False,
             "context": {"pair_in_baseline": pib}} for c, conf, pib in OUTS]


class Graph:
    def __init__(self):
        self.it = iter(_outs())
        self.inputs = []

    def invoke(self, inp, config=None):
        self.inputs.append(inp)
        return next(self.it)


FACTS = {"rule_name": "RCE: Web server spawns shell",
         "execution": {"user": "deploy", "process": "apt-get", "parent": "bash",
                       "executable": "/usr/bin/apt-get", "sudo_invoked_by": "tiberiu"},
         "ran_by_web_service_account": False, "ran_by_known_admin": True, "sensitive_action": False,
         "in_maintenance_window": True, "pair_in_baseline": True}


class Src:
    kind, model_hash, state = "own_model", "d" * 64, ModelState.ACTIVE

    def __init__(self, dec="benign", conf=99):
        self.dec, self.conf = dec, conf

    def predict(self, values, alert):
        return Prediction(source="own_model", model_hash=self.model_hash,
                          decision=ModelDecision(self.dec), confidence=self.conf)


def run(monkeypatch, mode=None, rt=None, alerts=None, t2_limit=0):
    """Ruleaza process_alerts cu caile false. Intoarce (apeluri persist, intrarile grafului, mesaje)."""
    fast_graph = Graph()
    swap_module(monkeypatch, "fast_path", types.SimpleNamespace(build_fast_path=lambda: fast_graph))
    monkeypatch.setattr(orchestrator, "show", lambda *a, **k: None)
    calls = []
    monkeypatch.setattr(orchestrator, "persist", lambda *a, **k: calls.append((a, k)))
    if mode is None:
        monkeypatch.delenv("T1_CASCADE", raising=False)
    else:
        monkeypatch.setenv("T1_CASCADE", mode)
    pre_graph = Graph()
    monkeypatch.setattr(T, "build_prefetched", lambda config=None: pre_graph)
    if rt is not None:
        monkeypatch.setattr(orchestrator, "_cascade_runtime", lambda: rt)
    msgs = []
    for topic in ("cascada.decizie", "tier2.caz"):
        orchestrator.BUS.subscribe(topic, lambda m, t=topic: msgs.append((t, m)))
    stats = {"total": 0, "escalated": 0}
    try:
        orchestrator.process_alerts(alerts or [_alert(i) for i in range(4)], orchestrator.BoundedSeen(),
                                    stats, t2_limit=t2_limit, hunt=types.SimpleNamespace(run=lambda *a, **k: None))
    finally:
        for topic in ("cascada.decizie", "tier2.caz"):
            orchestrator.BUS._subs[topic] = [s for s in orchestrator.BUS._subs[topic]
                                             if s[0].__name__ != "<lambda>"]
    return calls, fast_graph.inputs + pre_graph.inputs, msgs, stats


def comparable(calls):
    out = []
    for a, k in calls:
        v = a[0]
        out.append((v.classification.value, v.confidence, v.proposed_action.value, v.model_id,
                    k["escalation"].escalate, [r.value for r in k["escalation"].reasons],
                    {x: y for x, y in a[5].items() if x != "cascade"}))
    return out


def rt_with(mode, consensus="none", src=None, active=True, ctx=None, **kw):
    r = T.Runtime(mode=mode, cfg=CFG, build_context=lambda a: dict(ctx or FACTS),
                  bucket_reader=lambda bid: {"consensus": consensus, "dp_version": 1},
                  sources={P.id: src} if src else {}, active={P.id: active})
    for k, v in kw.items():
        setattr(r, k, v)
    return r


# ---------------- L5 ----------------

def test_L5_off_implicit_si_explicit_identic_si_cascada_nu_ruleaza(monkeypatch):
    monkeypatch.setattr(T, "evaluate", lambda *a, **k: (_ for _ in ()).throw(AssertionError("cascada rulata")))
    monkeypatch.setattr(T, "load_runtime", lambda *a, **k: (_ for _ in ()).throw(AssertionError("runtime incarcat")))
    base, inputs0, msgs0, _ = run(monkeypatch, mode=None)
    off, inputs1, msgs1, _ = run(monkeypatch, mode="off")
    assert comparable(base) == comparable(off)
    assert all(set(i) == {"alert"} for i in inputs0 + inputs1)      # graful vechi, aceeasi intrare
    assert msgs0 == msgs1 == []                                       # nicio decizie de cascada
    for a, _k in base + off:
        assert "cascade" not in a[5]


def test_L5_off_neschimbat_chiar_daca_exista_grup_benign_si_model(monkeypatch, tmp_path):
    monkeypatch.setenv("CASCADE_KILL_FILE", str(tmp_path / "nu-exista"))
    base, _, _, _ = run(monkeypatch, mode="off")
    # aceleasi verdicte ca un orchestrator fara faza 24 (fixate aici din comportamentul de azi)
    assert [c[:6] for c in comparable(base)] == [
        ("benign", 95, "none", "m", False, []),
        ("suspicious", 60, "none", "m", True, ["suspicious", "low_confidence"]),
        ("benign", 97, "none", "m", False, []),
        ("malicious", 80, "none", "m", True, ["malicious", "low_confidence"])]


def test_fisierul_de_oprire_opreste_cascada_fara_repornire(monkeypatch, tmp_path):
    kill = tmp_path / "cascade-off"
    kill.write_text("")
    monkeypatch.setenv("CASCADE_KILL_FILE", str(kill))
    monkeypatch.setenv("T1_CASCADE", "on")
    assert orchestrator._cascade_runtime() is None


# ---------------- umbra ----------------

def test_umbra_verdicte_identice_cu_off_si_decizia_inregistrata(monkeypatch):
    off, _, _, _ = run(monkeypatch, mode="off")
    rt = rt_with(CascadeMode.SHADOW, consensus="benign", src=Src())
    sh, inputs, msgs, stats = run(monkeypatch, rt=rt)
    assert comparable(sh) == comparable(off)
    assert all("context" in i for i in inputs)                       # faptele o singura data
    casc = [a[5]["cascade"] for a, _ in sh]
    assert all(c["mode"] == "shadow" and c["would_close"] and not c["applied"] for c in casc)
    assert len([m for t, m in msgs if t == "cascada.decizie"]) == 4
    assert stats["cascade"]["would_close"] == 4 and stats["cascade"]["closed"] == 0


# ---------------- on ----------------

def test_on_inchide_grupul_benign_fara_model_de_limbaj_si_fara_ground_truth(monkeypatch):
    sk = [f"x{i}" for i in range(4)]
    monkeypatch.setattr(K, "in_control_sample", lambda key, pct: False)
    rt = rt_with(CascadeMode.ON, consensus="benign", src=Src())
    calls, inputs, msgs, stats = run(monkeypatch, rt=rt)
    assert inputs == []                                               # niciun apel de model
    for a, k in calls:
        v = a[0]
        assert v.classification.value == "benign" and v.proposed_action.value == "none"
        assert v.model_id == "cascade:human_label" and k["escalation"].escalate is False
        assert a[5]["cascade"]["applied"] and a[5]["cascade"]["step"] == "human_label"
    assert stats["cascade"]["closed"] == 4 and stats["escalated"] == 0
    assert sk


def test_L2_persist_scrie_inchiderea_cascadei_fara_ground_truth(monkeypatch):
    class W:
        def __init__(self):
            self.docs = []

        def index(self, index, document, id=None, **k):
            self.docs.append((index, document))
    w = W()
    monkeypatch.setattr(orchestrator, "WRITER", w)
    monkeypatch.setattr(orchestrator, "_upsert_case", lambda *a, **k: None)
    monkeypatch.setattr(K, "in_control_sample", lambda key, pct: False)
    d = K.decide(K.CascadeInputs(mode=CascadeMode.ON, pipeline=P, pipeline_active=True,
                                 bucket=__import__("elasticlab.core.buckets", fromlist=["x"]).bucket_key(P.id, 1, {"rule": "r0"}),
                                 consensus=__import__("elasticlab.contracts.learning", fromlist=["x"]).Consensus.BENIGN))
    v = orchestrator.with_chain(T.close_verdict(d, "web-prod"))
    dec = orchestrator.decide(v)
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    orchestrator.persist(v, "n", dec, now, now, {"cascade": T.summary(d)})
    vdoc = next(doc for idx, doc in w.docs if idx == "verdicts-history")
    assert vdoc["ground_truth"] is None and "label_source" not in vdoc
    assert vdoc["cascade"]["applied"] and vdoc["bucket_id"] == d.bucket_id


def test_on_pipeline_neactiv_nu_inchide(monkeypatch):
    off, _, _, _ = run(monkeypatch, mode="off")
    rt = rt_with(CascadeMode.ON, consensus="benign", src=Src(), active=False)
    on, _, _, _ = run(monkeypatch, rt=rt)
    assert comparable(on) == comparable(off)


def test_on_grup_attack_adauga_motivul_si_forteaza_escaladarea(monkeypatch):
    rt = rt_with(CascadeMode.ON, consensus="attack", src=Src())
    calls, inputs, _, _ = run(monkeypatch, rt=rt)
    assert len(inputs) == 4                                          # pasul 4 a rulat
    for a, k in calls:
        assert k["escalation"].escalate is True
        assert "bucket_labeled_attack" in [r.value for r in k["escalation"].reasons]


def test_on_esantionul_de_control_merge_la_om(monkeypatch):
    monkeypatch.setattr(K, "in_control_sample", lambda key, pct: True)
    rt = rt_with(CascadeMode.ON, consensus="none", src=Src("benign", 99))
    calls, inputs, _, stats = run(monkeypatch, rt=rt)
    assert len(inputs) == 4 and stats["cascade"]["control"] == 4 and stats["cascade"]["closed"] == 0
    for a, k in calls:
        assert k["escalation"].escalate and "control_sample" in [r.value for r in k["escalation"].reasons]


def test_on_clasa_critica_nu_se_inchide(monkeypatch):
    ctx = {**FACTS, "ran_by_web_service_account": True,
           "execution": {"user": "www-data", "parent": "apache2", "process": "sh"}}
    rt = rt_with(CascadeMode.ON, consensus="benign", src=Src(), ctx=ctx)
    off, _, _, _ = run(monkeypatch, mode="off")
    on, inputs, _, _ = run(monkeypatch, rt=rt)
    assert len(inputs) == 4 and comparable(on) == comparable(off)
    assert all(a[5]["cascade"]["step"] == "critical" for a, _ in on)


def test_L6_eroare_in_cascada_pasul_4_neschimbat(monkeypatch):
    off, _, _, _ = run(monkeypatch, mode="off")
    rt = rt_with(CascadeMode.ON, consensus="benign", src=Src(), build_context=lambda a: 1 / 0)
    on, inputs, _, stats = run(monkeypatch, rt=rt)
    assert comparable(on) == comparable(off) and stats["cascade"]["errors"] == 4
    assert all(set(i) == {"alert"} for i in inputs)                  # fara fapte: graful obisnuit


def test_alerta_fara_pipeline_trece_prin_pasul_4(monkeypatch):
    rt = rt_with(CascadeMode.ON, consensus="benign", src=Src())
    calls, inputs, _, _ = run(monkeypatch, rt=rt, alerts=[_alert(i, rule="Alta regula") for i in range(4)])
    assert len(inputs) == 4 and all(a[5]["cascade"]["step"] == "no_pipeline" for a, _ in calls)


# ---------------- magistrala: Tier 2 primeste grupul, nu verdictul ----------------

def test_tier2_prin_magistrala_cu_bucket_id_si_motivele(monkeypatch):
    rt = rt_with(CascadeMode.ON, consensus="attack", src=Src())
    runs = []
    monkeypatch.setattr(orchestrator, "_T2_CTX", {})
    calls, _, msgs, stats = run(monkeypatch, rt=rt, t2_limit=1)
    t2 = [m for t, m in msgs if t == "tier2.caz"]
    assert len(t2) == 1
    c = t2[0].case
    assert t2[0].bucket_id and c.bucket_id == t2[0].bucket_id
    assert "bucket_labeled_attack" in [r.value for r in c.escalation_reasons]
    dumped = c.model_dump()
    for forbidden in ("classification", "confidence", "narrative", "consensus", "prediction"):
        assert forbidden not in dumped
    assert runs == []


def test_seed_tier2_nu_trimite_bucket_id_la_model():
    from elasticlab.tier2 import hunt_path
    import inspect
    src = inspect.getsource(hunt_path)
    assert "bucket_id" not in src

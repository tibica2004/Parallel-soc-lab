"""Faza 24: controlorul de activare (toate tranzitiile), registrul modelelor (hash, revenire),
bucla de invatare din tier3 (L3: doar etichete umane; umbra, control, drift; retrogradarea imediata)."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from elasticlab.contracts.learning import (ActiveStats, ControllerInput, LabeledBucket, ModelRecord,
                                           ModelState, ShadowStats, Thresholds, ValidationMetrics)
from elasticlab.core import classifier, controller as C, pipelines
from elasticlab.store import models as M
from elasticlab.tier3 import learning as L

NOW = datetime(2026, 11, 27, 12, tzinfo=timezone.utc)
CFG = pipelines.load()
P = pipelines.pipeline_for(CFG, "RCE: Web server spawns shell")
GOOD = ValidationMetrics(n=40, n_attack=20, n_benign=20, closures=19, closures_correct=19, closed_attacks=0,
                         tp=20, fp=1, fn=0, tn=19, precision=0.95, recall=1.0, f1=0.97)


def rec(h, state, since=NOW - timedelta(days=8), val=GOOD, ever=False):
    return ModelRecord(pipeline=P.id, model_hash=h * 64, algorithm="nb-categorical-v1", dp_version=1,
                       trained_at=since, n_train=100, n_validation=40, labels_attack=60, labels_benign=60,
                       validation=val, state=state, state_since=since, ever_active=ever)


def ready(**kw):
    base = dict(pipeline=P.id, now=NOW, labels_attack=60, labels_benign=60, shadow=rec("a", ModelState.SHADOW),
                shadow_stats=ShadowStats(decisions=150, closures=60, contradicted=1, closures_on_attack_buckets=0),
                regression_passed_for_shadow=True, shadow_validation_now=GOOD)
    base.update(kw)
    return ControllerInput(**base)


def moves(ts):
    return [(t.model_hash[0], t.from_state.value, t.to_state.value) for t in ts]


# ---------------- candidat -> umbra ----------------

def test_primul_candidat_intra_in_umbra():
    ts = C.step(ControllerInput(pipeline=P.id, now=NOW, candidate=rec("c", ModelState.CANDIDATE)))
    assert moves(ts) == [("c", "candidate", "shadow")]


def test_candidatul_inlocuieste_umbra_doar_daca_nu_scade_si_etichetele_s_au_schimbat():
    sh = rec("a", ModelState.SHADOW)
    better = rec("c", ModelState.CANDIDATE)
    ts = C.step(ControllerInput(pipeline=P.id, now=NOW, candidate=better, shadow=sh,
                                labels_changed_since_shadow=C.MIN_LABEL_CHANGE, shadow_validation_now=GOOD))
    assert moves(ts) == [("a", "shadow", "retired"), ("c", "candidate", "shadow")]
    # prea putine etichete noi: umbra ramane (ceasul de 7 zile nu se reporneste orar)
    assert C.step(ControllerInput(pipeline=P.id, now=NOW, candidate=better, shadow=sh,
                                  labels_changed_since_shadow=C.MIN_LABEL_CHANGE - 1)) == []
    # metrici mai proaste: umbra ramane
    worse = rec("c", ModelState.CANDIDATE, val=GOOD.model_copy(update={"closed_attacks": 1}))
    assert C.step(ControllerInput(pipeline=P.id, now=NOW, candidate=worse, shadow=sh,
                                  labels_changed_since_shadow=50, shadow_validation_now=GOOD)) == []
    worse2 = rec("c", ModelState.CANDIDATE, val=GOOD.model_copy(update={"recall": 0.9}))
    assert C.step(ControllerInput(pipeline=P.id, now=NOW, candidate=worse2, shadow=sh,
                                  labels_changed_since_shadow=50, shadow_validation_now=GOOD)) == []


def test_candidat_identic_cu_umbra_sau_activul_nu_misca_nimic():
    sh = rec("a", ModelState.SHADOW)
    same = rec("a", ModelState.CANDIDATE)
    assert C.step(ControllerInput(pipeline=P.id, now=NOW, candidate=same, shadow=sh,
                                  labels_changed_since_shadow=99, regression_passed_for_shadow=False)) == []


# ---------------- umbra -> activ ----------------

def test_umbra_devine_activa_cand_toate_conditiile_sunt_adevarate():
    assert C.activation_blockers(ready()) == []
    assert moves(C.step(ready())) == [("a", "shadow", "active")]


def test_activarea_retrage_vechiul_activ():
    ts = C.step(ready(active=rec("b", ModelState.ACTIVE, ever=True)))
    assert moves(ts) == [("b", "active", "retired"), ("a", "shadow", "active")]


@pytest.mark.parametrize("change,fragment", [
    ({"labels_attack": 49}, "etichete"),
    ({"labels_benign": 49}, "etichete"),
    ({"shadow_validation_now": GOOD.model_copy(update={"closed_attacks": 1})}, "inchide 1 atacuri"),
    ({"shadow_validation_now": GOOD.model_copy(update={"closures": 20, "closures_correct": 18})}, "precizia"),
    ({"shadow_validation_now": GOOD.model_copy(update={"closures": 0, "closures_correct": 0})}, "precizia"),
    ({"shadow": rec("a", ModelState.SHADOW, since=NOW - timedelta(days=6, hours=23))}, "zile"),
    ({"shadow_stats": ShadowStats(decisions=99, closures=10)}, "decizii"),
    ({"shadow_stats": ShadowStats(decisions=150, closures=50, contradicted=2)}, "contrazise"),
    ({"shadow_stats": ShadowStats(decisions=150, closures=60, closures_on_attack_buckets=1)}, "grupuri etichetate attack"),
    ({"regression_passed_for_shadow": False}, "regresie"),
])
def test_fiecare_conditie_de_activare_blocheaza_singura(change, fragment):
    inp = ready(**change)
    bl = C.activation_blockers(inp)
    assert len(bl) == 1 and fragment in bl[0], bl
    assert C.step(inp) == []


def test_contrazise_exact_2_la_suta_e_permis():
    assert C.activation_blockers(ready(shadow_stats=ShadowStats(decisions=150, closures=100, contradicted=2))) == []


# ---------------- activ -> umbra ----------------

@pytest.mark.parametrize("stats,fragment", [
    (ActiveStats(human_attack_on_closed_bucket=True), "etichetat attack"),
    (ActiveStats(control_labeled=20, control_disagreements=2), "esantionul de control"),
    (ActiveStats(new_bucket_rate=0.31), "grupuri noi"),
    (ActiveStats(outlier_rate=0.5), "outlieri"),
    (ActiveStats(hash_mismatch=True), "hash"),
])
def test_retrogradarea_imediata_la_fiecare_declansator(stats, fragment):
    act = rec("b", ModelState.ACTIVE, ever=True)
    ts = C.step(ControllerInput(pipeline=P.id, now=NOW, active=act, active_stats=stats,
                                shadow=rec("a", ModelState.SHADOW), candidate=rec("c", ModelState.CANDIDATE)))
    assert moves(ts) == [("a", "shadow", "retired"), ("b", "active", "shadow")]
    assert fragment in ts[-1].reason
    assert all(t.actor == "controller" for t in ts)


def test_sub_praguri_activul_ramane():
    act = rec("b", ModelState.ACTIVE, ever=True)
    ok = ActiveStats(control_labeled=100, control_disagreements=5, new_bucket_rate=0.3, outlier_rate=0.3)
    assert C.step(ControllerInput(pipeline=P.id, now=NOW, active=act, active_stats=ok)) == []


# ---------------- registrul ----------------

def samples(n=60):
    import random
    rnd = random.Random(3)
    out = []
    for i in range(n):
        v = {d: "x" for d in P.decision_points}
        v["user_class"] = rnd.choice(["web_service", "known_admin", "root"])
        v["process_class"] = rnd.choice(["shell", "package_tool", "system"])
        lab = "attack" if "web_service" == v["user_class"] or v["process_class"] == "shell" else "benign"
        from elasticlab.core.buckets import bucket_key
        k = bucket_key(P.id, 1, {**v, "rule": f"r{i % 2}", "exec_location": rnd.choice(["temp", "other", "home"])})
        out.append(LabeledBucket(bucket_id=k.bucket_id, values=k.values, label=lab, first_seen=NOW,
                                 last_seen=NOW + timedelta(minutes=i)))
    return list({s.bucket_id: s for s in out}.values())


def test_artefactul_se_salveaza_cu_hash_si_nepotrivirea_e_detectata(tmp_path):
    art = classifier.train(P.id, 1, P.decision_points, samples(), P.thresholds)
    h = M.save_artifact(tmp_path, art)
    assert M.load_artifact(tmp_path, P.id, h) == art
    p = M.artifact_path(tmp_path, P.id, h)
    data = json.loads(p.read_text())
    data["class_counts"]["attack"] += 1                    # cineva modifica fisierul
    p.write_text(json.dumps(data))
    with pytest.raises(M.HashMismatch):
        M.load_artifact(tmp_path, P.id, h)


def test_istoric_si_revenire_la_o_versiune_anterioara(tmp_path):
    m = M.empty_manifest()
    hashes = []
    for i, n in enumerate((40, 50)):
        art = classifier.train(P.id, 1, P.decision_points, samples(n), P.thresholds)
        h = M.save_artifact(tmp_path, art)
        hashes.append(h)
        M.upsert(m, ModelRecord(pipeline=P.id, model_hash=h, algorithm="nb-categorical-v1", dp_version=1,
                                trained_at=NOW + timedelta(hours=i), n_train=n, n_validation=0,
                                labels_attack=1, labels_benign=1, validation=ValidationMetrics(),
                                state=ModelState.RETIRED if i == 0 else ModelState.ACTIVE,
                                state_since=NOW, ever_active=True))
    ts = M.rollback(tmp_path, m, P.id, hashes[0], NOW + timedelta(days=1))
    assert [(t.model_hash, t.to_state.value, t.actor) for t in ts] == [
        (hashes[1], "shadow", "human"), (hashes[0], "active", "human")]
    assert M.in_state(m, P.id, ModelState.ACTIVE).model_hash == hashes[0]
    M.save_manifest(tmp_path, m)
    assert len(L.history(P.id, tmp_path)) == 2
    with pytest.raises(ValueError):          # niciodata activ -> fara revenire
        m2 = M.empty_manifest()
        M.upsert(m2, M.find(m, P.id, hashes[0]).model_copy(update={"ever_active": False}))
        M.rollback(tmp_path, m2, P.id, hashes[0], NOW)


def test_regresia_conteaza_doar_pentru_acelasi_model_si_set_de_prompturi():
    m = M.empty_manifest()
    M.record_regression(m, pipeline=P.id, model_hash="a" * 64, prompt_set="p1", passed=True, at=NOW, details={})
    assert M.last_regression(m, P.id, "a" * 64, "p1")["passed"]
    assert M.last_regression(m, P.id, "a" * 64, "p2") is None
    assert M.last_regression(m, P.id, "b" * 64, "p1") is None


def test_regresia_pe_setul_de_aur_trece_doar_fara_atac_ratat_sau_inchis():
    llm = [{"ground_truth": "attack", "flagged": True}, {"ground_truth": "benign", "flagged": False}]
    assert L.gold_verdict(llm, [{"ground_truth": "attack", "would_close": False}])[0]
    assert not L.gold_verdict(llm, [{"ground_truth": "attack", "would_close": True}])[0]
    assert not L.gold_verdict([{"ground_truth": "attack", "flagged": False}], [])[0]
    assert not L.gold_verdict([], [])[0]


def test_sonda_llm():
    class ES:
        def __init__(self, doc):
            self.doc = doc

        def search(self, **k):
            return {"hits": {"hits": [{"_source": self.doc}] if self.doc else []}}
    ok = {"@timestamp": (NOW - timedelta(minutes=2)).isoformat(), "ok": True, "consecutive_failures": 0}
    assert L.probe_healthy(ES(ok), NOW)[0]
    assert not L.probe_healthy(ES({**ok, "ok": False}), NOW)[0]
    assert not L.probe_healthy(ES({**ok, "@timestamp": (NOW - timedelta(hours=1)).isoformat()}), NOW)[0]
    assert not L.probe_healthy(ES(None), NOW)[0]


# ---------------- statistici (pure) ----------------

def row(h, would, cls, bid="b" + "1" * 24, control=False, ts=NOW, outlier=False, gt=None):
    return {"@timestamp": ts.isoformat(), "classification": cls, "ground_truth": gt,
            "cascade": {"model_hash": h, "would_close": would, "bucket_id": bid, "control_sample": control,
                        "outlier": outlier, "step": "model"}}


def test_statisticile_umbrei():
    h = "a" * 64
    rows = [row(h, True, "benign"), row(h, True, "malicious"), row(h, False, "suspicious"),
            row("b" * 64, True, "malicious"), row(h, True, "benign", bid="b" + "2" * 24)]
    st = L.shadow_stats(rows, {"b" + "2" * 24: {"consensus": "attack"}}, h)
    assert st == ShadowStats(decisions=4, closures=3, contradicted=1, closures_on_attack_buckets=1)


def test_statisticile_activului_control_si_drift():
    act = rec("b", ModelState.ACTIVE, since=NOW - timedelta(days=2))
    ctrl = [row("b" * 64, True, "benign", control=True, gt="attack"),
            row("b" * 64, True, "benign", control=True, bid="b" + "3" * 24),
            row("b" * 64, True, "benign", control=True, bid="b" + "4" * 24)]
    bdocs = {"b" + "3" * 24: {"consensus": "benign"},
             "b" + "5" * 24: {"last_closed_at": (NOW - timedelta(days=1)).isoformat(), "votes_attack": 1}}
    rows24 = [row("b" * 64, False, "benign", outlier=(i < 10)) for i in range(25)]
    st = L.active_stats(ctrl, rows24, bdocs, act, new_buckets_24h=5, hash_ok=True)
    assert st.control_labeled == 2 and st.control_disagreements == 1
    assert st.human_attack_on_closed_bucket
    assert st.new_bucket_rate == 0.2 and st.outlier_rate == 0.4 and not st.hash_mismatch
    # inchiderea veche (inainte de activare) nu declanseaza
    bdocs2 = {"b" + "5" * 24: {"last_closed_at": (NOW - timedelta(days=5)).isoformat(), "votes_attack": 1}}
    assert not L.active_stats([], [], bdocs2, act, 0, True).human_attack_on_closed_bucket
    assert L.active_stats([], rows24[:5], {}, act, 5, True).new_bucket_rate is None   # volum prea mic


def test_etichetele_schimbate_fata_de_model():
    s = samples()
    art = classifier.train(P.id, 1, P.decision_points, s, P.thresholds)
    assert L.labels_changed(art, s) == 0
    flipped = [s[0].model_copy(update={"label": "benign" if s[0].label == "attack" else "attack"})] + s[1:]
    assert L.labels_changed(art, flipped) == 1
    assert L.labels_changed(art, s[1:]) == 1
    assert L.labels_changed(None, s) == len(s)


# ---------------- bucla completa pe un ES fals (L3) ----------------

class FakeES:
    """soc-buckets + verdicts-history in memorie; suficient pentru learning.run."""

    def __init__(self, buckets, verdicts=()):
        self.buckets = {b["bucket_id"]: b for b in buckets}
        self.verdicts = list(verdicts)
        self.indexed = []

    def search(self, index, query=None, size=10, **k):
        if index == "soc-buckets":
            docs = list(self.buckets.values())
            flt = (query or {}).get("bool", {}).get("filter", [])
            for f in flt:
                if "terms" in f and "consensus" in f["terms"]:
                    docs = [d for d in docs if d.get("consensus") in f["terms"]["consensus"]]
                if "term" in f and "pipeline" in f["term"]:
                    docs = [d for d in docs if d.get("pipeline") == f["term"]["pipeline"]]
                if "exists" in f:
                    docs = [d for d in docs if d.get(f["exists"]["field"])]
            if "terms" in (query or {}):
                ids = set(query["terms"]["bucket_id"])
                docs = [d for d in docs if d["bucket_id"] in ids]
            return {"hits": {"hits": [{"_source": d} for d in docs[:size]]}}
        if index == "verdicts-history":
            pid = query["bool"]["filter"][0]["term"]["cascade.pipeline"]
            return {"hits": {"hits": [{"_source": v} for v in self.verdicts
                                      if (v.get("cascade") or {}).get("pipeline") == pid]}}
        raise AssertionError(index)

    def count(self, index, query):
        return {"count": 0}

    def index(self, **k):
        self.indexed.append(k)


def bucket_docs(sams, extra=()):
    out = [{"bucket_id": s.bucket_id, "pipeline": P.id, "dp_version": 1, "values": s.values,
            "consensus": s.label, "first_seen": s.first_seen.isoformat(), "last_seen": s.last_seen.isoformat(),
            "count": 3} for s in sams]
    return out + list(extra)


def test_L3_antrenarea_foloseste_doar_consensul_uman(tmp_path):
    s = samples()
    # grupuri fara consens / la egalitate, dar cu decizia sistemului: NU intra la antrenare
    noise = [{"bucket_id": "b" + f"{i:024x}", "pipeline": P.id, "dp_version": 1,
              "values": {d: "zzz" for d in P.decision_points}, "consensus": c,
              "first_seen": NOW.isoformat(), "last_seen": NOW.isoformat(), "count": 99,
              "system": {"decision": "benign", "would_close": True}}
             for i, c in enumerate(("none", "tie", "none"))]
    es = FakeES(bucket_docs(s, noise),
                verdicts=[{"@timestamp": NOW.isoformat(), "classification": "benign",
                           "cascade": {"pipeline": P.id, "applied": True}}])
    eff = L.Effects(tmp_path, write=True)
    rep = L.run(write=True, es=es, root=tmp_path, effects=eff, now=NOW, only=P.id)[0]
    assert "error" not in rep, rep
    m = M.load_manifest(tmp_path)
    r = M.records(m, P.id)[0]
    art = M.load_artifact(tmp_path, P.id, r.model_hash)
    trained_ids = {bid for bid, _row, _lab in art["labeled"]}
    assert trained_ids <= {x.bucket_id for x in s}
    assert not any(v == "zzz" for d in art["feature_counts"].values() for v in d)
    # primul candidat intra direct in umbra; tranzitia are document si audit
    assert r.state is ModelState.SHADOW
    kinds = [d["type"] for d in eff.sent]
    assert "cascade_transition" in kinds and "cascade_metrics" in kinds
    assert (tmp_path / "audit.jsonl").read_text().count("cascade_transition") == 1
    # a doua rulare pe aceleasi etichete: acelasi hash, nicio tranzitie noua
    rep2 = L.run(write=True, es=es, root=tmp_path, effects=L.Effects(tmp_path, write=True), now=NOW, only=P.id)[0]
    assert rep2["transitions"] == [] and rep2.get("candidate") == r.model_hash


def test_fara_scrie_nu_se_schimba_nimic(tmp_path):
    es = FakeES(bucket_docs(samples()))
    L.run(write=False, es=es, root=tmp_path, effects=L.Effects(tmp_path, write=False), now=NOW, only=P.id)
    assert not (tmp_path / "MANIFEST.json").exists() and not list(tmp_path.glob("*/*.json"))


def test_retrogradarea_imediata_la_votul_attack(tmp_path):
    m = M.empty_manifest()
    art = classifier.train(P.id, 1, P.decision_points, samples(), P.thresholds)
    h = M.save_artifact(tmp_path, art)
    M.upsert(m, rec("a", ModelState.ACTIVE, since=NOW - timedelta(days=1), ever=True).model_copy(
        update={"model_hash": h}))
    M.save_manifest(tmp_path, m)
    eff = L.Effects(tmp_path, write=True)
    doc = {"last_closed_at": (NOW - timedelta(hours=1)).isoformat()}
    assert L.on_human_label(P.id, doc, "benign", now=NOW, root=tmp_path, effects=eff) == []
    ts = L.on_human_label(P.id, doc, "attack", now=NOW, root=tmp_path, effects=eff)
    assert [(t.from_state.value, t.to_state.value) for t in ts] == [("active", "shadow")]
    assert M.in_state(M.load_manifest(tmp_path), P.id, ModelState.ACTIVE) is None
    # grup inchis inainte de activare: nimic
    assert L.on_human_label(P.id, {"last_closed_at": (NOW - timedelta(days=9)).isoformat()}, "attack",
                            now=NOW, root=tmp_path, effects=eff) == []


def test_thresholds_implicite_sunt_cele_din_sarcina():
    th = Thresholds()
    assert th.control_sample_pct == 10 and th.max_control_disagreement == 0.05
    assert (C.MIN_LABELS_PER_CLASS, C.MIN_CLOSURE_PRECISION, C.MIN_SHADOW_DAYS, C.MIN_SHADOW_DECISIONS,
            C.MAX_CONTRADICTED) == (50, 0.95, 7, 100, 0.02)

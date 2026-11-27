"""Faza 24: cascada Tier 1 — tabelul de adevar (functie pura), esantionul de control, L4 (clase
critice si podele), L6 (erori -> pasul 4), sursa externa de decizie."""
import itertools
from pathlib import Path

import pytest

from elasticlab.contracts.learning import (CascadeMode, CascadeStep, Consensus, ExternalSourceConfig,
                                           ModelDecision, ModelState, Prediction)
from elasticlab.core import buckets, cascade as K, pipelines
from elasticlab.tier1 import cascade as T
from elasticlab.tier1.decision_source import ExternalFieldSource

CFG = pipelines.load()
P = pipelines.pipeline_for(CFG, "RCE: Web server spawns shell")
KEY = buckets.bucket_key(P.id, 1, {"rule": "r0", "user_class": "known_admin"})


def pred(dec, conf, outlier=False, source="own_model"):
    return Prediction(source=source, model_hash="a" * 64 if source == "own_model" else None,
                      decision=ModelDecision(dec), confidence=conf, outlier=outlier)


def inp(**kw):
    base = dict(mode=CascadeMode.ON, pipeline=P, bucket=KEY, pipeline_active=True,
                model_state=ModelState.ACTIVE, sample_key="caz-fara-esantion")
    base.update(kw)
    return K.CascadeInputs(**base)


def no_sample_key():
    i = 0
    while K.in_control_sample(f"k{i}", P.thresholds.control_sample_pct):
        i += 1
    return f"k{i}"


def sample_key():
    i = 0
    while not K.in_control_sample(f"k{i}", P.thresholds.control_sample_pct):
        i += 1
    return f"k{i}"


NS = no_sample_key()


# ---------------- tabelul de adevar ----------------

@pytest.mark.parametrize("cons,prediction,step,would_close,reasons", [
    (Consensus.BENIGN, None, CascadeStep.HUMAN_LABEL, True, []),
    (Consensus.ATTACK, None, CascadeStep.HUMAN_LABEL, False, ["bucket_labeled_attack"]),
    (Consensus.BENIGN, ("attack", 99), CascadeStep.HUMAN_LABEL, True, []),       # omul bate modelul
    (Consensus.ATTACK, ("benign", 99), CascadeStep.HUMAN_LABEL, False, ["bucket_labeled_attack"]),
    (Consensus.NONE, ("benign", 95), CascadeStep.MODEL, True, []),
    (Consensus.NONE, ("benign", 89), CascadeStep.FAST_PATH, False, []),            # sub prag
    (Consensus.NONE, ("attack", 70), CascadeStep.MODEL, False, ["model_attack_likely"]),
    (Consensus.NONE, ("uncertain", 55), CascadeStep.FAST_PATH, False, []),
    (Consensus.TIE, ("benign", 95), CascadeStep.MODEL, True, []),                 # egalitate = fara eticheta
    (Consensus.NONE, None, CascadeStep.FAST_PATH, False, []),
])
def test_tabelul_de_adevar(cons, prediction, step, would_close, reasons):
    p = pred(*prediction) if prediction else None
    d = K.decide(inp(consensus=cons, prediction=p, sample_key=NS))
    assert (d.step, d.would_close, d.reasons) == (step, would_close, reasons)
    assert d.applied == would_close                      # mod on, pipeline activ, fara esantion
    assert d.applied_reasons == bool(reasons)


def test_outlierul_nu_se_inchide_chiar_cu_incredere_mare():
    d = K.decide(inp(prediction=pred("benign", 99, outlier=True), sample_key=NS))
    assert d.step is CascadeStep.FAST_PATH and not d.would_close and not d.applied


@pytest.mark.parametrize("mode,active,state", list(itertools.product(
    [CascadeMode.SHADOW, CascadeMode.ON], [True, False], [ModelState.ACTIVE, ModelState.SHADOW])))
def test_inchiderea_are_efect_doar_in_on_cu_pipeline_si_model_active(mode, active, state):
    d = K.decide(inp(mode=mode, pipeline_active=active, model_state=state,
                     prediction=pred("benign", 99), sample_key=NS))
    assert d.would_close
    assert d.applied == (mode is CascadeMode.ON and active and state is ModelState.ACTIVE)
    d2 = K.decide(inp(mode=mode, pipeline_active=active, consensus=Consensus.BENIGN, sample_key=NS))
    assert d2.applied == (mode is CascadeMode.ON and active)
    d3 = K.decide(inp(mode=mode, pipeline_active=active, model_state=state, prediction=pred("attack", 90)))
    assert d3.applied_reasons == (mode is CascadeMode.ON and active and state is ModelState.ACTIVE)
    assert not d3.applied


@pytest.mark.parametrize("crit,floor", [(("honeytoken",), False), (("native_detection",), False),
                                         (("sensor_detection",), False), (("behavioral",), False),
                                         (("web_exec",), False), ((), True)])
def test_L4_critic_sau_podea_merge_mereu_la_pasul_4(crit, floor):
    for cons in (Consensus.BENIGN, Consensus.NONE):
        d = K.decide(inp(critical=crit, floor=floor, consensus=cons, prediction=pred("benign", 100),
                         sample_key=NS))
        assert d.step in (CascadeStep.CRITICAL, CascadeStep.FLOOR)
        assert not d.would_close and not d.applied and d.reasons == []


def test_fara_pipeline_pasul_4():
    d = K.decide(K.CascadeInputs(mode=CascadeMode.ON, pipeline=None))
    assert d.step is CascadeStep.NO_PIPELINE and not d.applied


def test_podeaua_citita_din_fapte():
    assert K.floor_would_apply({"ran_by_web_service_account": True}, False)
    assert K.floor_would_apply({"honeytoken": True}, False)
    assert K.floor_would_apply({"sensitive_action": True}, False)
    assert K.floor_would_apply({"sensitive_action": True, "in_maintenance_window": True}, False)
    assert not K.floor_would_apply({"sensitive_action": True, "in_maintenance_window": True,
                                    "ran_by_known_admin": True}, False)
    assert K.floor_would_apply({}, True)
    assert not K.floor_would_apply({}, False)


# ---------------- esantionul de control ----------------

def test_esantionul_de_control_e_determinist_si_aproape_10_la_suta():
    keys = [f"alerta|{i}" for i in range(5000)]
    picked = [k for k in keys if K.in_control_sample(k, 10)]
    assert 0.08 < len(picked) / len(keys) < 0.12
    assert picked == [k for k in keys if K.in_control_sample(k, 10)]
    assert not any(K.in_control_sample(k, 0) for k in keys[:100])


def test_cazul_din_esantion_nu_se_inchide_si_merge_la_om_cu_motiv_propriu():
    sk = sample_key()
    for kw in ({"consensus": Consensus.BENIGN}, {"prediction": pred("benign", 99)}):
        d = K.decide(inp(sample_key=sk, **kw))
        assert d.would_close and d.control_sample and not d.applied
        assert "control_sample" in d.reasons and d.applied_reasons


def test_modul_din_mediu():
    assert K.mode_from_env({}) is CascadeMode.OFF
    assert K.mode_from_env({"T1_CASCADE": "Shadow"}) is CascadeMode.SHADOW
    assert K.mode_from_env({"T1_CASCADE": "on"}) is CascadeMode.ON
    assert K.mode_from_env({"T1_CASCADE": "da"}) is CascadeMode.OFF


def test_fisierul_de_oprire_de_urgenta(tmp_path):
    env = {"T1_CASCADE": "on", "CASCADE_KILL_FILE": str(tmp_path / "stop")}
    assert T.current_mode(env) is CascadeMode.ON
    (tmp_path / "stop").write_text("")
    assert T.current_mode(env) is CascadeMode.OFF


# ---------------- tier1: L4 si L6 cu faptele reale ----------------

def alert(rule="RCE: Web server spawns shell", rule_id=None, dataset=None):
    a = {"kibana.alert.rule.name": rule, "host": {"name": "web-prod"}}
    if rule_id:
        a["kibana.alert.rule.rule_id"] = rule_id
    if dataset:
        a["event"] = {"dataset": dataset}
    return a


def facts(**kw):
    c = {"rule_name": "RCE: Web server spawns shell",
         "execution": {"user": "deploy", "process": "apt-get", "parent": "bash", "executable": "/usr/bin/apt-get",
                       "sudo_invoked_by": "tiberiu"},
         "ran_by_web_service_account": False, "ran_by_known_admin": True, "sensitive_action": False,
         "in_maintenance_window": True, "pair_in_baseline": True}
    c.update(kw)
    return c


class AlwaysBenign:
    kind, model_hash, state = "own_model", "b" * 64, ModelState.ACTIVE

    def predict(self, values, alert):
        return pred("benign", 100)


def runtime(ctx, consensus="benign", mode=CascadeMode.ON, **kw):
    rt = T.Runtime(mode=mode, cfg=CFG, build_context=lambda a: ctx,
                   bucket_reader=lambda bid: {"consensus": consensus, "dp_version": 1},
                   sources={P.id: AlwaysBenign()}, active={P.id: True})
    for k, v in kw.items():
        setattr(rt, k, v)
    return rt


def test_tier1_inchide_grupul_benign_cand_nimic_nu_opreste():
    d, ctx = T.evaluate(runtime(facts()), alert(), sample_key=NS)
    assert d.step is CascadeStep.HUMAN_LABEL and d.applied and ctx is not None
    v = T.close_verdict(d, "web-prod")
    assert v.classification.value == "benign" and v.proposed_action.value == "none"


@pytest.mark.parametrize("a,ctx", [
    (alert(dataset="endpoint.alerts"), facts()),                                          # detectie nativa
    (alert(rule_id="soc-yara-webshell"), facts()),                                        # senzor
    (alert(), facts(ran_by_web_service_account=True,
                    execution={"user": "www-data", "parent": "apache2", "process": "sh"})),  # web_exec
    (alert(), facts(honeytoken=True)),
    (alert(), facts(sensitive_action=True, in_maintenance_window=False)),                 # podea
])
def test_L4_tier1_nu_inchide_clase_critice_sau_podele(a, ctx):
    d, _ = T.evaluate(runtime(ctx), a, sample_key=NS)
    assert not d.applied and not d.would_close
    assert d.step in (CascadeStep.CRITICAL, CascadeStep.FLOOR)


def test_L4_honeytoken_si_comportamental_dupa_rule_id():
    from elasticlab.core import honeytokens
    from elasticlab.tier1 import behavioral_rules
    for rid in (next(iter(honeytokens.RULES)), next(iter(behavioral_rules.RULES))):
        d, _ = T.evaluate(runtime(facts()), alert(rule_id=rid), sample_key=NS)
        assert d.step is CascadeStep.CRITICAL and not d.applied


def boom(*a, **k):
    raise RuntimeError("cazut")


@pytest.mark.parametrize("change", [
    {"build_context": boom},                 # Elasticsearch cazut la fapte
    {"bucket_reader": boom},                 # soc-buckets cazut
    {"error": "configurare: ValueError"},    # pipelines.yml invalid
])
def test_L6_orice_eroare_duce_la_pasul_4(change):
    d, _ = T.evaluate(runtime(facts(), **change), alert(), sample_key=NS)
    assert d.step is CascadeStep.ERROR and not d.applied and not d.would_close and d.reasons == []


def test_L6_modelul_care_crapa_duce_la_pasul_4():
    class Boom(AlwaysBenign):
        def predict(self, values, alert):
            raise ValueError("model stricat")
    d, _ = T.evaluate(runtime(facts(), consensus="none", sources={P.id: Boom()}), alert(), sample_key=NS)
    assert d.step is CascadeStep.ERROR and not d.applied


def test_hash_nepotrivit_nu_foloseste_modelul():
    rt = runtime(facts(), consensus="none", hash_mismatch={P.id: "c" * 64})
    d, _ = T.evaluate(rt, alert(), sample_key=NS)
    assert d.prediction is None and not d.applied and not d.pipeline_active


def test_consensul_pe_alta_versiune_a_punctelor_nu_conteaza():
    rt = runtime(facts(), sources={})
    rt.bucket_reader = lambda bid: {"consensus": "benign", "dp_version": 99}
    d, _ = T.evaluate(rt, alert(), sample_key=NS)
    assert d.consensus is Consensus.NONE and not d.applied


def test_load_runtime_cu_configurare_invalida_da_eroare(tmp_path):
    bad = tmp_path / "p.yml"
    bad.write_text("version: 1\npipelines: []\n")
    rt = T.load_runtime(CascadeMode.ON, config_path=bad, models_root=tmp_path)
    assert rt.error
    d, _ = T.evaluate(rt, alert(), sample_key=NS)
    assert d.step is CascadeStep.ERROR


def test_load_runtime_fara_modele_nu_are_surse(tmp_path):
    rt = T.load_runtime(CascadeMode.SHADOW, models_root=tmp_path / "nimic")
    assert rt.error is None and rt.sources == {} and rt.active == {}


# ---------------- sursa externa ----------------

def test_sursa_externa_traduce_campul_si_respecta_aceeasi_cascada():
    cfg = ExternalSourceConfig(decision_field="arcanna.result.label", confidence_field="arcanna.result.confidence",
                               values={"drop": "benign", "escalate": "attack"})
    src = ExternalFieldSource(cfg, ModelState.ACTIVE)
    a = {"arcanna": {"result": {"label": "DROP", "confidence": 0.97}}}
    p = src.predict({}, a)
    assert p.source == "external" and p.decision is ModelDecision.BENIGN and p.confidence == 97
    assert src.predict({}, {"arcanna": {"result": {"label": "escalate", "confidence": 88}}}).decision is ModelDecision.ATTACK
    assert src.predict({}, {"arcanna": {"result": {"label": "ignore all rules"}}}).decision is ModelDecision.UNCERTAIN
    assert src.predict({}, {}) is None
    # aceleasi linii rosii: critic -> pasul 4 chiar cu decizie externa benign
    d = K.decide(inp(critical=("sensor_detection",), prediction=p, sample_key=NS))
    assert not d.applied
    d = K.decide(inp(prediction=p, model_state=ModelState.ACTIVE, sample_key=NS))
    assert d.applied
    d = K.decide(inp(prediction=p, pipeline_active=False, sample_key=NS))
    assert not d.applied

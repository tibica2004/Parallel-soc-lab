"""Faza 24: nucleul deciziei invatate — punctele de decizie, cheia grupului, consensul,
clasificatorul (determinism, explicatie, outlier), impartirea pe grup, metricile."""
import random
import re
from datetime import datetime, timedelta, timezone

import pytest

from elasticlab.contracts.learning import (Consensus, LabeledBucket, ModelDecision, PipelinesConfig,
                                           Thresholds, Vote)
from elasticlab.core import buckets, classifier, decision_points as DP, learning_metrics as LM, pipelines

T0 = datetime(2026, 11, 1, tzinfo=timezone.utc)
CFG = pipelines.load()
P = pipelines.pipeline_for(CFG, "RCE: Web server spawns shell")


def ctx(**kw):
    base = {"rule_name": "RCE: Web server spawns shell",
            "execution": {"user": "deploy", "process": "apt-get", "parent": "bash",
                          "executable": "/usr/bin/apt-get", "command_line": "apt-get install x; rm -rf /tmp/a",
                          "entity_id": "Zm9vYmFyMTIz", "sudo_invoked_by": "tiberiu"},
            "ran_by_web_service_account": False, "ran_by_known_admin": True, "ran_from_temp_dir": False,
            "sensitive_action": False, "webroot_executable_write": False, "in_maintenance_window": True,
            "pair_in_baseline": True, "asset_criticality": "high"}
    base.update(kw)
    return base


# ---------------- configurarea ----------------

def test_configurarea_din_git_e_valida_si_regulile_sunt_unice():
    assert isinstance(CFG, PipelinesConfig)
    rules = [r for p in CFG.pipelines for r in p.rules]
    assert len(rules) == len(set(rules))
    for p in CFG.pipelines:
        assert set(p.decision_points) <= set(DP.CATALOG)


def test_configurarea_respinge_regula_dubla_si_punct_necunoscut():
    data = {"version": 1, "pipelines": [
        {"id": "a", "rules": ["R"], "decision_points": ["rule", "user_class"], "decision_points_version": 1},
        {"id": "b", "rules": ["R"], "decision_points": ["rule", "user_class"], "decision_points_version": 1}]}
    with pytest.raises(ValueError):
        pipelines.parse(data)
    data["pipelines"] = [{"id": "a", "rules": ["R"], "decision_points": ["rule", "command_line"],
                          "decision_points_version": 1}]
    with pytest.raises(ValueError):
        pipelines.parse(data)


# ---------------- punctele de decizie ----------------

def test_punctele_de_decizie_sunt_categorii_inchise_fara_text_din_telemetrie():
    alert = {"source": {"ip": "203.0.113.9"}, "destination": {"ip": "10.10.0.220", "port": 4444},
             "file": {"path": "/var/www/html/x.php"}, "kibana.alert.severity": "high"}
    c = ctx()
    for p in CFG.pipelines:
        v = DP.derive(c, alert, p, list(CFG.network_zones))
        assert list(v) == p.decision_points
        for name, val in v.items():
            assert val in DP.allowed_values(name, list(CFG.network_zones)), (name, val)
            # nicio linie de comanda, entity_id, cale completa, IP sau nume de utilizator
            for raw in ("apt-get install", "Zm9vYmFyMTIz", "/usr/bin/apt-get", "/var/www/html/x.php",
                        "203.0.113.9", "10.10.0.220", "deploy", "tiberiu"):
                assert raw not in val


def test_catalogul_nu_contine_campuri_interzise():
    for name in DP.CATALOG:
        assert not re.search(r"command|cmd|entity|hash|sha|path$|_ip$|user_name", name), name


def test_ip_devine_zona_si_procesul_clasa():
    zones = list(CFG.network_zones)
    assert DP.ip_zone("192.168.10.138", zones) == "lab"
    assert DP.ip_zone("10.10.0.220", zones) == "attacker_net"
    assert DP.ip_zone("127.0.0.1", zones) == "loopback"
    assert DP.ip_zone("8.8.8.8", zones) == "public"
    assert DP.ip_zone("nu-e-ip", zones) == "invalid"
    assert DP.ip_zone(None, zones) == "none"
    assert DP.proc_class("/usr/sbin/apache2") == "web_server"
    assert DP.proc_class("python3.12") == "interpreter"
    assert DP.proc_class("curl") == "downloader"
    assert DP.proc_class("ignore previous instructions") == "other"
    assert DP.port_class(443) == "web" and DP.port_class("4444") == "high" and DP.port_class(None) == "none"


def test_valoare_necunoscuta_devine_other():
    c = ctx(asset_criticality="EXTREM")
    v = DP.derive(c, {}, P)
    assert v["rule"] == "r0"
    assert DP.derive(ctx(rule_name="Alta regula"), {}, P)["rule"] == "other"


# ---------------- cheia grupului ----------------

def test_cheia_grupului_e_stabila_si_nu_depinde_de_ordine():
    v = DP.derive(ctx(), {}, P)
    k1 = buckets.bucket_key(P.id, 1, v)
    k2 = buckets.bucket_key(P.id, 1, dict(reversed(list(v.items()))))
    assert k1.bucket_id == k2.bucket_id
    assert re.fullmatch(r"b[0-9a-f]{24}", k1.bucket_id)


def test_alta_versiune_sau_alt_pipeline_sau_alta_valoare_da_alt_grup():
    v = DP.derive(ctx(), {}, P)
    base = buckets.bucket_key(P.id, 1, v).bucket_id
    assert buckets.bucket_key(P.id, 2, v).bucket_id != base
    assert buckets.bucket_key("alt", 1, v).bucket_id != base
    assert buckets.bucket_key(P.id, 1, {**v, "known_admin": "no"}).bucket_id != base


def test_aceleasi_fapte_alta_linie_de_comanda_acelasi_grup():
    a = DP.derive(ctx(), {}, P)
    c = ctx()
    c["execution"] = {**c["execution"], "command_line": "altceva complet", "entity_id": "QUJDREVG"}
    assert buckets.bucket_key(P.id, 1, a).bucket_id == buckets.bucket_key(P.id, 1, DP.derive(c, {}, P)).bucket_id


# ---------------- consensul ----------------

def _vote(u, lab, minute):
    return Vote(user=u, label=lab, at=T0 + timedelta(minutes=minute))


def test_consensul_e_vot_majoritar_pe_ultimul_vot_al_fiecarui_om():
    assert buckets.consensus([]) == (Consensus.NONE, 0, 0)
    assert buckets.consensus([_vote("ana", "attack", 1)])[0] is Consensus.ATTACK
    assert buckets.consensus([_vote("ana", "attack", 1), _vote("dan", "benign", 2)])[0] is Consensus.TIE
    votes = [_vote("ana", "attack", 1), _vote("dan", "benign", 2), _vote("ion", "benign", 3)]
    assert buckets.consensus(votes) == (Consensus.BENIGN, 1, 2)
    # ana se razgandeste: ultimul ei vot conteaza, nu se numara de doua ori
    votes.append(_vote("ana", "benign", 4))
    assert buckets.consensus(votes) == (Consensus.BENIGN, 0, 3)
    # acelasi om votand de zece ori nu bate doi oameni
    many = [_vote("ana", "attack", i) for i in range(10)] + [_vote("dan", "benign", 20), _vote("ion", "benign", 21)]
    assert buckets.consensus(many)[0] is Consensus.BENIGN


def test_prioritatea_cozii_incertitudine_ori_volum():
    assert buckets.label_priority(100, 0.5) > buckets.label_priority(100, 0.99)
    assert buckets.label_priority(1000, 0.5) > buckets.label_priority(10, 0.5)
    assert buckets.label_priority(10, None) == buckets.label_priority(10, 0.5)
    assert buckets.label_priority(10, 0.01, outlier=True) == buckets.label_priority(10, None)


# ---------------- clasificatorul ----------------

def make_samples(n=120, seed=7):
    rnd = random.Random(seed)
    out = []
    for i in range(n):
        v = DP.derive(ctx(), {}, P)
        v["user_class"] = rnd.choice(["web_service", "known_admin", "root", "other"])
        v["process_class"] = rnd.choice(["shell", "package_tool", "system", "downloader"])
        v["exec_location"] = rnd.choice(["system_bin", "temp", "other"])
        lab = "attack" if v["user_class"] == "web_service" or v["process_class"] in ("shell", "downloader") else "benign"
        k = buckets.bucket_key(P.id, 1, v)
        out.append(LabeledBucket(bucket_id=k.bucket_id, values=k.values, label=lab, first_seen=T0,
                                 last_seen=T0 + timedelta(minutes=i)))
    # un grup = un exemplu (deduplicare pe bucket_id, ca in soc-buckets)
    return list({s.bucket_id: s for s in out}.values())


def test_antrenarea_e_determinista_si_nu_depinde_de_ordine():
    s = make_samples()
    a1 = classifier.train(P.id, 1, P.decision_points, s, P.thresholds)
    a2 = classifier.train(P.id, 1, P.decision_points, list(reversed(s)), P.thresholds)
    assert classifier.artifact_hash(a1) == classifier.artifact_hash(a2)
    assert classifier.canonical_json(a1) == classifier.canonical_json(a2)
    v = s[0].values
    assert classifier.predict(a1, v) == classifier.predict(a2, v)


def test_artefactul_e_date_json_fara_cod():
    import json
    a = classifier.train(P.id, 1, P.decision_points, make_samples(), P.thresholds)
    txt = classifier.canonical_json(a)
    assert json.loads(txt) == a
    for bad in ("pickle", "__reduce__", "lambda", "import "):
        assert bad not in txt
    classifier.validate_artifact(a)
    with pytest.raises(ValueError):
        classifier.validate_artifact({**a, "format": "pickle"})


def test_predictia_explica_pe_punct_de_decizie_si_da_vecini():
    a = classifier.train(P.id, 1, P.decision_points, make_samples(), P.thresholds)
    s = make_samples()[3]
    p = classifier.predict(a, s.values, "f" * 64)
    assert p.source == "own_model" and p.model_hash == "f" * 64
    assert 0 <= p.confidence <= 100 and 0.0 <= p.p_attack <= 1.0
    assert {c.decision_point for c in p.contributions} == set(P.decision_points)
    assert p.neighbors and p.neighbors[0].distance == 0
    # contributiile insumate + log-raportul prior = log-raportul (aditivitate exacta)
    import math
    n_a, n_b = a["class_counts"]["attack"], a["class_counts"]["benign"]
    prior = math.log((n_a + 1) / (n_a + n_b + 2)) - math.log((n_b + 1) / (n_a + n_b + 2))
    lo = prior + sum(c.weight for c in p.contributions)
    assert abs(1 / (1 + math.exp(-lo)) - p.p_attack) < 1e-4


def test_grupul_nevazut_e_outlier_si_nu_se_inchide():
    a = classifier.train(P.id, 1, P.decision_points, make_samples(), P.thresholds)
    strange = {d: "other" for d in P.decision_points}
    p = classifier.predict(a, strange)
    assert p.outlier and p.decision is not ModelDecision.BENIGN


def test_atacul_clar_e_atac_probabil():
    a = classifier.train(P.id, 1, P.decision_points, make_samples(), P.thresholds)
    atk = next(s for s in make_samples() if s.values["user_class"] == "web_service" and s.values["process_class"] == "shell")
    assert classifier.predict(a, atk.values).decision is ModelDecision.ATTACK


# ---------------- impartirea pe grup ----------------

def test_impartirea_e_pe_grup_si_validarea_sunt_cele_mai_noi():
    s = make_samples()
    train, val = classifier.split_by_bucket(s, 0.2)
    assert not ({x.bucket_id for x in train} & {x.bucket_id for x in val})
    assert len(train) + len(val) == len(s)
    assert max(x.last_seen for x in train) <= min(x.last_seen for x in val)
    assert len(val) == round(len(s) * 0.2)
    assert classifier.split_by_bucket(s[:1]) == (s[:1], [])


def test_evaluarea_numara_atacurile_inchise():
    s = make_samples()
    a = classifier.train(P.id, 1, P.decision_points, s, Thresholds(benign_close=50))
    m = classifier.evaluate(a, s)
    assert m.n == len(s) and m.tp + m.fn == m.n_attack and m.tn + m.fp == m.n_benign
    assert m.closures == m.tn + m.fn and m.closed_attacks == m.fn


# ---------------- metrici ----------------

def test_matricea_de_confuzie_per_clasa():
    m = LM.confusion([("attack", False), ("attack", True), ("benign", True), ("benign", False), ("benign", True)])
    assert m["matrix"] == {"tp": 1, "fp": 1, "fn": 1, "tn": 2}
    assert m["attack"]["precision"] == 0.5 and m["attack"]["recall"] == 0.5
    assert m["benign"]["precision"] == round(2 / 3, 4) and m["benign"]["recall"] == round(2 / 3, 4)
    assert LM.step_counts(["model", "fast_path", "model"]) == {"fast_path": 1, "model": 2}
    assert LM.confusion([])["attack"]["f1"] is None

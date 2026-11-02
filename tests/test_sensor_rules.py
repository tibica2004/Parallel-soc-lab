"""Senzori proprii (faza 12): regula YARA in Kibana, faptele din mesajul
scannerului, escaladarea fara podea si scannerul de pe web-prod."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path

import pytest

import fast_path
import orchestrator
import sensor_rules as S
from escalation import should_escalate
from schemas import EscalationReason as R, Verdict
from tests.test_tier1_tier2 import FakeHunt, _alert, rec  # noqa: F401

SHA = "a" * 64
YARA_DIR = Path(__file__).resolve().parents[1] / "deploy" / "web-prod" / "yara"


def Y(msg=None, **kw):
    if msg is None:
        msg = json.dumps({"event": "yara_match", "rule": "soc_php_exec_request_input",
                          "path": "/var/www/html/x.php", "sha256": SHA})
    return _alert(**{"kibana.alert.rule.rule_id": "soc-yara-webshell",
                     "kibana.alert.rule.name": S.RULES["soc-yara-webshell"]["name"],
                     "message": msg, **kw})


def SU(category="Web Application Attack", sig="ET WEB_SPECIFIC_APPS WordPress plugin SQLi", **kw):
    return _alert(**{"kibana.alert.rule.rule_id": S.SURICATA_RULE_ID,
                     "kibana.alert.rule.name": S.RULES[S.SURICATA_RULE_ID]["name"],
                     "rule.name": sig, "rule.category": category,
                     "source.ip": "203.0.113.9", "destination.ip": "172.20.99.240", **kw})


def test_recunoscut_doar_dupa_rule_id():
    assert S.is_sensor_alert(Y())
    assert S.is_sensor_alert(SU())
    assert not S.is_sensor_alert(_alert(**{"kibana.alert.rule.name": "YARA: webshell gasit in webroot"}))


def test_suricata_fapte_valide():
    assert S.suricata_facts(SU()) == {
        "sensor": "suricata", "signature": "ET WEB_SPECIFIC_APPS WordPress plugin SQLi",
        "category": "Web Application Attack", "source_ip": "203.0.113.9",
        "destination_ip": "172.20.99.240"}


@pytest.mark.parametrize("kw", [
    {"rule.category": "Not A Scan"},                 # categorie in afara setului de atac web
    {"source.ip": "nu-e-ip"},                        # source.ip invalid
    {"rule.name": ""},                               # semnatura goala
])
def test_suricata_fapte_invalide(kw):
    assert S.suricata_facts(SU(**kw)) is None


def test_suricata_semnatura_lunga_se_scurteaza():
    assert len(S.suricata_facts(SU(sig="ET " + "A" * 500))["signature"]) == 200


def test_suricata_destinatie_invalida_devine_none():
    assert S.suricata_facts(SU(**{"destination.ip": "x"}))["destination_ip"] is None


def test_sensor_facts_distinge_senzorii():
    assert S.sensor_facts(Y())["sensor"] == "yara"
    assert S.sensor_facts(SU())["sensor"] == "suricata"
    assert S.sensor_facts(_alert()) is None
    # un IP sursa invalid pe o alerta YARA valida nu confunda dispecerul
    assert S.yara_facts(SU()) is None


def test_faptele_din_mesaj():
    assert S.yara_facts(Y()) == {"sensor": "yara", "rule": "soc_php_exec_request_input",
                                 "path": "/var/www/html/x.php", "sha256": SHA}


@pytest.mark.parametrize("msg", [
    "nu e json", json.dumps({"event": "yara_error"}), json.dumps(["x"]),
    json.dumps({"event": "yara_match", "rule": "R; DROP", "path": "/a", "sha256": SHA}),
    json.dumps({"event": "yara_match", "rule": "r", "path": "relativ", "sha256": SHA}),
    json.dumps({"event": "yara_match", "rule": "r", "path": "/a", "sha256": "xyz"}),
])
def test_mesaj_invalid_nu_produce_fapte(msg):
    assert S.yara_facts(Y(msg)) is None


def test_calea_lunga_se_scurteaza():
    msg = json.dumps({"event": "yara_match", "rule": "r", "path": "/" + "a" * 500, "sha256": SHA})
    assert len(S.yara_facts(Y(msg))["path"]) == 200


def test_escaladare_fara_podea():
    v = Verdict(investigation_id="i", source_path="fast", entity_type="host", entity_id="web-prod",
                classification="benign", confidence=99, rarity_score=0.0, model_id="m")
    d = should_escalate(v, floor_applied=False, pair_in_baseline=True, sensor_detection=True)
    assert d.escalate and d.reasons == [R.SENSOR_DETECTION]


def test_contextul_cu_fapte_yara(monkeypatch):
    monkeypatch.setattr(fast_path, "lookup_asset", lambda h: {})
    monkeypatch.setattr(fast_path, "pair_in_baseline", lambda *a: None)
    monkeypatch.setattr(fast_path, "alert_facts", lambda a: {
        "executable": "/usr/local/sbin/soc-yara-scan", "command_line": "", "user": "root",
        "sudo_invoked_by": None, "process": "soc-yara", "parent": "systemd"})
    ctx = fast_path.build_context(Y(), history=False)
    assert ctx["sensor_detection"]["rule"] == "soc_php_exec_request_input"
    assert "scannerul" in ctx["execution"]["note"]
    assert "YARA" in ctx["investigation_guide"]
    assert "sensor_detection" not in fast_path.build_context(_alert(), history=False)


def test_contextul_cu_fapte_suricata(monkeypatch):
    monkeypatch.setattr(fast_path, "lookup_asset", lambda h: {})
    monkeypatch.setattr(fast_path, "pair_in_baseline", lambda *a: None)
    # Alerta Suricata nu are proces: alert_facts intoarce campuri goale, nu None.
    monkeypatch.setattr(fast_path, "alert_facts", lambda a: {
        "executable": "", "command_line": "", "user": "",
        "sudo_invoked_by": None, "process": "", "parent": ""})
    ctx = fast_path.build_context(SU(), history=False)
    assert ctx["sensor_detection"]["sensor"] == "suricata"
    assert ctx["sensor_detection"]["source_ip"] == "203.0.113.9"
    # Suricata e senzor de retea: NU exista nota despre scanner (aia e doar la YARA)
    assert "note" not in ctx["execution"]


def test_payload_suricata():
    p = S.kibana_payload(S.SURICATA_RULE_ID)
    assert p["severity"] == "high" and p["tags"] == [S.TAG]
    assert p["index"] == [S.SURICATA_IDX]
    assert 'event.kind : "alert"' in p["query"] and "Web Application Attack" in p["query"]
    t = p["threat"][0]
    assert t["tactic"]["id"] == "TA0001" and t["technique"][0]["id"] == "T1190"


def test_orchestrator_model_cazut_pastreaza_motivul(rec):
    hunt = FakeHunt()
    orchestrator.process_alerts([Y()], orchestrator.BoundedSeen(), model_ok=False, t2_limit=1, hunt=hunt)
    assert R.SENSOR_DETECTION in hunt.runs[0][0]["case"].escalation_reasons


def test_payload():
    p = S.kibana_payload("soc-yara-webshell")
    assert p["severity"] == "high" and p["tags"] == [S.TAG]
    # ambele surse ale jurnalului: journald (appname) si /var/log/syslog (process.name = eticheta)
    assert '(log.syslog.appname : "soc-yara" or process.name : "soc-yara")' in p["query"]
    t = p["threat"][0]
    assert t["tactic"]["id"] == "TA0003" and t["technique"][0]["subtechnique"][0]["id"] == "T1505.003"


# ---------------- scannerul de pe web-prod ----------------

def _scanner():
    loader = importlib.machinery.SourceFileLoader("soc_yara_scan", str(YARA_DIR / "soc-yara-scan"))
    spec = importlib.util.spec_from_loader("soc_yara_scan", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def test_scannerul_nu_citeste_momeala(tmp_path, monkeypatch):
    m = _scanner()
    (tmp_path / "html").mkdir()
    for n in ("index.html", ".env.bak", "x.php"):
        (tmp_path / "html" / n).write_text("x")
    os.symlink("/etc/passwd", tmp_path / "html" / "link")
    monkeypatch.setattr(m, "ROOTS", [str(tmp_path)])
    names = sorted(Path(p).name for p in m.files())
    assert names == ["index.html", "x.php"]


def test_regulile_yara_pe_mostre():
    yara = pytest.importorskip("yara")
    r = yara.compile(str(YARA_DIR / "webshells.yar"))
    hit = lambda s: [x.rule for x in r.match(data=s.encode())]
    assert hit('<?php system($_GET["c"]); ?>') == ["soc_php_exec_request_input"]
    assert hit('<?php eval(gzinflate(base64_decode("eA=="))); ?>') == ["soc_php_obfuscated_eval"]
    assert hit('<?php $c = escapeshellarg($f); exec("convert " . $c); ?>') == []
    assert hit('<?php eval("return 1;"); ?>') == []


def test_drift_doar_campurile_de_detectie():
    import importlib.util
    spec = importlib.util.spec_from_file_location("hr", Path(__file__).resolve().parents[1] / "deploy" / "kibana" / "honeytoken_rules.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    want = S.kibana_payload("soc-yara-webshell")
    cur = {**want, "query": 'process.name : "soc-yara" and message : "yara_match"', "enabled": False,
           "exceptions_list": [{"id": "x"}]}
    assert m.drift(cur, want) == {"query": want["query"]}
    assert m.drift(want, want) == {}


# --- pasul 12b: ModSecurity CRS (DetectionOnly) -----------------------------------------
import sensor_rules as _S

_MS = ('[client 172.30.6.133:51234] [client 172.30.6.133] ModSecurity: Warning. Operator GE matched 20 '
       'at TX:anomaly_score. [file "/usr/share/modsecurity-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] '
       '[line "80"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 23)"] '
       '[severity "CRITICAL"] [ver "OWASP_CRS/3.3.5"] [hostname "192.168.10.138"] '
       '[uri "/index.php"] [unique_id "ZX"]')


def _ms_alert(msg, **kw):
    return {"kibana.alert.rule.parameters": {"rule_id": "soc-modsec-anomaly"},
            "kibana.alert.rule.rule_id": "soc-modsec-anomaly", "message": msg, **kw}


def test_modsec_e_senzor_si_payload_kibana():
    a = _ms_alert(_MS)
    assert _S.is_sensor_alert(a)
    p = _S.kibana_payload("soc-modsec-anomaly")
    assert p["index"] == ["logs-apache.error-*"] and "Inbound Anomaly Score Exceeded" in p["query"]
    assert p["threat"][0]["tactic"]["id"] == "TA0001"


def test_modsec_fapte_si_benzi():
    f = _S.modsec_facts(_ms_alert(_MS))
    assert f == {"sensor": "modsecurity", "score": 23, "band": "high", "uri": "/index.php",
                 "client_ip": "172.30.6.133", "rule_ids": ["949110"]}
    f = _S.modsec_facts(_ms_alert(_MS.replace("Total Score: 23", "Total Score: 55")))
    assert f["band"] == "critical"
    assert _S.sensor_facts(_ms_alert(_MS))["sensor"] == "modsecurity"


def test_modsec_mesaj_invalid_sau_ip_fals():
    assert _S.modsec_facts(_ms_alert("ModSecurity: Warning fara scor")) is None
    f = _S.modsec_facts(_ms_alert(_MS.replace("172.30.6.133", "not-an-ip")))
    assert f is not None and f["client_ip"] is None


def test_modsec_formatul_real_crs_335():
    # mesajul real de pe web-prod (2026-11-02), testul de detectie de pe es-node-1
    real = ('[client 192.168.10.121:46068] [client 192.168.10.121] ModSecurity: Warning. Operator GE matched 20 '
            'at TX:anomaly_score. [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Inbound Score: 73 - '
            'SQLI=15,XSS=15,RFI=0,LFI=35,RCE=5,PHPI=0,HTTP=0,SESS=0): individual paranoia level scores: 73, 0, 0, 0"] '
            '[uri "/index.php"]')
    f = _S.modsec_facts(_ms_alert(real))
    assert f["score"] == 73 and f["band"] == "critical" and f["client_ip"] == "192.168.10.121"

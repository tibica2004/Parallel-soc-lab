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


def test_recunoscut_doar_dupa_rule_id():
    assert S.is_sensor_alert(Y())
    assert not S.is_sensor_alert(_alert(**{"kibana.alert.rule.name": "YARA: webshell gasit in webroot"}))


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


def test_orchestrator_model_cazut_pastreaza_motivul(rec):
    hunt = FakeHunt()
    orchestrator.process_alerts([Y()], orchestrator.BoundedSeen(), model_ok=False, t2_limit=1, hunt=hunt)
    assert R.SENSOR_DETECTION in hunt.runs[0][0]["case"].escalation_reasons


def test_payload():
    p = S.kibana_payload("soc-yara-webshell")
    assert p["severity"] == "high" and p["tags"] == [S.TAG] and S.YARA_TAG in p["query"]
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

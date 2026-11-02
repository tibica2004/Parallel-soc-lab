"""plann.md A5 (documentul portii) si S6 (YARA sare core-ul oficial) — functii pure."""
import importlib.machinery
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import gate_metrics as G

ROOT = Path(__file__).resolve().parent.parent
_loader = importlib.machinery.SourceFileLoader("soc_yara_scan", str(ROOT / "deploy/web-prod/yara/soc-yara-scan"))
_spec = importlib.util.spec_from_loader("soc_yara_scan", _loader)
yara = importlib.util.module_from_spec(_spec)
_loader.exec_module(yara)

T0 = datetime(2026, 11, 2, 15, 0, tzinfo=timezone.utc)


def test_documentul_portii():
    res = [("a", "attack", "malicious", 95, "TP"), ("b", "attack", "benign", 80, "FN"),
           ("c", "benign", "benign", 90, "TN"), ("d", "benign", "suspicious", 70, "FP")]
    d = G.gate_summary("scenarios", {"TP": 1, "FN": 1, "TN": 1, "FP": 1}, res, commit="abc1234",
                       prompt_set="4f01c8b50efc", model_tag="qwen3:14b", started=T0,
                       finished=T0 + timedelta(minutes=20))
    assert d["type"] == "gate" and d["recall"] == 0.5 and d["fp_rate"] == 0.5 and d["passed"] is False
    assert d["missed"] == ["b"] and d["false_positives"] == ["d"] and d["duration_s"] == 1200.0
    ok = G.gate_summary("scenarios_fast", {"TP": 3, "TN": 1}, [], commit=None, prompt_set=None,
                        model_tag="m", started=T0, finished=T0)
    assert ok["passed"] and ok["recall"] == 1.0 and ok["fp_rate"] == 0.0


def test_persist_scrie_fisier_fara_cheie(tmp_path, monkeypatch):
    monkeypatch.delenv("ES_METRICS_WRITER_API_KEY", raising=False)
    d = G.gate_summary("x", {"TP": 1}, [], commit=None, prompt_set=None, model_tag="m", started=T0, finished=T0)
    err = G.persist(d, tmp_path)
    assert "fara ES_METRICS" in err and list(tmp_path.glob("gate-x-*.json"))


def test_yara_sare_doar_core_identic():
    sums = {"wp-includes/load.php": "abc", "index.php": "def"}
    assert yara.is_pristine_core("/var/www/html/wp-includes/load.php", "abc", sums)
    assert not yara.is_pristine_core("/var/www/html/wp-includes/load.php", "MOD", sums)   # modificat
    assert not yara.is_pristine_core("/var/www/html/wp-includes/evil.php", "abc", sums)   # necunoscut
    assert not yara.is_pristine_core("/var/www/html/wp-content/plugins/x.php", "abc", sums)
    assert not yara.is_pristine_core("/var/www/html/index.php", "def", None)             # fara sume
    assert yara.wp_version("<?php\n$wp_version = '7.1.3';") == "7.1.3"

"""Pasul 5: runner-ul ART (doar functiile pure: nu ruleaza nimic) si calculul de acoperire."""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import coverage as cv
import hunt as H

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("art_runner", ROOT / "deploy/web-prod/art_runner.py")
art = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(art)
T0 = datetime(2026, 11, 3, 10, 0, tzinfo=timezone.utc)


def _test(cmd="uname -a", cleanup="", deps=None, plat=("linux",), ex="sh", args=None):
    t = {"name": "t", "supported_platforms": list(plat), "executor": {"name": ex, "command": cmd,
         "cleanup_command": cleanup}, "input_arguments": args or {}}
    if deps:
        t["dependencies"] = deps
    return t


def test_runner_refuza_ce_nu_e_pentru_laborator():
    assert art.refusal(_test(plat=("windows",)), "x", "") == "nu e pentru linux"
    assert "executor" in art.refusal(_test(ex="manual"), "x", "")
    assert "dependinte" in art.refusal(_test(deps=[{"x": 1}]), "x", "")
    assert "URL" in art.refusal(_test(), "curl https://example.com/x", "")
    assert "8.8.8.8" in art.refusal(_test(), "ping -c1 8.8.8.8", "")
    assert art.refusal(_test(), "scp f user@192.168.10.160:/tmp/", "rm f") is None
    assert art.refusal(_test(), "ss -tan; cat /etc/passwd", "") is None


def test_runner_argumente_implicite_si_suprascrise():
    t = _test(cmd="echo #{file} > #{dir}/x", args={"file": {"default": "a"}, "dir": {"default": "/tmp"}})
    assert art.render(t["executor"]["command"], t, {}) == "echo a > /tmp/x"
    assert art.render(t["executor"]["command"], t, {"dir": "/var/tmp"}) == "echo a > /var/tmp/x"
    import pytest
    with pytest.raises(ValueError):
        art.render("x", t, {"necunoscut": "1"})
    with pytest.raises(ValueError):
        art.load_test({"atomic_tests": [t]}, 2)


def test_runner_inregistrare_fara_comanda():
    r = art.record("start", "r1", "T1082", 1, "System Information Discovery", "tiberiu")
    assert r["event"] == "art_start" and "command" not in r


def _docs(rid, tech, start, end=None, cleanup_ok=True):
    d = [{"@timestamp": start.isoformat(), "event": "art_start", "run_id": rid, "technique_id": tech,
          "test_number": 1, "test_name": "x", "executor_user": "tiberiu"}]
    if end:
        d.append({"@timestamp": end.isoformat(), "event": "art_end", "run_id": rid, "cleanup_ok": cleanup_ok})
    return d


def test_perechi_si_ferestre():
    runs = cv.pair_runs(_docs("a", "T1082", T0, T0 + timedelta(seconds=30)) + _docs("b", "T1136.001", T0))
    a, b = runs
    assert a["window_end"] == T0 + timedelta(seconds=30) + cv.AFTER
    assert b["window_end"] == T0 + cv.NO_END + cv.AFTER


def test_clasificare_layer_rezumat_si_goluri():
    res = [{"run_id": "1", "technique_id": "T1082", "test_number": 1, "status": cv.classify(0, 5), "n_events": 5},
           {"run_id": "2", "technique_id": "T1082", "test_number": 2, "status": cv.classify(2, 9),
            "rule_names": ["R"], "time_to_alert_s": 40.0},
           {"run_id": "3", "technique_id": "T1053.003", "test_number": 1, "status": cv.classify(0, 0),
            "cleanup_ok": False}]
    layer = cv.navigator_layer(res)
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    sc = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert sc == {"T1082": 2, "T1053.003": 0}
    s = cv.summary(res)
    assert s["techniques_tested"] == 2 and s["pct_detected"] == 50.0 and s["cleanup_failed"] == ["3"]
    assert [g["technique_id"] for g in cv.gap_list(res)] == ["T1053.003"]


def test_tier3_prioritizeaza_golurile_cu_sablon(tmp_path):
    import tier3
    p = tmp_path / "gap.json"
    p.write_text(json.dumps([{"technique_id": "T1053.003"}, {"technique_id": "T9999"}]))
    assert tier3.gap_techniques(p) == ("T1053.003",)
    assert tier3.gap_techniques(tmp_path / "lipsa.json") == ()
    now = datetime(2026, 11, 3, tzinfo=timezone.utc)
    state = {t: {"last": "2026-11-01T00:00:00Z"} for t in H.TECHNIQUES}
    assert H.pick_techniques(state, 2, priority=("T1053.003",), now=now)[0] == "T1053.003"
    state["T1053.003"] = {"last": "2026-11-02T23:00:00Z"}      # vanat acum o ora: fara prioritate
    assert H.pick_techniques(state, 2, priority=("T1053.003",), now=now)[0] != "T1053.003"

"""ablation.py: metricile per configuratie (functie pura) si rotatia ordinii."""
import ablation


def _r(sc, cfg, out, p=1, cls="suspicious", esc=True, inj=False, lat=1000, tok=100, tools=0, rej=0, err=None):
    return {"scenario": sc, "config": cfg, "pass": p, "gt": "attack", "injection": inj, "outcome": out,
            "classification": cls, "escalate": esc, "latency_ms": lat, "tokens": tok,
            "tool_calls": tools, "rejected": rej, "error": err}


def test_rotatie():
    c = ["A", "B", "C", "D"]
    assert ablation.rotation(c, 0) == c and ablation.rotation(c, 1) == ["B", "C", "D", "A"]
    assert ablation.rotation(c, 4) == c


def test_metrici():
    rows = [_r("s1", "A", "TP"), _r("s2", "A", "FN", cls="benign", esc=False, inj=True),
            _r("s3", "A", "FP", lat=3000), _r("s4", "A", "TN", cls="benign", esc=False),
            _r("s1", "C", "TP", tools=3, rej=1, inj=True, tok=300)]
    s = ablation.summarize(rows)
    a = s["A"]
    assert (a["TP"], a["FN"], a["FP"], a["TN"]) == (1, 1, 1, 1)
    assert a["recall"] == 0.5 and a["false_positive_rate"] == 0.5 and a["escalation_rate"] == 0.5
    assert a["injection_runs"] == 1 and a["injection_resisted"] == 0
    assert a["latency_ms_p50"] == 1000.0
    c = s["C"]
    assert c["tool_calls_per_run"] == 3 and c["rejected_pivots"] == 1 and c["injection_resisted"] == 1


def test_instabilitate_intre_treceri():
    rows = [_r("s1", "A", "TP", p=1), _r("s1", "A", "TP", p=2),
            _r("s2", "A", "TP", p=1), _r("s2", "A", "FN", p=2, cls="benign")]
    s = ablation.summarize(rows)["A"]
    assert s["multi_pass_scenarios"] == 2 and s["unstable_scenarios"] == 1


def test_eroarea_escaladeaza():
    r = ablation._error_row("s", "C", 1, {"ground_truth": "attack"}, TimeoutError(), 5)
    assert r["outcome"] == "TP" and r["escalate"] and r["error"] == "TimeoutError"
    r = ablation._error_row("s", "C", 1, {"ground_truth": "benign"}, TimeoutError(), 5)
    assert r["outcome"] == "FP"

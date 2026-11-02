"""Pasul 8.3: metricile, schimbarile fata de baseline si determinismul (functii pure)."""
import regression as R


def _o(*outs):
    return [{"ground_truth": "attack" if o in ("TP", "FN") else "benign", "outcome": o} for o in outs]


def test_metrici_atac():
    m = R.metrics(_o("TP", "TP", "TP", "FN", "FP", "TN", "TN", "TN"))
    assert m["precision_attack"] == 0.75 and m["recall_attack"] == 0.75 and m["f1_attack"] == 0.75
    assert m["fpr_benign"] == 0.25 and m["n"] == 8
    assert R.metrics([])["f1_attack"] is None


def test_schimbari_fata_de_baseline():
    base = {"a": {"classification": "malicious", "flagged": True}, "b": {"classification": "benign", "flagged": False}}
    now = {"a": {"classification": "suspicious", "flagged": True}, "b": {"classification": "benign", "flagged": False},
           "c": {"classification": "benign", "flagged": False}}
    assert [c["alert"] for c in R.changed(base, now)] == ["a"]


def test_determinism_prag_si_schimbari_grave():
    same = {str(i): {"classification": "benign", "flagged": False} for i in range(50)}
    b = dict(same)
    b["0"] = {"classification": "suspicious", "flagged": True}
    d = R.determinism(same, b)
    assert d["identical_pct"] == 98.0 and d["passed"] and d["severe"] == []
    b["1"] = {"classification": "malicious", "flagged": True}
    d = R.determinism(same, b)
    assert not d["passed"] and d["severe"] == ["1"]


def test_echilibru_set_de_aur():
    items = [{"ground_truth": "attack"}] * 50 + [{"ground_truth": "benign"}] * 49
    assert not R.balanced(items)["ok"]
    assert R.balanced(items + [{"ground_truth": "benign"}])["ok"]

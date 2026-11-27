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


# ---------------------------------------------------------------------------------------------
# Faza 23: intervale Wilson 95% si export() repetabil
# ---------------------------------------------------------------------------------------------

def test_wilson_valori_cunoscute():
    # Valori de referinta (Wilson 1927; aceleasi ca statsmodels proportion_confint method="wilson")
    assert R.wilson(8, 10) == (0.4902, 0.9433)
    assert R.wilson(45, 50) == (0.7864, 0.9565)
    assert R.wilson(0, 10) == (0.0, 0.2775)


def test_wilson_n_zero_si_k_egal_n():
    assert R.wilson(0, 0) is None
    assert R.wilson(10, 10) == (0.7225, 1.0)
    assert R.wilson(1, 1) == (0.2065, 1.0)
    lo, hi = R.wilson(50, 50)
    assert hi == 1.0 and 0.9 < lo < 1.0


def test_wilson_respinge_k_in_afara_intervalului():
    import pytest
    with pytest.raises(ValueError):
        R.wilson(11, 10)


def test_metrici_cu_intervale():
    m = R.metrics(_o("TP", "TP", "TP", "FN", "FP", "TN", "TN", "TN"))
    assert m["precision_attack_ci95"] == [0.3006, 0.9544]
    assert m["recall_attack_ci95"] == [0.3006, 0.9544]
    assert m["fpr_benign_ci95"] == [0.0456, 0.6994]
    gol = R.metrics([])
    assert gol["precision_attack_ci95"] is None and gol["recall_attack_ci95"] is None
    assert gol["fpr_benign_ci95"] is None


def test_fmt_ci_pentru_raport():
    assert R.fmt_ci(0.75, [0.3006, 0.9544]) == "0.75 [0.3006, 0.9544]"
    assert R.fmt_ci(None, None) == "—"
    assert R.fmt_ci(1.0, None) == "1.0"


class _FakeES:
    """ES fals pentru export(): un verdict etichetat de om + alerta lui."""

    def __init__(self, gt="attack"):
        self.gt = gt

    def search(self, **_kw):
        return {"hits": {"hits": [{"_id": "v1", "_source": {
            "ground_truth": self.gt, "rule_name": "r",
            "evidence_refs": [{"index": ".internal.alerts-security.alerts-default-000001", "doc_id": "a1"}]}}]}}

    def get(self, index, id):
        return {"_source": {"kibana.alert.rule.name": "r", "_id_ref": id}}


def test_export_ruleaza_de_doua_ori(tmp_path, monkeypatch):
    import json
    import stat
    golden = tmp_path / "golden" / "golden_v1.ndjson"
    monkeypatch.setattr(R, "GOLDEN", golden)
    monkeypatch.setattr(R, "_es", lambda *a, **k: _FakeES("attack"))
    assert R.export() == 0
    assert stat.S_IMODE(golden.stat().st_mode) == 0o440
    # a doua rulare: fisierul vechi e doar-citire; inainte de faza 23 pica la write_text
    monkeypatch.setattr(R, "_es", lambda *a, **k: _FakeES("benign"))
    assert R.export() == 0
    rows = [json.loads(l) for l in golden.read_text().splitlines()]
    assert [r["ground_truth"] for r in rows] == ["benign"]
    assert stat.S_IMODE(golden.stat().st_mode) == 0o440
    assert not (golden.parent / "golden_v1.ndjson.tmp").exists()

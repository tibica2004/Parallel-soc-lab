"""metrics.compute: functie pura peste documente de audit, urme si etichete."""
from datetime import datetime, timedelta, timezone

import pytest

import metrics
import orchestrator

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


def _t(hours_ago, secs=0):
    return (NOW - timedelta(hours=hours_ago, seconds=secs)).isoformat()


def _audit(h, tier="fast", cls="benign", esc=None, reasons=(), dur=10, failure=None, tier2=None,
           corr="not_required", model="m"):
    start = NOW - timedelta(hours=h)
    return {"@timestamp": _t(h), "started_at": start.isoformat(),
            "finished_at": (start + timedelta(seconds=dur)).isoformat(),
            "escalate": esc, "escalation_reasons": list(reasons), "failure": failure, "tier2": tier2,
            "verdict": {"source_path": tier, "classification": cls, "corroboration_status": corr,
                        "model_id": model}}


def _by_tier(docs):
    return {d["tier"]: d for d in docs}


def test_escaladare_esecuri_latenta():
    audits = [
        _audit(1, esc=False, dur=10),
        _audit(2, cls="suspicious", esc=True, reasons=["suspicious"], dur=20, tier2="investigated"),
        _audit(3, cls="undetermined", esc=True, reasons=["undetermined", "tier1_failure"], dur=90,
               failure="case_timeout", model="none", tier2="skipped_budget"),
        _audit(4, tier="hunt", cls="malicious", dur=60, corr="agreement"),
        _audit(5, tier="hunt", cls="undetermined", dur=60, corr="disagreement"),
        _audit(200, esc=True),                                     # in afara ferestrei de 1 zi
    ]
    d = _by_tier(metrics.compute(audits, [], [], NOW, days=1))
    f, h, a = d["fast"], d["hunt"], d["all"]
    assert (f["cases"], f["escalation_decided"], f["escalated"]) == (3, 3, 2)
    assert f["escalation_rate"] == pytest.approx(2 / 3, abs=1e-4)
    assert f["reason_suspicious"] == 1 and f["reason_tier1_failure"] == 1
    assert f["failure_case_timeout"] == 1 and f["no_model"] == 1
    assert (f["tier2_investigated"], f["tier2_skipped_budget"]) == (1, 1)
    assert f["latency_ms_p50"] == 20000.0
    assert h["escalation_rate"] is None                            # calea lenta nu decide escaladarea
    assert (h["ab_agreement"], h["ab_disagreement"], h["ab_agreement_rate"]) == (1, 1, 0.5)
    assert a["cases"] == 5


def test_etichete_doar_umane():
    verdicts = [
        {"@timestamp": _t(1), "source_path": "fast", "label_source": "human", "label_outcome": "TP"},
        {"@timestamp": _t(1), "source_path": "fast", "label_source": "human", "label_outcome": "TP"},
        {"@timestamp": _t(1), "source_path": "fast", "label_source": "human", "label_outcome": "FN"},
        {"@timestamp": _t(1), "source_path": "fast", "label_source": "human", "label_outcome": "FP"},
        {"@timestamp": _t(1), "source_path": "fast", "label_source": "human", "label_outcome": "TN"},
        {"@timestamp": _t(1), "source_path": "fast", "label_outcome": "TN"},          # fara sursa umana
        {"@timestamp": _t(1), "source_path": "fast", "ground_truth": "benign"},       # eticheta veche
    ]
    f = _by_tier(metrics.compute([], [], verdicts, NOW, days=1))["fast"]
    assert (f["labeled"], f["TP"], f["FP"], f["FN"], f["TN"]) == (5, 2, 1, 1, 1)
    assert f["precision"] == pytest.approx(2 / 3, abs=1e-4)
    assert f["recall"] == pytest.approx(2 / 3, abs=1e-4)
    assert f["missed_attack_rate"] == pytest.approx(1 / 3, abs=1e-4)
    assert f["false_positive_rate"] == 0.5


def test_fara_etichete_metricile_sunt_goale_nu_zero():
    f = _by_tier(metrics.compute([], [], [], NOW, days=1))["fast"]
    assert f["precision"] is None and f["recall"] is None and f["escalation_rate"] is None


def test_urme():
    traces = [{"@timestamp": _t(1), "source_path": "hunt",
               "totals": {"tokens": 6000, "tool_calls": 4, "tool_errors": 1}},
              {"@timestamp": _t(2), "source_path": "hunt",
               "totals": {"tokens": 2000, "tool_calls": 0, "tool_errors": 0}}]
    h = _by_tier(metrics.compute([], traces, [], NOW, days=1))["hunt"]
    assert (h["tokens_total"], h["tokens_per_case"], h["tool_calls_per_case"], h["tool_error_rate"]) == \
        (8000, 4000.0, 2.0, 0.25)


def test_drift():
    cur = [_audit(1, esc=True, cls="suspicious"), _audit(2, esc=True, cls="suspicious")]
    old = [_audit(30, esc=False, cls="benign"), _audit(31, esc=True, cls="suspicious")]
    f = _by_tier(metrics.compute(cur + old, [], [], NOW, days=1))["fast"]
    assert f["prev_escalation_rate"] == 0.5 and f["drift_escalation_rate"] == 0.5
    assert f["drift_classes_tvd"] == 0.5


def test_documente_plate_pentru_kibana():
    docs = metrics.compute([_audit(1, esc=True, reasons=["malicious"])], [], [], NOW, days=1)
    for d in docs:
        assert all(not isinstance(v, (dict, list)) for v in d.values())
        assert d["window_days"] == 1 and d["tier"] in ("fast", "hunt", "all")


def test_orchestratorul_tolereaza_esecul_instantaneului(monkeypatch, capsys):
    import types
    import metrics as m
    monkeypatch.setattr(orchestrator, "WRITER", types.SimpleNamespace())
    monkeypatch.setattr(orchestrator, "_metrics_warned", False)
    def boom(*a, **k):
        raise PermissionError("soc-metrics")
    monkeypatch.setattr(m, "compute_and_write", boom)
    orchestrator._metrics_snapshot(); orchestrator._metrics_snapshot()
    assert capsys.readouterr().out.count("instantaneul a esuat") == 1


# ---------------------------------------------------------------------------------------------
# Faza 23: coada omului (timpul pana la prima privire, escaladari pe zi)
# ---------------------------------------------------------------------------------------------

def _v(h_verdict, h_label=None, source="human", history=()):
    d = {"@timestamp": _t(h_verdict), "source_path": "fast", "label_source": source}
    if h_label is not None:
        d["labeled_at"] = _t(h_label)
        d["label_outcome"] = "TP"
    d["label_history"] = list(history)
    return d


def test_prima_privire_doar_etichete_umane():
    docs = [_v(10, 9), _v(10, 8), _v(10, 6), _v(10, 0),           # 1 h, 2 h, 4 h, 10 h
            _v(5, 4, source="auto"),                               # nu e om: ignorat
            _v(5, None),                                           # neetichetat: ignorat
            _v(3, 4)]                                              # eticheta inainte de verdict: sarit
    v = sorted(metrics.time_to_first_look_s(docs))
    assert v == [3600.0, 7200.0, 14400.0, 36000.0]
    m = metrics._first_look_metrics(docs)
    assert m["first_look_n"] == 4
    assert m["first_look_s_p50"] == 10800.0
    assert m["first_look_s_p90"] == pytest.approx(29520.0)


def test_prima_privire_ia_cea_mai_veche_eticheta_umana():
    # reetichetat azi, dar omul s-a uitat prima data dupa 1 h -> 1 h, nu 9 h
    d = _v(10, 1, history=[{"label_source": "human", "labeled_at": _t(9)},
                           {"label_source": None, "labeled_at": _t(9.9)}])
    assert metrics.time_to_first_look_s([d]) == [3600.0]


def test_prima_privire_gol():
    m = metrics._first_look_metrics([])
    assert m == {"first_look_n": 0, "first_look_s_p50": None, "first_look_s_p90": None}


def test_escaladate_pe_zi():
    a = [_audit(1, esc=True), _audit(2, esc=True), _audit(2, esc=False), _audit(30, esc=True),
         _audit(3, esc=None), {"escalate": True}]
    assert metrics.escalated_by_day(a) == {"2026-10-11": 1, "2026-10-12": 2}
    assert metrics.escalated_by_day([]) == {}


def test_compute_are_coada_omului():
    audits = [_audit(1, esc=True), _audit(5, esc=True), _audit(6, esc=False)]
    verdicts = [_v(10, 9), _v(10, 8)]
    d = _by_tier(metrics.compute(audits, [], verdicts, NOW, 1))["all"]
    assert d["escalated_per_day"] == 2.0
    assert d["first_look_n"] == 2 and d["first_look_s_p50"] == 5400.0
    d2 = _by_tier(metrics.compute(audits, [], verdicts, NOW, 2))["all"]
    assert d2["escalated_per_day"] == 1.0

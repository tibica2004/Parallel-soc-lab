"""Faza 23, etapa 2: numaratoarea pentru regula asimetrica Tier 2 (functii pure, fara ES)."""
import importlib.util
from pathlib import Path

_P = Path(__file__).resolve().parent.parent / "experiments" / "tier2_fara_dovezi.py"
_spec = importlib.util.spec_from_file_location("tier2_fara_dovezi", _P)
T = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(T)


def test_randuri_doar_din_unelte():
    assert T.has_rows([{"events": [{"type": "tool", "rows": 3}]}])
    assert not T.has_rows([{"events": [{"type": "tool", "rows": 0}, {"type": "llm", "rows": 5},
                                       {"type": "tool", "rows": None}]}])
    assert not T.has_rows([])


def test_clasificare_sweep_vs_tier1_si_pe_zi():
    v = [{"investigation_id": "a", "chain_id": "c1", "@timestamp": "2026-11-01T10:00:00Z"},   # Tier 1: exclus
         {"investigation_id": "b", "chain_id": "c2", "@timestamp": "2026-11-01T11:00:00Z"},   # randuri: ramane benign
         {"investigation_id": "c", "chain_id": "c3", "@timestamp": "2026-11-01T12:00:00Z"},   # fara randuri
         {"investigation_id": "d", "chain_id": "c4", "@timestamp": "2026-11-02T12:00:00Z"}]   # fara urma deloc
    traces = {"a": [{"events": []}], "b": [{"events": [{"type": "tool", "rows": 2}]}],
              "c": [{"events": [{"type": "tool", "rows": 0}]}]}
    r = T.classify(v, {"c1"}, traces)
    assert (r["hunt_benign"], r["from_tier1"], r["from_sweep"]) == (4, 1, 3)
    assert r["sweep_benign_without_rows"] == 2 and r["of_which_no_trace_doc"] == 1
    assert r["per_day"] == {"2026-11-01": 1, "2026-11-02": 1}

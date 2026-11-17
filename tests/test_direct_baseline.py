"""Faza 23 (1.5): linia de baza "model direct" — partile pure (parsare, scor, agregare).
Fara model si fara Elasticsearch."""
import importlib.util
from pathlib import Path

import prompt_injection as PI

_P = Path(__file__).resolve().parent.parent / "experiments" / "direct_baseline.py"
_spec = importlib.util.spec_from_file_location("direct_baseline", _P)
DB = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(DB)


def _v(cls, act="none", ok=True):
    return {"classification": cls, "proposed_action": act, "parse_ok": ok}


def test_parsare_raspuns_valid_si_gandire():
    v = DB.parse_verdict('<think>hm</think>```json\n{"classification": "Malicious", "confidence": 90}\n```')
    assert v == {"classification": "malicious", "proposed_action": "none", "parse_ok": True}
    v = DB.parse_verdict('Iata: {"classification": "benign", "proposed_action": "none"} gata')
    assert v["classification"] == "benign" and v["parse_ok"]


def test_esecul_de_parsare_escaladeaza():
    for bad in ("nu stiu", '{"classification": "probabil benign"}', "[1, 2]", ""):
        v = DB.parse_verdict(bad)
        assert v["classification"] == "undetermined" and v["proposed_action"] == "escalate_human"
        assert v["parse_ok"] is False
    assert DB.flagged(DB.failure_verdict("timeout"))


def test_undetermined_de_la_model_escaladeaza():
    v = DB.parse_verdict('{"classification": "undetermined", "proposed_action": "none"}')
    assert v["proposed_action"] == "escalate_human" and DB.flagged(v)


def test_scor_ca_interfata_de_etichetare():
    assert DB.score(_v("malicious"), "attack") == "TP"
    assert DB.score(_v("benign"), "attack") == "FN"
    assert DB.score(_v("benign", "escalate_human"), "benign") == "FP"
    assert DB.score(_v("benign"), "benign") == "TN"
    assert DB.score(DB.failure_verdict("x"), "benign") == "FP"


def test_majoritate_pe_treceri():
    p = [_v("benign"), _v("malicious"), _v("benign")]
    assert DB.key_of(DB.majority_verdict(p)) == ("benign", False)


def test_agregare_set_de_aur():
    items = [
        {"ground_truth": "attack", "passes": [_v("malicious")] * 3},                          # TP stabil
        {"ground_truth": "attack", "passes": [_v("benign"), _v("benign"), _v("suspicious")]},  # FN, instabil
        {"ground_truth": "benign", "passes": [_v("benign")] * 3},                             # TN
        {"ground_truth": "benign", "passes": [DB.failure_verdict("x")] * 3},                  # FP (esec)
    ]
    g = DB.aggregate_golden(items)
    m = g["majority"]
    assert (m["TP"], m["FN"], m["TN"], m["FP"]) == (1, 1, 1, 1)
    assert m["recall_attack"] == 0.5 and m["recall_attack_ci95"] == [0.0945, 0.9055]
    assert g["unstable_between_passes"] == 1 and g["parse_failures"] == 3 and g["calls"] == 12
    assert len(g["per_pass"]) == 3 and g["per_pass"][2]["recall_attack"] == 1.0
    assert DB.aggregate_golden([]) == {"n": 0}


def test_agregare_injectie_refoloseste_criteriile_suitei():
    cases = PI.build_cases()
    clean = {"M1": [_v("malicious")] * 3, "B1": [_v("benign")] * 3}
    runs = {c["id"]: ([_v("malicious")] * 3 if c["base"] == "M1" else [_v("benign")] * 3) for c in cases}
    s = DB.aggregate_injection(clean, cases, runs)["summary"]
    assert s["passed"] and s["identical"] == s["identity_cases"] and s["malicious_all_ok"]
    # un singur caz M1 retrogradat la benign -> pica criteriul tare
    first_m1 = next(c["id"] for c in cases if c["base"] == "M1" and not c["fact_changing"])
    runs[first_m1] = [_v("benign")] * 3
    s = DB.aggregate_injection(clean, cases, runs)["summary"]
    assert not s["malicious_all_ok"] and not s["passed"] and first_m1 in s["failed_ids"]


def test_tabelul_text():
    items = [{"ground_truth": "attack", "passes": [_v("malicious")] * 3},
             {"ground_truth": "benign", "passes": [_v("benign")] * 3}]
    rep = {"ts": "t", "model": "m", "passes": 3, "prompt_sha256": "ab" * 32,
           "golden": DB.aggregate_golden(items),
           "injection": {"skipped": "--doar golden"}, "latency_ms": {"n": 6, "p50": 812.0, "p90": 900.0}}
    t = DB.render_table(rep)
    assert "recall atac      1.0 [0.2065, 1.0]" in t
    assert "rata FP (benign) 0.0 [0.0, 0.7935]" in t
    assert "Injectie: --doar golden" in t and "p50 812.0 ms" in t
    assert "lipseste" in DB.render_table({"golden": {"n": 0, "skipped": "lipseste"}})


def test_promptul_minim_nu_are_delimitare_sau_fapte():
    # linia de baza masoara modelul singur: fara markerii de telemetrie neincrezatoare si fara fapte
    assert "untrusted" not in DB.SYSTEM_PROMPT.lower() and "TELEMETRIE" not in DB.SYSTEM_PROMPT
    assert "pair_in_baseline" not in DB.SYSTEM_PROMPT


def test_nu_scrie_in_indici():
    src = _P.read_text()
    for idx in ("verdicts-history", "soc-audit", "soc-metrics"):
        assert f'index="{idx}"' not in src and f"index='{idx}'" not in src
    assert ".index(" not in src and "fast_path" not in src.split('"""', 2)[2]

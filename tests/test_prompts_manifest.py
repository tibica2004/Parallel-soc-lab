"""Pasul 8.2: prompturile sunt versionate; o schimbare fara bump pica aici (si orchestratorul refuza)."""
import prompts as P


def test_registrul_se_rezolva():
    h = P.current()
    assert set(h) == set(P.REGISTRY) and all(len(v) == 64 for v in h.values())


def test_manifestul_e_la_zi():
    bad = P.diff(P.load_manifest(), P.current())
    assert bad == [], (f"prompturi schimbate fara bump: {bad}. Ruleaza make regression, apoi "
                       "python prompts.py --update --reason ...")


def test_bump_doar_ce_s_a_schimbat_si_set_nou():
    old = {"prompts": {"a": {"version": 2, "sha256": "x"}, "b": {"version": 1, "sha256": "y"},
                       "vechi": {"version": 1, "sha256": "z"}}}
    new, changed = P.bump(old, {"a": "x", "b": "y2", "c": "w"}, "motiv", "2026-11-02")
    assert changed == ["b", "c"]
    assert new["prompts"]["a"]["version"] == 2 and new["prompts"]["b"]["version"] == 2
    assert new["prompts"]["c"]["version"] == 1 and "vechi" not in new["prompts"]
    assert new["prompt_set"] == P.prompt_set({"a": "x", "b": "y2", "c": "w"})


def test_setul_depinde_de_continut_nu_de_ordine():
    assert P.prompt_set({"a": "1", "b": "2"}) == P.prompt_set({"b": "2", "a": "1"})
    assert P.prompt_set({"a": "1"}) != P.prompt_set({"a": "2"})

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
    assert changed == ["b", "c", "vechi (sters)"]
    assert new["prompts"]["a"]["version"] == 2 and new["prompts"]["b"]["version"] == 2
    assert new["prompts"]["c"]["version"] == 1 and "vechi" not in new["prompts"]
    assert new["prompt_set"] == P.prompt_set({"a": "x", "b": "y2", "c": "w"})


def test_setul_depinde_de_continut_nu_de_ordine():
    assert P.prompt_set({"a": "1", "b": "2"}) == P.prompt_set({"b": "2", "a": "1"})
    assert P.prompt_set({"a": "1"}) != P.prompt_set({"a": "2"})


def test_stergerea_unui_prompt_e_o_schimbare():
    old = {"prompts": {"a": {"version": 1, "sha256": "x"}, "vechi": {"version": 2, "sha256": "z"}}}
    new, changed = P.bump(old, {"a": "x"}, "sters", "2026-11-02")
    assert changed == ["vechi (sters)"] and "vechi" not in new["prompts"] and new["prompt_set"] == P.prompt_set({"a": "x"})


def test_toate_constantele_de_prompt_sunt_in_registru():
    """Faza 22 F: orice constanta de modul care ajunge la model (nume terminat in _PROMPT, _NOTE
    sau _RULES) din modulele cu prompturi trebuie sa fie in REGISTRY, altfel o schimbare acolo
    nu declanseaza poarta de versiune."""
    import importlib
    import re
    registered = {(mod, name) for mod, name in P.REGISTRY.values() if mod != "file"}
    missing = []
    for mod in ("hunt_path", "fast_path", "l1_agent", "hunt", "rules", "tier3"):
        m = importlib.import_module(mod)
        for name, val in vars(m).items():
            if re.match(r"^[A-Z0-9_]+(_PROMPT|_NOTE|_RULES)$", name) and isinstance(val, str) \
                    and (mod, name) not in registered:
                missing.append(f"{mod}.{name}")
    assert missing == [], f"prompturi in afara MANIFEST-ului: {missing}"

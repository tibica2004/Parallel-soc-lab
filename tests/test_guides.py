"""Ghidurile de investigatie (detections/*.md) referite de fast_path.RULE_TO_GUIDE exista
si incap in fereastra de 1500 de caractere pe care lookup_guide o trimite in prompt.
Fara model, fara Elasticsearch."""
from pathlib import Path

import fast_path

ROOT = Path(__file__).resolve().parent.parent


def test_toate_ghidurile_din_harta_exista():
    lipsa = [f for f in fast_path.RULE_TO_GUIDE.values() if not (ROOT / "detections" / f).exists()]
    assert lipsa == []


def test_ghidurile_incap_in_fereastra_promptului():
    for f in fast_path.RULE_TO_GUIDE.values():
        text = (ROOT / "detections" / f).read_text(encoding="utf-8")
        assert len(text) <= 1500, f"{f}: {len(text)} caractere, lookup_guide taie la 1500"
        assert "## Concluzie" in text, f"{f}: lipseste sectiunea Concluzie"


def test_lookup_guide_pe_regulile_cu_volum_mare():
    for rule in ("Webshell: Executable written to webroot",
                 "Suspicious execution from temp directory",
                 "RCE: Web server spawns shell"):
        g = fast_path.lookup_guide(rule)
        assert g and g.startswith("# "), rule
    assert fast_path.lookup_guide("regula inexistenta") is None


def test_ghidurile_se_cauta_in_repo_nu_in_home():
    """Faza 23: implicitul e detections/ de langa hunt_path.py, nu ~/lab/detections, deci
    o clona in alt director (sau pe alt host) gaseste ghidurile; GUIDES_DIR din mediu ramane."""
    import hunt_path
    assert hunt_path.guides_dir({}) == ROOT / "detections"
    assert hunt_path.guides_dir({"GUIDES_DIR": ""}) == ROOT / "detections"
    assert str(hunt_path.guides_dir({"GUIDES_DIR": "/alt/director"})) == "/alt/director"

"""Faza 24: radacina depozitului vine dintr-un singur loc (elasticlab/paths.py), nu din __file__-ul
fiecarui modul, ca modulele sa poata sta in subpachete."""
from __future__ import annotations

from pathlib import Path

from elasticlab.paths import REPO_ROOT

TESTS_ROOT = Path(__file__).resolve().parent.parent
ALLOWED = {"elasticlab/paths.py", "elasticlab/_compat.py"}


def test_repo_root_e_radacina_depozitului():
    assert REPO_ROOT == TESTS_ROOT
    for rel in ("prompts/MANIFEST.json", "detections", "kb", "scenarios.yml", "deploy/soc-orchestrator.service"):
        assert (REPO_ROOT / rel).exists(), rel


def test_niciun_modul_nu_isi_ia_radacina_din_file():
    files = list(REPO_ROOT.glob("*.py")) + list(REPO_ROOT.glob("elasticlab/**/*.py"))
    bad = [str(p.relative_to(REPO_ROOT)) for p in files
           if str(p.relative_to(REPO_ROOT)) not in ALLOWED and "__file__" in p.read_text(encoding="utf-8")]
    assert bad == []

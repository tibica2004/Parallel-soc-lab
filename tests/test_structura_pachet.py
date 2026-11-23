"""Faza 24: modulele mutate in elasticlab/ raman importabile pe vechile cai (acelasi obiect de modul),
scripturile pornite direct merg, iar caile din ExecStart exista."""
from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

from elasticlab._compat import MOVED
from elasticlab.paths import REPO_ROOT

MAIN_RE = re.compile(r'^if __name__ == ["\']__main__["\']:', re.M)


@pytest.mark.parametrize("old,new", sorted(MOVED.items()))
def test_calea_veche_e_acelasi_modul(old, new):
    assert importlib.import_module(old) is importlib.import_module(new)


@pytest.mark.parametrize("old,new", sorted(MOVED.items()))
def test_fisierul_subtire(old, new):
    stub = (REPO_ROOT / f"{old}.py").read_text(encoding="utf-8")
    target = REPO_ROOT / (new.replace(".", "/") + ".py")
    assert target.exists()
    assert f'alias(__name__, "{new}")' in stub and len(stub.splitlines()) <= 15
    # scripturile rulate direct (ExecStart, Makefile) trec prin run_main
    assert (f'run_main("{new}")' in stub) == bool(MAIN_RE.search(target.read_text(encoding="utf-8")))


def test_fiecare_fisier_subtire_e_in_moved():
    stubs = {p.stem for p in REPO_ROOT.glob("*.py") if "elasticlab._compat" in p.read_text(encoding="utf-8")}
    assert stubs == set(MOVED)


def _execstart_scripts() -> list[tuple[str, str]]:
    out = []
    for unit in REPO_ROOT.glob("deploy/**/*.service"):
        text = unit.read_text(encoding="utf-8")
        if "WorkingDirectory=/home/tiberiu/lab" not in text:
            continue
        for line in text.splitlines():
            if line.startswith("ExecStart="):
                out += [(unit.name, tok) for tok in line.split() if tok.endswith(".py") and not tok.startswith("/")]
    return out


def test_caile_din_execstart_exista():
    scripts = _execstart_scripts()
    assert ("soc-orchestrator.service", "orchestrator.py") in scripts
    assert [s for s in scripts if not (REPO_ROOT / s[1]).exists()] == []


def test_elasticlab_nu_importa_pe_caile_vechi():
    """Altfel regula de importuri (.importlinter) nu ar vedea dependenta: numele vechi sunt module
    din afara pachetului. (prompts.REGISTRY numeste modulele ca siruri; trece prin fisierele subtiri.)"""
    import ast
    bad = []
    for p in REPO_ROOT.glob("elasticlab/**/*.py"):
        for n in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            names = ([a.name for a in n.names] if isinstance(n, ast.Import)
                     else [n.module] if isinstance(n, ast.ImportFrom) and n.level == 0 else [])
            bad += [f"{p.relative_to(REPO_ROOT)}:{n.lineno} {m}" for m in names if m and m.split(".")[0] in MOVED]
    assert bad == []

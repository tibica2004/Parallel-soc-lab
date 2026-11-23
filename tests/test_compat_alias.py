"""Faza 24: fisierele subtiri de la vechile cai (elasticlab/_compat.py). Pe un pachet temporar,
fara modulele SOC-ului."""
from __future__ import annotations

import importlib
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from elasticlab._compat import alias
from elasticlab.paths import REPO_ROOT

STUB = "from elasticlab._compat import alias\nalias(__name__, {new!r})\n"
SCRIPT_STUB = ("from elasticlab._compat import alias, run_main\n"
               "if __name__ == '__main__':\n    run_main({new!r})\nelse:\n    alias(__name__, {new!r})\n")


@pytest.fixture
def pkg(tmp_path, monkeypatch):
    """pkgx/a.py si pkgx/b.py se importa circular prin NUMELE VECHI (vechi_a, vechi_b)."""
    (tmp_path / "pkgx").mkdir()
    (tmp_path / "pkgx" / "__init__.py").write_text("")
    (tmp_path / "pkgx" / "a.py").write_text(textwrap.dedent("""
        import vechi_b
        STARE = []
        def cheama_b():
            return vechi_b.valoare()
    """))
    (tmp_path / "pkgx" / "b.py").write_text(textwrap.dedent("""
        import vechi_a
        def valoare():
            return len(vechi_a.STARE)
    """))
    (tmp_path / "pkgx" / "script.py").write_text(textwrap.dedent("""
        import sys
        def main():
            print("argv", sys.argv[1:])
            return 3
        if __name__ == "__main__":
            sys.exit(main())
    """))
    (tmp_path / "vechi_a.py").write_text(STUB.format(new="pkgx.a"))
    (tmp_path / "vechi_b.py").write_text(STUB.format(new="pkgx.b"))
    (tmp_path / "vechi_script.py").write_text(SCRIPT_STUB.format(new="pkgx.script"))
    monkeypatch.syspath_prepend(str(tmp_path))
    yield tmp_path
    for name in [n for n in sys.modules if n.startswith(("pkgx", "vechi_"))]:
        del sys.modules[name]


def test_acelasi_obiect_de_modul(pkg):
    import vechi_a
    import pkgx.a
    assert vechi_a is pkgx.a is sys.modules["vechi_a"] is sys.modules["pkgx.a"]
    import vechi_b
    assert vechi_b is importlib.import_module("pkgx.b")


def test_import_circular_prin_numele_vechi(pkg):
    import vechi_a
    vechi_a.STARE.append(1)
    assert vechi_a.cheama_b() == 1          # b vede modulul real, nu fisierul subtire


def test_monkeypatch_pe_numele_vechi_ajunge_in_modulul_nou(pkg, monkeypatch):
    import vechi_b
    import pkgx.a
    monkeypatch.setattr(vechi_b, "valoare", lambda: 42)
    assert pkgx.a.cheama_b() == 42


def test_import_intai_pe_numele_nou(pkg):
    import pkgx.b
    import vechi_b
    assert vechi_b is pkgx.b


def test_reload_merge(pkg):
    import vechi_a
    assert importlib.reload(vechi_a) is sys.modules["pkgx.a"]


def test_modul_lipsa_da_eroare_clara(pkg):
    with pytest.raises(ModuleNotFoundError, match="pkgx.nu_exista"):
        alias("vechi_lipsa", "pkgx.nu_exista")


def test_script_rulat_direct_pastreaza_argv_si_codul_de_iesire(pkg):
    env = {"PYTHONPATH": f"{REPO_ROOT}", "PATH": "/usr/bin:/bin"}
    r = subprocess.run([sys.executable, str(pkg / "vechi_script.py"), "--x", "1"], cwd=pkg, env=env,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 3, r.stderr
    assert "argv ['--x', '1']" in r.stdout

"""Expunere WordPress (faza 18): comparator de versiuni, validarea feed-ului si
potrivirea pura intre versiunile instalate si lista de vulnerabilitati. Fara ES."""
import pytest

import exposure as X


@pytest.mark.parametrize("v,expect", [
    ("1.2.3", (1, 2, 3)), ("7.1.3", (7, 1, 3)), ("5", (5,)),
    ("6.4.2-beta1", (6, 4, 2)), ("nu-versiune", None), ("", None), (None, None),
])
def test_parse_version(v, expect):
    assert X.parse_version(v) == expect


def test_compara_completand_cu_zero():
    assert X._cmp((1, 2), (1, 2, 0)) == 0
    assert X._cmp((1, 2), (1, 3)) < 0
    assert X._cmp((2,), (1, 9, 9)) > 0


@pytest.mark.parametrize("ver,intro,fixed,vuln", [
    ("7.1.3", "0", "7.1.4", True),       # sub limita de sus
    ("7.1.4", "0", "7.1.4", False),      # fixed e exclusiv: versiunea reparata NU e vulnerabila
    ("3.9", "4.0", "5.3.1", False),      # sub introduced
    ("4.0", "4.0", "5.3.1", True),       # introduced e inclusiv
    ("9.9", "0", None, True),            # nereparat: fara limita de sus
    ("9.9", "0", "", True),              # fixed gol = nereparat
    ("stricata", "0", "7.1.4", False),   # versiune instalata neparsabila -> prudent, nu vulnerabila
])
def test_in_range(ver, intro, fixed, vuln):
    assert X.in_range(ver, intro, fixed) is vuln


def test_parse_entries_valideaza():
    raw = {"components": [
        {"component": "core", "introduced": "0", "fixed": "7.1.4", "severity": "critical", "cve": "CVE-2026-0001"},
        {"component": "AkiSmet", "introduced": "4.0", "fixed": "5.3.1", "severity": "bizar"},  # severitate -> medium
        {"component": "rau slug!", "fixed": "1.0"},          # slug invalid -> sarit
        {"component": "x", "introduced": "nu-e-versiune"},   # introduced invalid -> sarit
        {"component": "y", "fixed": "nu-e-versiune"},        # fixed invalid -> sarit
        "nu-e-dict",                                         # sarit
    ]}
    out = X.parse_entries(raw, "test")
    comps = [e["component"] for e in out]
    assert comps == ["core", "akismet"]                      # doar cele valide, slug normalizat
    assert out[1]["severity"] == "medium" and out[1]["cve"] is None
    assert out[0]["cve"] == "CVE-2026-0001"


def test_normalize_installed_forme_si_validare():
    # forma `wp plugin list` (lista de dict)
    lst = [{"name": "akismet", "version": "5.0"}, {"name": "rau!", "version": "1.0"},
           {"name": "hello", "version": "x"}, "junk"]
    assert X.normalize_installed(lst) == {"akismet": "5.0"}
    # forma dict directa, cu nucleul
    assert X.normalize_installed({"core": "7.1.3", "akismet": "5.0"}) == {"core": "7.1.3", "akismet": "5.0"}


def test_vulnerable_components_potriveste_si_sorteaza():
    entries = tuple(X.parse_entries({"components": [
        {"component": "core", "introduced": "0", "fixed": "7.1.4", "severity": "critical", "cve": "CVE-2026-0001"},
        {"component": "akismet", "introduced": "4.0", "fixed": "5.3.1", "severity": "high"},
        {"component": "hello", "introduced": "0", "fixed": None, "severity": "medium"},
    ]}, "test"))
    installed = {"core": "7.1.3", "akismet": "5.9", "hello": "1.0"}  # akismet 5.9 >= 5.3.1 -> NU vulnerabil
    out = X.vulnerable_components(installed, entries)
    assert [m["component"] for m in out] == ["core", "hello"]        # grav intai
    assert out[0]["cve"] == "CVE-2026-0001" and out[0]["installed_version"] == "7.1.3"


def test_versiune_neinstalata_nu_apare():
    entries = tuple(X.parse_entries({"components": [
        {"component": "core", "introduced": "0", "fixed": "7.1.4", "severity": "critical"}]}, "test"))
    assert X.vulnerable_components({"akismet": "1.0"}, entries) == []


def test_load_citeste_feed_local():
    entries = X.load()
    assert any(e["component"] == "core" for e in entries)
    assert all(e["severity"] in X.SEVERITIES for e in entries)

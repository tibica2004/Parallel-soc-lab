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


def test_installed_from_doc():
    doc = {"host": "web-prod", "components": [
        {"component": "core", "version": "7.1.3"}, {"component": "akismet", "version": "5.0"},
        {"component": "rau!", "version": "1.0"}]}      # slug invalid -> sarit
    assert X.installed_from_doc(doc) == {"core": "7.1.3", "akismet": "5.0"}
    assert X.installed_from_doc(None) == {}


@pytest.mark.parametrize("path,slug", [
    ("/wp-content/plugins/akismet/akismet.php", "akismet"),
    ("/wp-content/plugins/akismet", "akismet"),
    ("/wp-content/themes/twentytwo/style.css", "twentytwo"),
    ("/WP-CONTENT/PLUGINS/Akismet/x.php", "akismet"),     # ne-sensibil la litere
    ("/wp-login.php", None), ("/xmlrpc.php", None), ("/", None),
    ("/wp-content/uploads/x.php", None),                  # nu e plugin/theme
    (None, None), (123, None),
])
def test_component_from_path(path, slug):
    assert X.component_from_path(path) == slug


def _vuln():
    entries = tuple(X.parse_entries({"components": [
        {"component": "core", "introduced": "0", "fixed": "7.1.4", "severity": "critical", "cve": "CVE-2026-0001"},
        {"component": "akismet", "introduced": "4.0", "fixed": "5.3.1", "severity": "high", "cve": "CVE-2026-0002"},
    ]}, "test"))
    return X.vulnerable_components({"core": "7.1.3", "akismet": "5.0"}, entries)


def test_correlate_fara_vulnerabile_e_gol():
    assert X.correlate([], [{"source_ip": "1.2.3.4", "url_path": "/x"}]) == []


def test_correlate_plugin_tintit_si_core():
    vuln = _vuln()
    touches = [
        {"source_ip": "203.0.113.9", "url_path": "/wp-content/plugins/akismet/x.php", "kind": "web_enumeration", "count": 5},
        {"source_ip": "203.0.113.9", "url_path": "/xmlrpc.php", "kind": "wp_recon_path", "count": 2},
    ]
    out = X.correlate(vuln, touches)
    by = {(c["component"], c["source_ip"]): c for c in out}
    # akismet lovit direct pe slug
    assert ("akismet", "203.0.113.9") in by and by[("akismet", "203.0.113.9")]["cve"] == "CVE-2026-0002"
    # core: orice atingere de atac pe host conteaza (ambele), hits insumate
    core = by[("core", "203.0.113.9")]
    assert core["hits"] == 7 and core["severity"] == "critical"
    # cel mai grav intai
    assert out[0]["component"] == "core"


def test_correlate_plugin_neatins_nu_apare():
    vuln = _vuln()
    # sursa loveste doar un plugin care NU e in lista vulnerabila
    out = X.correlate(vuln, [{"source_ip": "198.51.100.7",
                              "url_path": "/wp-content/plugins/jetpack/x.php", "count": 1}])
    comps = {c["component"] for c in out}
    assert "akismet" not in comps          # jetpack nu e akismet
    assert comps == {"core"}               # dar e o atingere de atac pe host -> core


def test_correlate_sare_randuri_invalide():
    vuln = _vuln()
    out = X.correlate(vuln, [{"url_path": "/x"}, "junk", {"source_ip": "   "},
                             {"source_ip": "203.0.113.9", "url_path": "/wp-login.php"}])
    assert len(out) == 1 and out[0]["component"] == "core" and out[0]["hits"] == 1


def test_correlation_key_stabil():
    c = {"source_ip": "203.0.113.9", "component": "akismet"}
    assert X.correlation_key("web-prod", c) == "wp_exposure|web-prod|203.0.113.9|akismet"


def test_make_exposure_case_valid():
    from schemas import EscalationReason
    c = {"component": "akismet", "installed_version": "5.0", "cve": "CVE-2026-0002",
         "severity": "high", "source_ip": "203.0.113.9", "hits": 7, "sample_path": "/wp-content/plugins/akismet/x.php"}
    case = X.make_exposure_case(c, "web-prod", "12345678-1234-1234-1234-123456789abc")
    assert case.origin == "tier3_hunt" and case.host == "web-prod"
    assert case.escalation_reasons == [EscalationReason.HUNT_MATCH]
    assert case.hunt_match.technique == "T1190" and case.hunt_match.template_id == "wp_exposure"
    assert case.hunt_match.who == "203.0.113.9" and case.hunt_match.count == 7
    assert "akismet" in case.hunt_match.what and "CVE-2026-0002" in case.hunt_match.what

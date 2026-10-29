"""
Teste pentru nday_watch: functii pure (fara retea, fara Elasticsearch). Verifica
ce intra in actiune — potrivirea de versiuni, severitatea, _id-ul idempotent,
schema de granita — nu apelurile de retea.
"""
from __future__ import annotations

import pytest

import nday_watch as nd
from nday_watch import VulnRecord


def test_cvss_to_severity_boundaries():
    assert nd.cvss_to_severity(0.0) == "low"
    assert nd.cvss_to_severity(3.9) == "low"
    assert nd.cvss_to_severity(4.0) == "medium"
    assert nd.cvss_to_severity(6.9) == "medium"
    assert nd.cvss_to_severity(7.0) == "high"
    assert nd.cvss_to_severity(8.9) == "high"
    assert nd.cvss_to_severity(9.0) == "critical"
    assert nd.cvss_to_severity(10.0) == "critical"
    # scor necunoscut -> prudent, medium
    assert nd.cvss_to_severity(None) == "medium"
    assert nd.cvss_to_severity(-1.0) == "medium"


def test_vuln_id_stable_and_idempotent():
    a = nd.vuln_id("web-prod", "CVE-2024-1234", "contact-form-7")
    b = nd.vuln_id("web-prod", "cve-2024-1234", "Contact-Form-7")  # case-insensitive
    c = nd.vuln_id("web-prod", "CVE-2024-9999", "contact-form-7")
    assert a == b                     # acelasi _id -> upsert, zero duplicate
    assert a != c                     # CVE diferit -> _id diferit
    assert len(a) == 64               # sha256 hex


def test_to_cpe_and_purl_only_known_components():
    assert nd.to_cpe("apache", "2.4.58") == "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
    assert nd.to_cpe("php", "8.3.0").startswith("cpe:2.3:a:php:php:8.3.0")
    assert nd.to_cpe("wp_core", "7.1.3").startswith("cpe:2.3:a:wordpress:wordpress:7.1.3")
    assert nd.to_cpe("plugin", "1.0") is None          # A2: pluginurile NU au CPE aici
    assert nd.to_cpe("apache", "nu-e-versiune") is None
    assert nd.to_purl("wp_core", "7.1.3") == "pkg:generic/wordpress@7.1.3"
    assert nd.to_purl("theme", "1.0") is None


def test_osv_affects_in_range():
    affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "2.4.0"}, {"fixed": "2.4.60"}]}]}]
    vulnerable, fixed, needs_review = nd.osv_affects("2.4.58", affected)
    assert vulnerable is True
    assert fixed == "2.4.60"
    assert needs_review is False


def test_osv_affects_patched_version_not_vulnerable():
    affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "2.4.0"}, {"fixed": "2.4.60"}]}]}]
    vulnerable, _fixed, needs_review = nd.osv_affects("2.4.60", affected)
    assert vulnerable is False
    assert needs_review is False


def test_osv_affects_unparseable_installed_needs_review():
    affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]
    vulnerable, _fixed, needs_review = nd.osv_affects("nu-stiu", affected)
    assert vulnerable is False
    assert needs_review is True      # prudent: nu aruncam, cerem revizuire umana


def test_osv_affects_unknown_range_type_needs_review():
    affected = [{"ranges": [{"type": "CALVER", "events": [{"introduced": "0"}]}]}]
    _vulnerable, _fixed, needs_review = nd.osv_affects("2.4.58", affected)
    assert needs_review is True


def _nvd_cve(cpe_matches):
    """Construieste un cve_obj NVD minimal cu o configuratie cu cpeMatch-urile date."""
    return {"configurations": [{"nodes": [{"cpeMatch": cpe_matches}]}]}


def test_nvd_affects_in_range_confirms_and_sets_fixed():
    cve = _nvd_cve([{"vulnerable": True,
                     "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                     "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.60"}])
    vulnerable, fixed, needs_review = nd.nvd_affects("apache", "2.4.58", cve)
    assert vulnerable is True
    assert fixed == "2.4.60"
    assert needs_review is False


def test_nvd_affects_out_of_range_not_vulnerable():
    cve = _nvd_cve([{"vulnerable": True,
                     "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                     "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.50"}])
    vulnerable, _fixed, needs_review = nd.nvd_affects("apache", "2.4.58", cve)
    assert vulnerable is False
    assert needs_review is False          # interval clar, instalat in afara -> nu e vuln


def test_nvd_affects_exact_version_match():
    cve = _nvd_cve([{"vulnerable": True,
                     "criteria": "cpe:2.3:a:php:php:8.3.6:*:*:*:*:*:*:*"}])
    vulnerable, fixed, needs_review = nd.nvd_affects("php", "8.3.6", cve)
    assert (vulnerable, fixed, needs_review) == (True, None, False)
    # alta versiune exacta -> nu se potriveste, nici needs_review
    v2, _f, nr2 = nd.nvd_affects("php", "8.3.7", cve)
    assert v2 is False and nr2 is False


def test_nvd_affects_wildcard_all_versions_vulnerable():
    cve = _nvd_cve([{"vulnerable": True,
                     "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"}])
    vulnerable, fixed, needs_review = nd.nvd_affects("wp_core", "7.1.3", cve)
    assert (vulnerable, fixed, needs_review) == (True, None, False)


def test_nvd_affects_unparsable_bound_needs_review():
    cve = _nvd_cve([{"vulnerable": True,
                     "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                     "versionEndExcluding": "nu-e-versiune"}])
    _v, _f, needs_review = nd.nvd_affects("apache", "2.4.58", cve)
    assert needs_review is True           # prudent: nu confirmam, nu aruncam


def test_nvd_affects_wrong_product_ignored():
    # cpeMatch pentru alt produs -> nu ne priveste; fara config utile -> needs_review
    cve = _nvd_cve([{"vulnerable": True,
                     "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                     "versionEndExcluding": "1.0"}])
    vulnerable, _f, needs_review = nd.nvd_affects("apache", "2.4.58", cve)
    assert vulnerable is False
    assert needs_review is True


def test_is_update_available():
    assert nd.is_update_available("1.2.0", "1.3.0") is True
    assert nd.is_update_available("1.3.0", "1.3.0") is False
    assert nd.is_update_available("2.0.0", "1.9.9") is False
    assert nd.is_update_available("x", "1.0") is False       # neparsabil -> fara semnal


def test_vulnrecord_extra_forbid_blocks_exploit_fields():
    # E2: campurile exploit/poc/payload NU exista in model -> extra=forbid le respinge
    base = dict(cve="CVE-2024-1", component_type="plugin", component_name="demo",
                installed_version="1.0", severity="high", first_seen=nd.now_iso(),
                last_seen=nd.now_iso(), source="wpscan", host="web-prod")
    VulnRecord(**base)  # valid
    for bad in ("exploit", "poc", "payload"):
        with pytest.raises(Exception):
            VulnRecord(**base, **{bad: "orice"})


def test_vulnrecord_rejects_bad_severity_and_type():
    base = dict(cve="CVE-2024-1", component_name="demo", installed_version="1.0",
                first_seen=nd.now_iso(), last_seen=nd.now_iso(), source="osv",
                host="web-prod")
    with pytest.raises(Exception):
        VulnRecord(**base, component_type="plugin", severity="apocaliptic")
    with pytest.raises(Exception):
        VulnRecord(**base, component_type="firmware", severity="high")


def test_vulnrecord_rejects_whitespace_cve():
    with pytest.raises(Exception):
        VulnRecord(cve="CVE 2024 1", component_type="plugin", component_name="demo",
                   installed_version="1.0", severity="high", first_seen=nd.now_iso(),
                   last_seen=nd.now_iso(), source="wpscan", host="web-prod")


def test_build_plugin_records_no_feed_is_needs_review():
    recs = nd.build_plugin_records("plugin", "mystery-plugin", "1.0", None)
    assert len(recs) == 1
    assert recs[0].needs_review is True
    assert recs[0].cve == "UNKNOWN-NO-FEED"
    assert recs[0].component_name == "mystery-plugin"


def test_es_client_missing_key_hard_fails(monkeypatch):
    # R9: o cheie de scriere lipsa trebuie sa opreasca rularea, NU sa cada tacut
    # pe ES_API_KEY (read-only) si sa scrie in gol (403 inghitit = no-op tacut).
    monkeypatch.delenv("ES_VULNS_WRITER_API_KEY", raising=False)
    monkeypatch.setenv("ES_API_KEY", "read-only-key")
    with pytest.raises(RuntimeError, match="ES_VULNS_WRITER_API_KEY"):
        nd.es_client("ES_VULNS_WRITER_API_KEY")


def test_es_client_present_key_builds_client(monkeypatch):
    # constructia Elasticsearch e lenesa (nu se conecteaza) -> testabil fara retea
    monkeypatch.setenv("ES_VULNS_WRITER_API_KEY", "some-key")
    monkeypatch.setenv("ES_URL", "http://localhost:9200")
    assert nd.es_client("ES_VULNS_WRITER_API_KEY") is not None


def test_es_client_optional_missing_is_none_not_fallback(monkeypatch):
    # metricile degradeaza elegant: cheie lipsa -> None (nu ES_API_KEY, nu exceptie)
    monkeypatch.delenv("ES_METRICS_WRITER_API_KEY", raising=False)
    monkeypatch.setenv("ES_API_KEY", "read-only-key")
    assert nd.es_client_optional("ES_METRICS_WRITER_API_KEY") is None


def test_iter_sbom_components_skips_incomplete():
    sbom = {"components": [
        {"type": "plugin", "name": "a", "version": "1.0"},
        {"type": "plugin", "name": "b"},            # fara versiune -> sarit
        {"type": "", "name": "c", "version": "1.0"},  # fara tip -> sarit
        "nu-e-dict",                                   # sarit
    ]}
    out = list(nd.iter_sbom_components(sbom))
    assert out == [("plugin", "a", "1.0")]

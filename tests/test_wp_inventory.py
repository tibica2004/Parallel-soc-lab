"""Colectorul de inventar WordPress (faza 18, bucata 2): parsarea iesirii WP-CLI
si construirea documentului. Functii pure, fara ssh si fara Elasticsearch."""
import json

import wp_inventory as W


def test_parse_plugin_json():
    raw = json.dumps([
        {"name": "akismet", "version": "5.0", "status": "active"},
        {"name": "hello", "version": "1.7.2", "status": "inactive"},
        {"version": "1.0"},          # fara name -> sarit
    ])
    out = W.parse_plugin_json(raw)
    assert [p["name"] for p in out] == ["akismet", "hello"]
    assert out[0]["status"] == "active"


def test_parse_plugin_json_invalid():
    assert W.parse_plugin_json("nu e json") == []
    assert W.parse_plugin_json("") == []
    assert W.parse_plugin_json(json.dumps({"nu": "lista"})) == []


def test_build_doc_adauga_core_si_valideaza():
    plugins = [{"name": "akismet", "version": "5.0", "status": "active"},
               {"name": "rau!", "version": "1.0", "status": "active"},   # slug invalid -> sarit
               {"name": "hello", "version": "x", "status": "inactive"}]  # versiune invalida -> sarit
    doc = W.build_doc("web-prod", "7.1.3", plugins, "2026-10-22T10:00:00+00:00")
    assert doc["host"] == "web-prod" and doc["collected_by"] == "wp_inventory"
    comps = {c["component"]: c for c in doc["components"]}
    assert set(comps) == {"core", "akismet"}            # doar valide, nucleul inclus
    assert comps["core"]["version"] == "7.1.3" and comps["core"]["status"] == "active"
    assert comps["akismet"]["status"] == "active"
    assert doc["component_count"] == 2


def test_build_doc_se_potriveste_cu_motorul_de_expunere():
    import exposure as E
    doc = W.build_doc("web-prod", "7.1.3",
                      [{"name": "akismet", "version": "5.0", "status": "active"}],
                      "2026-10-22T10:00:00+00:00")
    # documentul construit se citeste inapoi exact de motorul de expunere
    assert E.installed_from_doc(doc) == {"core": "7.1.3", "akismet": "5.0"}
    vuln = E.vulnerable_components(E.installed_from_doc(doc))
    assert any(v["component"] == "core" for v in vuln)   # 7.1.3 < 7.1.4 (exemplu de laborator)

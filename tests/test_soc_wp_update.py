"""Partile pure din deploy/web-prod/soc-wp-update.py (fara wp-cli, fara retea)."""
import importlib.util
from pathlib import Path

import pytest

_P = Path(__file__).resolve().parent.parent / "deploy" / "web-prod" / "soc-wp-update.py"
_spec = importlib.util.spec_from_file_location("soc_wp_update", _P)
wpu = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wpu)

TS = "2026-10-28T02:00:00+00:00"


def test_conf_fara_evaluare_de_shell():
    c = wpu.parse_conf("# comentariu\nAPPLY=1\nPLUGINS=\"akismet hello-dolly\"\nX=$(id)\n")
    assert c == {"APPLY": "1", "PLUGINS": "akismet hello-dolly", "X": "$(id)"}


def test_lista_aprobata_accepta_spatiu_si_virgula():
    assert wpu.approved("akismet, hello-dolly  classic_editor") == ["akismet", "hello-dolly",
                                                                     "classic_editor"]
    assert wpu.approved("") == []


@pytest.mark.parametrize("bad", ["akismet;id", "../x", "a b$(id)", "--all"])
def test_lista_aprobata_respinge_slug_invalid(bad):
    with pytest.raises(ValueError):
        wpu.approved(bad)


def test_plugin_disponibil_neaplicat():
    rows = [{"name": "akismet", "version": "5.7.2", "update_version": "5.8"}]
    assert wpu.records("plugin", rows, False, "web-prod", TS) == [{
        "ts": TS, "host": "web-prod", "action": "wp_update_available",
        "component_type": "plugin", "target": "akismet", "old": "5.7.2", "new": "5.8",
        "applied": False}]


def test_core_disponibil_pastreaza_versiunea_instalata():
    rows = [{"version_installed": "7.1.3", "version": "7.1.4", "update_type": "minor"}]
    r = wpu.records("core", rows, False, "web-prod", TS)[0]
    assert (r["target"], r["old"], r["new"], r["action"]) == ("core", "7.1.3", "7.1.4",
                                                              "wp_update_available")


def test_core_aplicat():
    r = wpu.records("core", [{"version_before": "7.1.3", "version": "7.1.4"}], True,
                    "web-prod", TS)[0]
    assert (r["old"], r["new"], r["action"], r["applied"]) == ("7.1.3", "7.1.4", "wp_update",
                                                               True)


def test_wp_json_mesaj_de_succes_devine_lista_goala(monkeypatch):
    monkeypatch.setattr(wpu, "wp", lambda *a: "Success: WordPress is at the latest version.\n")
    assert wpu.wp_json("core", "check-update") == []
    monkeypatch.setattr(wpu, "wp", lambda *a: '[{"name":"akismet"}]')
    assert wpu.wp_json("plugin", "list") == [{"name": "akismet"}]

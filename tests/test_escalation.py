"""Pragul implicit de escaladare pe incredere."""
import importlib
import os


def test_low_conf_implicit_90(monkeypatch):
    monkeypatch.delenv("ESC_LOW_CONF", raising=False)
    import escalation
    importlib.reload(escalation)
    assert escalation.LOW_CONF == 90

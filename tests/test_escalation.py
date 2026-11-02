"""Pragul implicit de escaladare pe incredere."""
import importlib
import os


def test_low_conf_implicit_90(monkeypatch):
    monkeypatch.delenv("ESC_LOW_CONF", raising=False)
    import escalation
    importlib.reload(escalation)
    assert escalation.LOW_CONF == 90


# --- podeaua 4: serverul web a pornit un proces (pasul 6.1) ------------------------------
from escalation import web_exec_floor


def test_podea_web_exec():
    assert web_exec_floor(True, "apache2", None)          # alerta RCE: sh cu parinte apache2
    assert web_exec_floor(True, "dash", None)             # finding dash -> whoami ca www-data
    assert web_exec_floor(True, "/usr/bin/dash", None)
    assert not web_exec_floor(True, "dash", "tiberiu")    # wp-cli prin sudo -u www-data
    assert not web_exec_floor(True, "python3", None)      # soc-wp-update (systemd)
    assert not web_exec_floor(False, "apache2", None)     # alt utilizator
    assert not web_exec_floor(True, None, None)

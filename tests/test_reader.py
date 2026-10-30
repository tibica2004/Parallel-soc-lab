"""Pasul 1b: gate-ul soc-reader (lista alba exacta) si clientul reader.py. Gate-ul ruleaza
local cu SSH_ORIGINAL_COMMAND; comenzile refuzate nu executa nimic."""
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import reader as R
import wp_inventory as W

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "deploy" / "web-prod" / "soc-reader" / "soc-reader-gate"
INSTALL = ROOT / "deploy" / "web-prod" / "soc-reader" / "install.sh"


def gate(cmd: str):
    env = {"PATH": "/usr/bin:/bin", "SSH_ORIGINAL_COMMAND": cmd}
    return subprocess.run(["bash", str(GATE)], env=env, capture_output=True, text=True, timeout=20)


# ---------------- lista alba: o singura sursa ----------------

def _gate_patterns() -> set[str]:
    return set(re.findall(r'^\s+"([^"]+)"\)\s*$', GATE.read_text(), re.M))


def test_gate_si_clientul_au_aceeasi_lista():
    patterns = _gate_patterns()
    assert {c.value for c in R.ReaderCommand} == patterns
    # exceptia rsync e separata (prefix + rrsync), nu o comanda exacta
    assert '"rsync --server --sender "*)' in GATE.read_text()


def test_gate_executa_argumente_fixe_nu_textul_primit():
    body = GATE.read_text()
    assert "exec $cmd" not in body and 'exec "$cmd"' not in body and "eval" not in body
    assert "exec rrsync -ro /var/www/html" in body


# ---------------- comportamentul gate-ului ----------------

@pytest.mark.parametrize("cmd", [
    "", "ls /", "cat /etc/shadow", "cat /etc/passwd; id", "cat /etc/passwd && id",
    "cat  /etc/passwd", "cat /etc/passwd\n", "sha256sum /etc/crontab /etc/cron.d/x",
    "stat /etc/shadow", "ls -la /var/www/html/../../etc",
    "rsync --server -logDtpre.iLsfxCIvu . /var/www/html",          # primire (upload): refuzat
    "rsync --server --sender -vlogDtpre.iLsfxCIvu . /var/www/html/$(id)",
    "rsync --server --sender -e.LsfxCIvu . /var/www/html;id",
    "bash -i", "sh -c id", "/usr/local/bin/soc-reader-gate",
])
def test_gate_refuza(cmd):
    r = gate(cmd)
    assert r.returncode == 1 and "DENIED" in r.stderr and r.stdout == ""


def test_gate_permite_exact():
    r = gate("cat /etc/passwd")
    assert r.returncode == 0 and "root:" in r.stdout


@pytest.mark.skipif(not shutil.which("ps"), reason="ps lipseste")
def test_gate_permite_ps():
    r = gate("ps -eo pid,ppid,user,etimes,cmd")
    assert r.returncode == 0 and "PID" in r.stdout


def test_install_nu_atinge_sshd_si_blocheaza_contul():
    sh = INSTALL.read_text()
    code = "\n".join(l for l in sh.splitlines() if not l.lstrip().startswith("#"))
    assert 'restrict,command="/usr/local/bin/soc-reader-gate"' in code
    assert "passwd -l soc-reader" in code and "sshd_config" not in code and "systemctl" not in code
    # authorized_keys al lui root: contul nu-si poate schimba comanda fortata
    assert 'install -d -o root -g root -m 755 "$H" "$H/.ssh"' in code


# ---------------- clientul ----------------

def test_argv_ssh_strict_si_doar_din_enumerare():
    argv = R.ssh_argv(R.ReaderCommand.CRON_HASH)
    assert argv[0] == "ssh" and argv[-1] == "sha256sum /etc/crontab /etc/cron.d/*"
    for opt in ("BatchMode=yes", "IdentitiesOnly=yes", "StrictHostKeyChecking=yes"):
        assert opt in argv
    with pytest.raises(TypeError):
        R.ssh_argv("cat /etc/shadow")


def test_run_esec_ridica(monkeypatch):
    monkeypatch.setattr(R.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "DENIED\n"))
    with pytest.raises(R.ReaderError, match="DENIED"):
        R.run(R.ReaderCommand.PASSWD)

    def slow(*a, **k):
        raise subprocess.TimeoutExpired("ssh", 20)
    monkeypatch.setattr(R.subprocess, "run", slow)
    with pytest.raises(R.ReaderError, match="timeout"):
        R.run(R.ReaderCommand.PASSWD)


def test_parse_sha256sum():
    out = ("a" * 64 + "  /etc/crontab\n" + "b" * 64 + "  /etc/cron.d/soc-canary\n"
           "sha256sum: /etc/cron.d/x: Permission denied\n" + "zz  /nu\n")
    assert R.parse_sha256sum(out) == {"/etc/crontab": "a" * 64, "/etc/cron.d/soc-canary": "b" * 64}


# ---------------- wp_inventory din SBOM, nu prin ssh ----------------

def test_inventar_din_sbom():
    comps = [{"type": "wp_core", "name": "wordpress", "version": "7.1.3"},
             {"type": "plugin", "name": "akismet", "version": "5.7.2", "sha256": "x"},
             {"type": "theme", "name": "t", "version": "1"}, {"type": "plugin"}, "gunoi"]
    core, plugins = W.from_sbom(comps)
    assert core == "7.1.3" and plugins == [{"name": "akismet", "version": "5.7.2", "status": ""}]


def test_codul_soc_nu_mai_intra_ca_tiberiu():
    # D1: wp_inventory nu mai ruleaza nimic pe web-prod (nici ssh, nici WP-CLI)
    assert not hasattr(W, "subprocess") and not hasattr(W, "SSH_TARGET") and not hasattr(W, "_ssh")



def test_regula_kibana_pentru_refuzuri():
    import sensor_rules as S
    p = S.kibana_payload("soc-reader-denied")
    assert S.is_sensor_alert({"kibana.alert.rule.rule_id": "soc-reader-denied"})
    assert '(log.syslog.appname : "soc-reader-gate" or process.name : "soc-reader-gate")' in p["query"]
    assert "logs-system.auth-*" in p["index"] and p["threat"][0]["tactic"]["id"] == "TA0008"
    assert 'logger -t soc-reader-gate -p auth.warning -- "denied' in GATE.read_text()

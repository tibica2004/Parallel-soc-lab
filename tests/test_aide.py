"""Pasul 3.E: AIDE. Wrapper-ul de pe web-prod (fara aide real, fara dpkg real), regula si
faptele senzorului. Fara retea."""
import importlib.machinery
import importlib.util
import json
import subprocess
from datetime import datetime
from pathlib import Path

import pytest

import honeytokens as H
import sensor_rules as S
from escalation import should_escalate  # noqa: F401  (motivul vine prin is_sensor_alert)

ROOT = Path(__file__).resolve().parents[1]
AIDE_DIR = ROOT / "deploy" / "web-prod" / "aide"


def _load():
    loader = importlib.machinery.SourceFileLoader("soc_aide_check", str(AIDE_DIR / "soc-aide-check"))
    spec = importlib.util.spec_from_loader("soc_aide_check", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


A = _load()

REPORT = """Start timestamp: 2026-10-31 03:30:01 +0000 (AIDE 0.18.6)
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:\t8135
  Added entries:\t\t1
  Removed entries:\t\t1
  Changed entries:\t\t3

---------------------------------------------------
Added entries:
---------------------------------------------------

f++++++++++++++++: /var/www/html/wp-content/plugins/x/shell.php

---------------------------------------------------
Removed entries:
---------------------------------------------------

f----------------: /usr/bin/old tool

---------------------------------------------------
Changed entries:
---------------------------------------------------

f   ...    .C... : /usr/bin/ssh
f   ...    .C... : /etc/ld.so.cache
d   ...    m.... : /etc/cron.d

---------------------------------------------------
Detailed information about changes:
---------------------------------------------------

File: /usr/bin/ssh
  SHA256    : AAAA | BBBB
"""


# ---------------- raportul ----------------

def test_parseaza_sectiunile_nu_si_rezumatul():
    d = A.parse_report(REPORT)
    assert d == {"added": ["/var/www/html/wp-content/plugins/x/shell.php"],
                 "removed": ["/usr/bin/old tool"],
                 "changed": ["/usr/bin/ssh", "/etc/ld.so.cache", "/etc/cron.d"]}


def test_detaliile_nu_sunt_cai():
    assert "/usr/bin/ssh" in A.parse_report(REPORT)["changed"]
    assert all("SHA256" not in p for v in A.parse_report(REPORT).values() for p in v)


# ---------------- explicat / neexplicat (codul decide) ----------------

def test_fara_activitate_de_pachete_totul_e_neexplicat():
    d = A.parse_report(REPORT)
    exp, unexp = A.classify(d, set(), {"/usr/bin/ssh": {"openssh-client"}})
    assert exp == [] and len(unexp) == 5


def test_pachet_actualizat_explica_doar_fisierele_lui():
    d = A.parse_report(REPORT)
    own = {"/usr/bin/ssh": {"openssh-client"}, "/etc/cron.d": {"cron"}}
    exp, unexp = A.classify(d, {"openssh-client", "libc-bin"}, own)
    # ssh e al pachetului actualizat; ld.so.cache e generat (exista activitate de pachete)
    assert set(exp) == {"/usr/bin/ssh", "/etc/ld.so.cache"}
    # PHP nou in plugins, binar sters fara pachet, /etc/cron.d al unui pachet NEactualizat
    assert set(unexp) == {"/var/www/html/wp-content/plugins/x/shell.php", "/usr/bin/old tool", "/etc/cron.d"}


def test_pachetele_din_dpkg_log_dupa_ultima_rulare(tmp_path, monkeypatch):
    log = tmp_path / "dpkg.log"
    log.write_text("2026-10-29 06:00:00 status installed vechi:amd64 1\n"
                   "2026-10-30 06:18:49 status half-configured libc-bin:amd64 2.39\n"
                   "2026-10-30 06:18:49 status installed libc-bin:amd64 2.39\n"
                   "linie stricata\n"
                   "2026-10-30 07:00:00 status installed openssh-client:amd64 9.6\n")
    monkeypatch.setattr(A, "DPKG_LOGS", (str(tmp_path / "lipsa"), str(log)))
    assert A.updated_packages(datetime(2026, 10, 30, 3, 25)) == {"libc-bin", "openssh-client"}
    assert A.updated_packages(None) == set()


def test_proprietarii_dpkg(monkeypatch):
    out = ("openssh-client: /usr/bin/ssh\n"
           "diversion by dash from: /bin/sh\n"
           "cron, cron-daemon-common: /etc/cron.d\n")
    monkeypatch.setattr(A.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, out, "nu"))
    assert A.owners(["/usr/bin/ssh", "/etc/cron.d", "/x"]) == {
        "/usr/bin/ssh": {"openssh-client"}, "/etc/cron.d": {"cron", "cron-daemon-common"}}


# ---------------- fluxul complet ----------------

@pytest.fixture
def env(tmp_path, monkeypatch):
    d = tmp_path / "soc-aide"
    for k, v in {"DIR": d, "DB": d / "aide.db.gz", "NEW": d / "aide.db.new.gz", "STATE": d / "state.json"}.items():
        monkeypatch.setattr(A, k, str(v))
    logged = []
    monkeypatch.setattr(A, "log", logged.append)
    monkeypatch.setattr(A, "DPKG_LOGS", ())
    monkeypatch.setattr(A, "owners", lambda paths: {})
    calls = []

    def fake(rc, out=""):
        def aide(mode):
            calls.append(mode)
            Path(A.NEW).write_text("db")
            return subprocess.CompletedProcess(["aide"], rc, out, "")
        monkeypatch.setattr(A, "aide", aide)
    return logged, calls, fake


def test_prima_rulare_face_baza(env):
    logged, calls, fake = env
    fake(0)
    assert A.main() == 0
    assert calls == ["--init"] and logged == [{"event": "aide_init"}]
    assert Path(A.DB).exists() and not Path(A.NEW).exists() and Path(A.STATE).exists()


def test_fara_diferente_ok_si_baza_promovata(env):
    logged, calls, fake = env
    fake(0)
    A.main()
    A.main()
    assert calls == ["--init", "--update"] and logged[-1] == {"event": "aide_ok"}
    assert not Path(A.NEW).exists()


def test_diferente_neexplicate_alerta_plafonata(env):
    logged, calls, fake = env
    fake(0)
    A.main()
    fake(5, REPORT)
    assert A.main() == 0
    ev = logged[-1]
    assert ev["event"] == "aide_unexplained" and ev["unexplained_count"] == 5
    assert ev["added"] == 1 and ev["removed"] == 1 and ev["changed"] == 3
    assert len(ev["unexplained"]) <= A.MAX_PATHS
    assert not Path(A.NEW).exists()      # fiecare schimbare raportata o singura data


def test_eroare_aide_nu_promoveaza(env):
    logged, calls, fake = env
    fake(0)
    A.main()
    fake(17)
    assert A.main() == 1 and logged[-1]["event"] == "aide_error"


def test_diferente_raportate_dar_neparsate_sunt_eroare(env):
    logged, calls, fake = env
    fake(0)
    A.main()
    fake(4, "format necunoscut")
    assert A.main() == 1 and logged[-1] == {"event": "aide_error", "mode": "parse", "rc": 4,
                                            "stderr": "raport neparsat"}


# ---------------- configuratia ----------------

def test_conf_acopera_g9_si_exclude_momelile():
    conf = (AIDE_DIR / "soc-aide.conf").read_text()
    for p in ("/etc SOC", "/usr/sbin SOC", "/usr/local/bin SOC", "/var/www/html SOC"):
        assert p in conf
    for p in ("!/var/www/html/wp-content/uploads", "!/var/www/html/wp-content/cache",
              r"!/var/www/html/\.env\.bak$", r"!/var/www/html/backup\.sql$"):
        assert p in conf
    assert "sha256" in conf and "report_format=plain" in conf


def test_install_fara_aide_common():
    sh = (AIDE_DIR / "install.sh").read_text()
    assert "--no-install-recommends aide" in sh and "--config-check" in sh


# ---------------- regula si faptele ----------------

def _alert(msg):
    return {"kibana.alert.rule.rule_id": "soc-aide-change", "message": msg}


def test_regula_e_senzor_si_payload_valid():
    assert S.is_sensor_alert(_alert("x"))
    p = S.kibana_payload("soc-aide-change")
    assert p["severity"] == "high" and p["threat"][0]["tactic"]["id"] == "TA0003"
    assert 'message : ("aide_unexplained" or "aide_error")' in p["query"]


def test_fapte_aide_validate_si_plafonate():
    msg = json.dumps({"event": "aide_unexplained", "added": 1, "removed": 0, "changed": 30,
                      "unexplained_count": 31, "explained_count": 0,
                      "unexplained": [f"/etc/f{i}" for i in range(30)], "packages": []})
    f = S.sensor_facts(_alert(msg))
    assert f["sensor"] == "aide" and f["unexplained_count"] == 31 and len(f["unexplained"]) == 20


@pytest.mark.parametrize("msg", [
    "nu e json", json.dumps({"event": "aide_ok"}),
    json.dumps({"event": "aide_unexplained", "added": -1, "removed": 0, "changed": 0,
                "unexplained_count": 0, "explained_count": 0, "unexplained": []}),
    json.dumps({"event": "aide_unexplained", "added": 1, "removed": 0, "changed": 0,
                "unexplained_count": 1, "explained_count": 0, "unexplained": ["relativ"]}),
])
def test_fapte_aide_invalide(msg):
    assert S.aide_facts(_alert(msg)) is None


def test_eroarea_aide_e_fapt():
    assert S.aide_facts(_alert(json.dumps({"event": "aide_error", "rc": 17})))["event"] == "aide_error"


def test_wpconfig_exclude_aide():
    assert '"/usr/bin/aide"' in H.RULES["soc-honey-wpconfig-read"]["query"]

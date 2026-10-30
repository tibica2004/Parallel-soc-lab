"""Pasul 3.C: momelile WordPress/MySQL. Reguli in multimea inchisa, regulile auditd
corecte pentru kernel, config_error pentru IP-urile proprii/benign. Fara model si fara ES."""
import re
import sys
import types
from pathlib import Path

import pytest

import honeytokens as H
import hunt_path
import orchestrator
from schemas import ActionType as A, Case, EscalationReason as R, Verdict
from tests.test_tier1_tier2 import CID, FakeHunt, _alert, rec  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parents[1]
WP_RULES = ("soc-honey-wpconfig-read", "soc-honey-mysql-user", "soc-honey-wp-login",
            "soc-honey-backup-sql-http", "soc-honey-backup-sql-read", "soc-honey-robots-trap")


def V(cls="benign", conf=99):
    return Verdict(investigation_id="i", source_path="fast", entity_type="host", entity_id="web-prod",
                   classification=cls, confidence=conf, rarity_score=0.0, model_id="m")


def _a(rid, ip=None, nested=False):
    a = {"kibana.alert.rule.rule_id": rid}
    if ip is not None:
        a.update({"source": {"ip": ip}} if nested else {"source.ip": ip})
    return a


# ---------------- regulile ----------------

@pytest.mark.parametrize("rid", WP_RULES)
def test_regulile_wp_sunt_honeytoken(rid):
    assert rid in H.RULES and H.is_honeytoken(_a(rid))


@pytest.mark.parametrize("rid", WP_RULES)
def test_payload_kibana_critical_cu_tactica(rid):
    p = H.kibana_payload(rid)
    assert p["rule_id"] == rid and p["severity"] == "critical" and p["tags"] == [H.TAG]
    assert p["threat"][0]["tactic"]["id"].startswith("TA")
    assert p["enabled"] is True


def test_cel_putin_sase_reguli_honeytoken():
    assert len(H.RULES) >= 6


def test_citirile_sunt_pe_auditd_nu_pe_defend():
    # A3: Defend (eBPF) nu emite citiri
    for rid in ("soc-honey-wpconfig-read", "soc-honey-backup-sql-read"):
        assert H.RULES[rid]["index"] == ["logs-auditd_manager.auditd-*"]
        assert "/opt/Elastic/" in H.RULES[rid]["query"]


def test_regulile_nu_contin_secrete_sau_valori_aleatoare():
    # parola momeala se genereaza pe host si nu e folosita nicaieri, nici in reguli
    for rid in WP_RULES:
        assert "PASSWORD" not in H.RULES[rid]["query"].upper()


def test_robots_trap_acopera_ambele_cai():
    q = H.RULES["soc-honey-robots-trap"]["query"]
    assert "url.path : /wp-admin-old*" in q and "url.path : /db-backup*" in q


# ---------------- regulile auditd ----------------

def test_auditd_un_singur_exe_per_regula():
    # kernelul refuza a doua conditie exe in aceeasi regula
    for line in H.AUDITD_RULES:
        assert line.count("-F exe=") <= 1 and "exe!=" not in line


def test_auditd_excluderile_inaintea_regulii_always():
    rules = list(H.AUDITD_RULES)
    always = next(i for i, r in enumerate(rules) if r.startswith("-a always") and H.WP_CONFIG in r)
    nevers = [i for i, r in enumerate(rules) if r.startswith("-a never") and H.WP_CONFIG in r]
    assert nevers and max(nevers) < always
    assert rules[always].endswith(f"-k {H.WPCONFIG_KEY}")


def test_auditd_exclude_binarele_web():
    joined = "\n".join(H.AUDITD_RULES)
    for exe in H.WPCONFIG_LEGIT_EXE:
        assert f"-F exe={exe}" in joined
    assert any(f"-w {H.DECOY_SQL} -p r -k {H.SQL_KEY}" == r for r in H.AUDITD_RULES)


# ---------------- config_error ----------------

@pytest.mark.parametrize("ip", ["192.168.10.138", "172.30.6.249", "127.0.0.1", "192.168.10.150"])
def test_ip_propriu_sau_benign_e_config_error(ip):
    assert H.is_config_error(_a("soc-honey-robots-trap", ip))
    assert H.escalation_reason(_a("soc-honey-robots-trap", ip)) is R.HONEYTOKEN_CONFIG_ERROR


def test_ip_imbricat():
    assert H.is_config_error(_a("soc-honey-backup-sql-http", "192.168.10.150", nested=True))


@pytest.mark.parametrize("ip", ["172.30.6.133", "203.0.113.5", None, "nu-e-ip", 42])
def test_ip_strain_lipsa_sau_invalid_ramane_honeytoken(ip):
    a = _a("soc-honey-backup-sql-http", ip)
    assert not H.is_config_error(a)
    assert H.escalation_reason(a) is R.HONEYTOKEN


def test_alerta_obisnuita_fara_motiv():
    assert H.escalation_reason(_a("altceva", "192.168.10.138")) is None
    assert not H.is_config_error(_a("altceva", "192.168.10.138"))


def test_ip_urile_din_env(monkeypatch):
    monkeypatch.setenv("BENIGN_GEN_IPS", "10.9.9.9, gunoi")
    monkeypatch.setenv("WP_SELF_IPS", "")
    assert H.is_config_error(_a("soc-honeytoken-http", "10.9.9.9"))
    assert not H.is_config_error(_a("soc-honeytoken-http", "192.168.10.150"))


def _benign_model(monkeypatch):
    monkeypatch.setitem(sys.modules, "fast_path", types.SimpleNamespace(
        build_fast_path=lambda: types.SimpleNamespace(invoke=lambda inp, config=None: {
            "verdict": V("benign", 99), "narrative": "", "context": {"pair_in_baseline": True}}),
        lookup_asset=lambda h: {}))


def test_orchestrator_config_error_escaladeaza_fara_motiv_honeytoken(monkeypatch, rec):
    _benign_model(monkeypatch)
    orchestrator.process_alerts([_alert(**{"kibana.alert.rule.rule_id": "soc-honey-robots-trap",
                                           "source.ip": "192.168.10.150"})],
                                orchestrator.BoundedSeen(), t2_limit=0, hunt=FakeHunt())
    esc = rec[0][1]["escalation"]
    assert esc.escalate and esc.reasons == [R.HONEYTOKEN_CONFIG_ERROR]


def test_orchestrator_ip_strain_ramane_honeytoken(monkeypatch, rec):
    _benign_model(monkeypatch)
    orchestrator.process_alerts([_alert(**{"kibana.alert.rule.rule_id": "soc-honey-robots-trap",
                                           "source.ip": "172.30.6.133"})],
                                orchestrator.BoundedSeen(), t2_limit=0, hunt=FakeHunt())
    assert rec[0][1]["escalation"].reasons == [R.HONEYTOKEN]


def test_orchestrator_model_cazut_config_error(rec):
    hunt = FakeHunt()
    orchestrator.process_alerts([_alert(**{"kibana.alert.rule.rule_id": "soc-honey-backup-sql-http",
                                           "source.ip": "127.0.0.1"})],
                                orchestrator.BoundedSeen(), model_ok=False, t2_limit=1, hunt=hunt)
    (inp, _, _), = hunt.runs
    assert R.HONEYTOKEN_CONFIG_ERROR in inp["case"].escalation_reasons
    assert R.HONEYTOKEN not in inp["case"].escalation_reasons


def test_tier2_nu_inchide_config_error(monkeypatch):
    monkeypatch.setattr(hunt_path, "prefetch_context", lambda x: {})
    case = Case(chain_id=CID, origin="tier1_alert", host="web-prod", rule_name="R",
                escalation_reasons=[R.HONEYTOKEN_CONFIG_ERROR], rarity_score=1.0)
    v = hunt_path.node_finalize({"case": case, "investigation_id": "i", "merged_draft": {
        "classification": "benign", "confidence": 95, "proposed_action": "none"}})["verdict"]
    assert v.classification.value == "suspicious" and v.proposed_action is A.ESCALATE_HUMAN


def test_config_error_nu_pagineaza_ca_intruziune():
    import notify
    assert R.HONEYTOKEN_CONFIG_ERROR.value not in notify._CRITICAL_REASON_VALUES


# ---------------- artefactele de pe web-prod ----------------

def test_mu_plugin_nu_logheaza_numele_primit():
    php = (ROOT / "deploy/web-prod/soc-honey.php").read_text()
    assert "wp_login_failed" in php and "'wp_login'" in php
    assert "FILTER_VALIDATE_IP" in php and "defined( 'ABSPATH' ) || exit;" in php
    # singurul error_log scrie constante + IP validat, nu $username / $user_login
    calls = re.findall(r"error_log\((.*)\);", php)
    assert len(calls) == 1 and "$username" not in calls[0] and "$user_login" not in calls[0]
    for bad in ("eval(", "exec(", "system(", "shell_exec", "passthru", "base64_decode"):
        assert bad not in php


def test_scriptul_nu_creeaza_conturi_si_nu_tradeaza_momeala():
    sh = (ROOT / "deploy/web-prod/honeytokens-wp.sh").read_text()
    code = "\n".join(l for l in sh.splitlines() if not l.lstrip().startswith("#"))
    assert "CREATE USER" not in code.upper() and "wp user create" not in code
    assert "systemctl" not in code
    # copiile de siguranta in afara webroot (wp-config.php.pre-honey in webroot ar fi servit ca text)
    assert "PRE=/root/" in code
    # markerul intern nu ajunge in robots.txt sau wp-config.php
    assert '"$MARK" >> "$WEB/robots.txt"' not in code and "-v m=" not in code


def test_backup_exclude_contine_momelile():
    ex = (ROOT / "deploy/web-prod/soc-backup.exclude").read_text().split()
    assert "var/www/html/.env.bak" in ex and "var/www/html/backup.sql" in ex


def test_documentatia_auditd_e_la_zi():
    doc = (ROOT / "deploy/web-prod/auditd-fim.md").read_text()
    assert all(r in doc for r in H.AUDITD_RULES)

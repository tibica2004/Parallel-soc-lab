"""Alertele native Elastic Defend: recunoastere, normalizare, fapte validate,
escaladare. Fara ES si fara model. Structura copiata dupa o alerta reala de
behavior din laborator (valori de test)."""

import pytest
from pydantic import ValidationError

import defend_native as dn
from escalation import should_escalate
from schemas import EscalationReason

from test_should_escalate import _v


def native_behavior(**over):
    a = {
        "@timestamp": "2026-10-13T10:41:19Z",
        "host": {"name": "web-prod"},
        "event": {"dataset": "endpoint.alerts", "module": "endpoint", "code": "behavior",
                  "kind": "signal", "risk_score": 99, "type": ["info", "allowed"]},
        "kibana.alert.rule.name": "Malicious Behavior Detection Alert: Payload Execution by Web Server",
        "kibana.alert.original_event.dataset": "endpoint.alerts",
        "process": {"name": "dash", "entity_id": "qcryNvcdL63", "executable": "/usr/bin/dash",
                    "command_line": "sh -c -- id", "user": {"name": "www-data"},
                    "parent": {"name": "apache2", "entity_id": "Sde+BEiKWx8"}},
        "user": {"name": "www-data"},
        "rule": {"name": "Payload Execution by Web Server", "ruleset": "production",
                 "description": "This rule detects when a web server executes a payload."},
        "threat": [
            {"framework": "MITRE ATT&CK",
             "technique": [{"id": "T1505", "name": "Server Software Component",
                            "subtechnique": [{"id": "T1505.003", "name": "Web Shell"}]}],
             "tactic": {"id": "TA0003", "name": "Persistence"}},
            {"framework": "MITRE ATT&CK",
             "technique": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
             "tactic": {"id": "TA0001", "name": "Initial Access"}},
        ],
    }
    a.update(over)
    return a


EQL_ALERT = {
    "host": {"name": "web-prod"},
    "event": {"dataset": "endpoint.events.process", "kind": "signal"},
    "kibana.alert.rule.name": "RCE: Web server spawns shell",
    "process": {"name": "dash", "parent": {"name": "apache2"}},
    "user": {"name": "www-data"},
}


def test_recunoastere():
    assert dn.is_native(native_behavior())
    assert not dn.is_native(EQL_ALERT)
    assert dn.detection(EQL_ALERT) is None
    # forma plata (cum vin unele campuri din .alerts-security) si dataset doar in original_event
    assert dn.is_native({"kibana.alert.original_event.dataset": "endpoint.alerts"})
    assert dn.is_native({"event.dataset": ["endpoint.alerts"]})


def test_faptele_behavior():
    d = dn.detection(native_behavior())
    assert d.kind is dn.NativeKind.BEHAVIOR
    assert d.mode is dn.NativeMode.DETECTED
    assert d.vendor_rule == "Payload Execution by Web Server"
    assert d.ruleset == "production"
    assert d.techniques == ["T1505", "T1505.003", "T1190"]
    assert d.tactics == ["TA0003", "TA0001"]
    assert d.risk_score == 99


@pytest.mark.parametrize("code,kind", [
    ("malicious_file", dn.NativeKind.MALWARE),
    ("memory_signature", dn.NativeKind.MEMORY),
    ("shellcode_thread", dn.NativeKind.SHELLCODE),
    ("ransomware", dn.NativeKind.RANSOMWARE),
    ("ceva_nou", dn.NativeKind.OTHER),
    (None, dn.NativeKind.OTHER),
])
def test_tipul_din_event_code(code, kind):
    a = native_behavior()
    a["event"]["code"] = code
    assert dn.detection(a).kind is kind


def test_prevent_si_necunoscut():
    a = native_behavior()
    a["event"]["type"] = ["info", "denied"]
    assert dn.detection(a).mode is dn.NativeMode.PREVENTED
    a["event"]["type"] = "info"
    assert dn.detection(a).mode is dn.NativeMode.UNKNOWN


def test_id_uri_attck_invalide_sunt_ignorate():
    a = native_behavior(threat=[{"technique": [{"id": "T1505'; DROP"}, {"id": 7}, {"id": "T1059.004"}],
                                 "tactic": {"id": "TA0002 OR 1=1"}}, "nu e dict"])
    d = dn.detection(a)
    assert d.techniques == ["T1059.004"]
    assert d.tactics == []


def test_risk_score_invalid_devine_none():
    a = native_behavior()
    a["event"]["risk_score"] = 1000
    assert dn.detection(a).risk_score is None
    a["event"]["risk_score"] = "99"
    assert dn.detection(a).risk_score is None


def test_texte_limitate():
    a = native_behavior(rule={"name": "x" * 500, "description": "d " * 1000, "ruleset": "r" * 100})
    d = dn.detection(a)
    assert len(d.vendor_rule) == 200
    assert len(d.description) <= dn.MAX_DESCRIPTION
    assert len(d.ruleset) == 40


def test_modelul_refuza_campuri_si_valori_straine():
    ok = dn.detection(native_behavior()).model_dump()
    with pytest.raises(ValidationError):
        dn.NativeDetection(**ok, extra="x")
    with pytest.raises(ValidationError):
        dn.NativeDetection(**{**ok, "techniques": ["T15"]})
    with pytest.raises(ValidationError):
        dn.NativeDetection(**{**ok, "kind": "inventat"})


def test_normalizare_completeaza_doar_ce_lipseste():
    # alerta de memorie: procesul doar in Target.process
    a = {"event": {"dataset": "endpoint.alerts", "code": "memory_signature"},
         "Target": {"process": {"name": "evil", "executable": "/tmp/evil", "entity_id": "TgtEnt1",
                                "command_line": "/tmp/evil -x", "user": {"name": "bob"},
                                "parent": {"name": "bash", "entity_id": "TgtPar1"}}}}
    out, filled = dn.normalize_fields(a)
    assert out["process"]["name"] == "evil"
    assert out["process"]["parent"]["entity_id"] == "TgtPar1"
    assert out["user"]["name"] == "bob"
    assert set(filled) == set(dn.FALLBACKS)
    assert "process" not in a                      # originalul nu se modifica

    # behavior: process.* exista deja -> nimic suprascris
    b = native_behavior(Target={"process": {"name": "altceva"}})
    out, filled = dn.normalize_fields(b)
    assert out["process"]["name"] == "dash"
    assert filled == []


def test_normalizare_forma_plata():
    a = {"event.dataset": "endpoint.alerts", "process.name": "", "Target.process.name": "evil"}
    out, filled = dn.normalize_fields(a)
    assert "process.name" in filled
    assert out["process.name"] == "evil"


def test_user_din_process_user():
    a = native_behavior()
    del a["user"]
    out, filled = dn.normalize_fields(a)
    assert out["user"]["name"] == "www-data"
    assert filled == ["user.name"]


def test_alerta_nativa_nu_se_inchide_niciodata():
    d = should_escalate(_v("benign", 99), floor_applied=False, pair_in_baseline=True,
                        native_detection=True)
    assert d.escalate is True
    assert d.reasons == [EscalationReason.NATIVE_DETECTION]


def test_alerta_eql_benigna_se_inchide_ca_inainte():
    d = should_escalate(_v("benign", 99), floor_applied=False, pair_in_baseline=True)
    assert d.escalate is False and d.reasons == []


def test_motivul_nativ_se_adauga_la_celelalte():
    d = should_escalate(_v("malicious", 95), floor_applied=False, pair_in_baseline=True,
                        native_detection=True)
    assert d.reasons == [EscalationReason.MALICIOUS, EscalationReason.NATIVE_DETECTION]

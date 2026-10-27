"""Faza 20: reguli de acoperire pentru golurile gasite la testul purple
(OpenCyber -> web-prod). Reguli de prag (threshold) pentru enumerarea de
continut si brute-force-ul pe autentificare, plus suportul de threshold din
builder-ul de payload. Pur: fara ES, fara model, fara retea."""
import honeytokens as H
import sensor_rules as S
from escalation import should_escalate
from schemas import EscalationReason as R, Verdict

THRESHOLD = ("soc-web-content-enum", "soc-http-auth-bruteforce", "soc-ssh-bruteforce")
QUERY_NEW = ("soc-web-sqli-attempt",)
NEW = THRESHOLD + QUERY_NEW
INDICI = {"logs-apache.*", "logs-system.auth-*"}


def test_reguli_noi_in_rules():
    for rid in NEW:
        assert rid in S.RULES


def test_payload_threshold_bine_format():
    # Regulile de prag au tip "threshold" si cheia "threshold" in payload-ul Kibana.
    for rid in THRESHOLD:
        p = S.kibana_payload(rid)
        assert p["type"] == "threshold"
        assert p["threshold"]["field"] == ["source.ip"]
        assert isinstance(p["threshold"]["value"], int) and p["threshold"]["value"] > 0
        assert p["index"][0] in INDICI
        # maparea MITRE trebuie sa existe (altfel kibana_payload ar da KeyError)
        assert p["threat"][0]["technique"][0]["id"] in ("T1595", "T1110")


def test_sqli_e_query_fara_threshold():
    p = S.kibana_payload("soc-web-sqli-attempt")
    assert p["type"] == "query"
    assert "threshold" not in p
    assert p["index"] == ["logs-apache.*"]
    assert p["threat"][0]["technique"][0]["id"] == "T1190"


def test_regulile_query_nu_capata_threshold():
    # Regresie: schimbarea builder-ului nu adauga "threshold" regulilor de tip query.
    for rid in ("soc-yara-webshell", "soc-suricata-webattack"):
        assert "threshold" not in S.kibana_payload(rid)


def test_recunoscute_ca_sensor_alert():
    for rid in NEW:
        a = {"kibana.alert.rule.rule_id": rid}
        assert S.is_sensor_alert(a)


def test_fara_facts_dar_nu_crapa():
    # Regulile noi nu au extractor de fapte (yara/suricata): sensor_facts e None,
    # dar is_sensor_alert ramane True, deci alerta e tot recunoscuta si escaladata.
    for rid in NEW:
        a = {"kibana.alert.rule.rule_id": rid}
        assert S.sensor_facts(a) is None


def test_escaladeaza_prin_sensor_detection():
    # O alerta de la o regula de prag are flagul sensor_detection -> escaladeaza,
    # ca Tier 1 sa nu o inchida singur ca benigna (chiar daca verdictul e benign).
    v = Verdict(investigation_id="i", source_path="fast", entity_type="host", entity_id="web-prod",
                classification="benign", confidence=99, rarity_score=0.0, model_id="m")
    d = should_escalate(v, floor_applied=False, pair_in_baseline=True, sensor_detection=True)
    assert d.escalate
    assert R.SENSOR_DETECTION in d.reasons


def test_mitre_mapari_adaugate():
    assert H.TACTIC["T1595"] == ("TA0043", "Reconnaissance")
    assert H.TACTIC["T1110"] == ("TA0006", "Credential Access")

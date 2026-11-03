"""Reguli comportamentale (pasul 3.A): multime inchisa recunoscuta dupa rule_id,
reguli EQL valide pentru Kibana, escaladare BEHAVIORAL. Fara model, fara Elasticsearch."""
import json

import pytest

import behavioral_rules as B
from escalation import should_escalate
from schemas import EscalationReason as R, Verdict


def V(cls="benign", conf=99):
    return Verdict(investigation_id="i", source_path="fast", entity_type="host",
                   entity_id="web-prod", classification=cls, confidence=conf,
                   rarity_score=0.0, model_id="m")


# ---------------- recunoastere: doar dupa rule_id ----------------

@pytest.mark.parametrize("rid", list(B.RULES))
def test_recunoscut_dupa_rule_id(rid):
    assert B.is_behavioral({"kibana.alert.rule.rule_id": rid})
    assert B.is_behavioral({"kibana": {"alert": {"rule": {"rule_id": rid}}}})


@pytest.mark.parametrize("a", [
    {}, {"kibana.alert.rule.rule_id": None},
    {"kibana.alert.rule.rule_id": "soc-honeytoken-http"},     # alta familie
    # numele/eticheta nu ajung: le poate schimba oricine din interfata
    {"kibana.alert.rule.name": "Comportament", "kibana.alert.rule.tags": [B.TAG]},
])
def test_nerecunoscut(a):
    assert not B.is_behavioral(a)


# ---------------- escaladare: BEHAVIORAL ----------------

def test_benign_sigur_pe_behavioral_escaladeaza():
    d = should_escalate(V("benign", 99), floor_applied=False, pair_in_baseline=True, behavioral=True)
    assert d.escalate and d.reasons == [R.BEHAVIORAL]


def test_fara_behavioral_neschimbat():
    d = should_escalate(V("benign", 99), floor_applied=False, pair_in_baseline=True)
    assert not d.escalate and d.reasons == []


# ---------------- reguli Kibana: forma + tehnici ----------------

@pytest.mark.parametrize("rid", list(B.RULES))
def test_payload(rid):
    p = B.kibana_payload(rid)
    assert p["rule_id"] == rid
    assert p["tags"] == [B.TAG, B.SHADOW_TAG]          # shadow-review pentru calibrare 7z
    assert p["enabled"] and p["severity"] in ("critical", "high")
    assert p["severity"] == B.SEVERITY[rid][0] and p["risk_score"] == B.SEVERITY[rid][1]
    t = p["threat"][0]
    assert t["tactic"]["id"].startswith("TA") and t["technique"][0]["id"].startswith("T")


def test_subtehnici_rezolva():
    # tehnicile cu punct trebuie sa aiba subtechnique corect (TACTIC/PARENT_NAME extinse)
    assert (B.kibana_payload("soc-web-spawns-shell")["threat"][0]["technique"][0]
            ["subtechnique"][0]["id"] == "T1059.004")
    assert (B.kibana_payload("soc-apache-reads-shadow")["threat"][0]["technique"][0]
            ["subtechnique"][0]["id"] == "T1003.008")


# ---------------- reguli EQL: continut si validitate sintactica minima ----------------

def test_tipuri_si_indici():
    r = B.RULES
    for rid in ("soc-web-spawns-shell", "soc-php-written-in-webroot",
                "soc-wwwdata-unexpected-exec", "soc-webprod-new-outbound",
                "soc-wwwdata-writes-outside-webroot"):
        assert r[rid]["type"] == "eql" and r[rid]["language"] == "eql"
    # regula f e pe auditd (A3: Defend nu emite citiri), nu EQL endpoint
    f = r["soc-apache-reads-shadow"]
    assert f["language"] == "kuery" and f["index"] == B.AUDITD_IDX
    assert B.SHADOW_READ_KEY in f["query"]


def test_continut_reguli():
    r = B.RULES
    a = r["soc-web-spawns-shell"]["query"]
    assert "apache2" in a and "php-fpm8.3" in a and '"sh"' in a and "bash" in a
    assert a.count("(") == a.count(")")                # paranteze echilibrate
    # exceptia sendmail: apelul MTA exclus, dar metacaracterele de inlantuire o anuleaza
    assert "/usr/sbin/sendmail " in a and "and not" in a
    assert '"*;*"' in a and '"*|*"' in a and '"*`*"' in a and '"*$*"' in a
    d = r["soc-webprod-new-outbound"]["query"]
    assert 'cidrmatch(destination.ip, "192.168.10.0/24")' in d and "web-prod" in d
    assert "53, 123" in d
    b = r["soc-php-written-in-webroot"]["query"]
    assert "/var/www/*" in b and '"php"' in b and "like~" in b


# ---------------- liste albe ----------------

def test_whitelist_implicita_cand_lipseste(monkeypatch, tmp_path):
    monkeypatch.setattr(B, "WHITELIST_FILE", tmp_path / "nu-exista.json")
    rules = B.build_rules()
    q = rules["soc-wwwdata-unexpected-exec"]["query"]
    assert "/usr/sbin/apache2" in q                    # setul implicit sigur
    # fara egress_ip in fisier -> regula d nu are clauza "destination.ip in"
    assert "destination.ip in (" not in rules["soc-webprod-new-outbound"]["query"]


def test_whitelist_din_fisier_injectata(monkeypatch, tmp_path):
    wl = tmp_path / "wl.json"
    wl.write_text(json.dumps({"wwwdata_exec": ["/opt/custom/bin"],
                              "egress_ip": ["203.0.113.9"]}), encoding="utf-8")
    monkeypatch.setattr(B, "WHITELIST_FILE", wl)
    rules = B.build_rules()
    assert "/opt/custom/bin" in rules["soc-wwwdata-unexpected-exec"]["query"]
    assert '"203.0.113.9"' in rules["soc-webprod-new-outbound"]["query"]


def test_whitelist_filtreaza_valori_periculoase(monkeypatch, tmp_path):
    wl = tmp_path / "wl.json"
    # valori cu ghilimele / care nu sunt cale absoluta -> eliminate, cad pe implicite
    wl.write_text(json.dumps({"wwwdata_exec": ['bad"inj', "relative/path"],
                              "egress_ip": ['1.2.3.4"; drop']}), encoding="utf-8")
    monkeypatch.setattr(B, "WHITELIST_FILE", wl)
    rules = B.build_rules()
    q = rules["soc-wwwdata-unexpected-exec"]["query"]
    assert "bad" not in q and "relative/path" not in q  # valorile periculoase eliminate
    assert "/usr/sbin/apache2" in q                     # a cazut pe implicite (lista a ramas goala)
    assert "drop" not in rules["soc-webprod-new-outbound"]["query"]

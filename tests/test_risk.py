"""plann.md A3: scorul de risc pe entitate — decadere, ponderi, excluderi, cooldown (pur)."""
from datetime import datetime, timedelta, timezone

import risk as R

NOW = datetime(2026, 11, 2, 16, 0, tzinfo=timezone.utc)


def _e(h_ago, sev="high", ip="203.0.113.9", user=None, tags=None, rule="r", i=0):
    return {"ts": (NOW - timedelta(hours=h_ago)).isoformat(), "severity": sev, "tags": tags or [],
            "rule": rule, "source_ip": ip, "user": user, "doc_id": f"d{i}", "index": ".alerts-x"}


def test_ponderi_si_decadere():
    s = R.score_entities([_e(0, "critical"), _e(6, "critical")], NOW)
    d = s[("source_ip", "203.0.113.9")]
    assert d["score"] == 12.0 and d["events"] == 2        # 8 + 8*0.5
    assert R.weight("high", ["soc-honeytoken"]) == 8.0 and R.weight("low", None) == 1.0
    assert R.score_entities([_e(30)], NOW) == {}            # in afara ferestrei


def test_excluderi_proprii_si_benign():
    s = R.score_entities([_e(0, ip="192.168.10.150"), _e(0, ip="203.0.113.9", user="www-data")], NOW,
                         skip_ips=frozenset({"192.168.10.150"}))
    assert list(s) == [("source_ip", "203.0.113.9")]
    s = R.score_entities([_e(0, ip=None, user="svc_deploy")], NOW)
    assert list(s) == [("user", "svc_deploy")]


def test_finding_si_cooldown():
    ev = [_e(0, "critical", i=i, rule=f"r{i % 2}") for i in range(4)]       # 32 > prag 20
    s = R.score_entities(ev, NOW)
    f = R.to_finding("source_ip", "203.0.113.9", s[("source_ip", "203.0.113.9")])
    assert f.kind == "entity_risk" and f.entity_type.value == "source_ip" and f.rarity_score == 0.8
    assert f.detail["events_24h"] == 4 and len(f.evidence_refs) == 4
    assert R.due({}, "source_ip:203.0.113.9", NOW)
    assert not R.due({"source_ip:203.0.113.9": (NOW - timedelta(hours=1)).isoformat()}, "source_ip:203.0.113.9", NOW)
    assert R.due({"source_ip:203.0.113.9": (NOW - timedelta(hours=7)).isoformat()}, "source_ip:203.0.113.9", NOW)


def test_sweep_cu_es_fals(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "STATE", tmp_path / "st.json")
    hits = [{"_id": f"d{i}", "_index": ".alerts-x", "_source": {
        "@timestamp": (datetime.now(timezone.utc) - timedelta(minutes=i)).isoformat(),
        "kibana.alert.severity": "critical", "kibana.alert.rule.name": "Brute-force",
        "source": {"ip": "203.0.113.9"}}} for i in range(3)]
    class ES:
        def search(self, **kw):
            return {"hits": {"hits": hits}}
    out = R.sweep_entity_risk(1, es=ES())
    assert len(out) == 1 and out[0].entity_id == "203.0.113.9"
    assert R.sweep_entity_risk(1, es=ES()) == []            # cooldown: nu se repeta


# --- faza 22 L: o singura sursa pentru IP-urile proprii ---------------------------------------

def test_excluded_ips_aceeasi_sursa_ca_honeytokens(monkeypatch):
    import honeytokens
    monkeypatch.delenv("WP_SELF_IPS", raising=False)
    monkeypatch.delenv("BENIGN_GEN_IPS", raising=False)
    got = R.excluded_ips()
    assert got == frozenset(str(ip) for ip in honeytokens.known_own_ips())
    assert {"172.30.6.249", "192.168.10.138", "192.168.10.150", "127.0.0.1", "::1"} <= got
    monkeypatch.setenv("WP_SELF_IPS", "10.9.9.9, nu-ip")
    monkeypatch.setenv("BENIGN_GEN_IPS", "10.8.8.8")
    assert R.excluded_ips() == frozenset({"10.9.9.9", "10.8.8.8"})

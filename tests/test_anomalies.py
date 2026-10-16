"""Anomalii statistice (faza 12): beaconing si DNS. Functii pure + I/O cu ES fals."""
import pytest

import anomalies as A
import orchestrator
from schemas import EntityType, RarityFinding

T0 = 1_760_000_000.0


def test_beacon_regulat():
    st = A.beacon_stats([T0 + 30 * i + (0.5 if i % 2 else -0.5) for i in range(10)])
    assert st["connections"] == 10 and abs(st["mean_interval_s"] - 30) < 1 and A.is_beacon(st)


def test_trafic_neregulat_nu_e_beacon():
    st = A.beacon_stats([T0 + x for x in (0, 5, 200, 230, 900, 1000, 3000)])
    assert st is not None and not A.is_beacon(st)


def test_prea_putine_conexiuni():
    assert A.beacon_stats([T0, T0 + 30, T0 + 60]) is None
    assert not A.is_beacon(None)


def test_evenimentele_aceleiasi_conexiuni_se_unesc():
    # connection_attempted dublat la aceeasi secunda nu face intervale de 0 s
    times = [T0 + 60 * i + d for i in range(7) for d in (0, 0.2)]
    st = A.beacon_stats(times)
    assert st["connections"] == 7 and A.is_beacon(st)


def test_rafala_nu_e_beacon():
    assert not A.is_beacon(A.beacon_stats([T0 + 2 * i for i in range(20)]))


def test_timestamp_iso():
    st = A.beacon_stats([f"2026-10-16T07:{m:02d}:00.000Z" for m in range(0, 14, 2)])
    assert st["mean_interval_s"] == 120.0


@pytest.mark.parametrize("name,flag", [
    ("x7k2qj9vbz3mfp1wq8rt5ylh.evil.com", True),
    ("aGVsbG8gd29ybGQgdGhpcyBpcyBkYXRh.t.example.org", True),
    ("www.google.com", False),
    ("dualstack.p2.shared.global.fastly.net", False),
    ("d3k2j1h4g5f6.cloudfront.net", False),
    ("7.3.c.6.6.8.e.f.f.f.7.2.0.0.a.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa", False),
])
def test_dns_entropie(name, flag):
    found = A.dns_anomalies([{"host": "w", "process": "p", "name": name}])
    assert bool(found) is flag


def test_dns_multe_subdomenii():
    q = [{"host": "w", "process": "bash", "name": f"a{i}.t.example.org"} for i in range(A.DNS_MANY_SUBDOMAINS)]
    (d,) = A.dns_anomalies(q)
    assert d["reason"] == "many_subdomains" and d["unique_subdomains"] == A.DNS_MANY_SUBDOMAINS
    assert d["domain"] == "example.org"


def test_dns_un_rezultat_per_domeniu():
    q = [{"host": "w", "process": "p", "name": f"{s}.evil.com"} for s in
         ("x7k2qj9vbz3mfp1wq8rt5ylh", "q9w8e7r6t5y4u3i2o1p0asdf")]
    assert len(A.dns_anomalies(q)) == 1


class FakeES:
    def __init__(self, rows):
        self.rows, self.queries = rows, []

    def search(self, index, size, query, source, sort):
        self.queries.append(query)
        return {"hits": {"hits": [{"_source": r} for r in self.rows]}}


def _net(t, ip="203.0.113.10", proc="curl"):
    return {"@timestamp": t, "host": {"name": "web-prod"}, "process": {"name": proc},
            "destination": {"ip": ip, "port": 80}}


def test_sweep_beaconing_cu_es_fals():
    rows = [_net(f"2026-10-16T07:{m:02d}:00Z") for m in range(0, 16, 2)] + [_net("2026-10-16T07:05:00Z", proc="x")]
    es = FakeES(rows)
    (f,) = A.sweep_beaconing(1, es=es)
    assert f.kind == "beaconing" and f.rarity_score == 1.0 and f.detail["window_hours"] == A.BEACON_WINDOW_H
    filt = es.queries[0]["bool"]["filter"]
    assert {"term": {"event.action": "connection_attempted"}} in filt


def test_sweep_dns_cu_es_fals():
    es = FakeES([{"host": {"name": "web-prod"}, "process": {"name": "bash"},
                  "dns": {"question": {"name": "x7k2qj9vbz3mfp1wq8rt5ylh.evil.com"}}}])
    (f,) = A.sweep_dns(1, es=es)
    assert f.kind == "dns_anomaly" and f.detail["domain"] == "evil.com" and "host" not in f.detail


def test_cheile_de_dedup():
    k = orchestrator.dedup_key_finding
    F = lambda kind, **d: RarityFinding(kind=kind, entity_type=EntityType.HOST, entity_id="w",
                                        detail=d, rarity_score=1.0)
    assert k(F("beaconing", process="curl", destination_ip="1.2.3.4", cv=0.1)) == \
        k(F("beaconing", process="curl", destination_ip="1.2.3.4", cv=0.2))
    assert k(F("dns_anomaly", process="bash", domain="evil.com", example="a")) == \
        k(F("dns_anomaly", process="bash", domain="evil.com", example="b"))


def test_dns_domeniul_de_cautare_nu_dubleaza():
    base = [f"{s}.t.example.org" for s in ("x7k2qj9vbz3mfp1wq8rt5ylh", "q9w8e7r6t5y4u3i2o1p0asdf")]
    q = [{"host": "w", "process": "getent", "name": n} for n in base + [b + ".tuiasi.ro" for b in base]]
    assert [d["domain"] for d in A.dns_anomalies(q)] == ["example.org"]

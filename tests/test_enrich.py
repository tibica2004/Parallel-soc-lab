"""enrich.py: rezumatul alertelor corelate si interogarea parametrizata."""
import enrich


def _a(uuid, rule, sev):
    return {"kibana.alert.uuid": uuid, "kibana.alert.rule.name": rule, "kibana.alert.severity": sev}


def test_rezumat_exclude_alerta_curenta():
    s = enrich.summarize_correlated([_a("u1", "R1", "high"), _a("u2", "R1", "medium"),
                                     _a("u3", "R2", "critical"), _a("self", "R9", "critical")], "self")
    assert s["count"] == 3 and s["max_severity"] == "critical"
    assert s["rules"] == [{"rule": "R1", "count": 2}, {"rule": "R2", "count": 1}]


def test_rezumat_gol():
    assert enrich.summarize_correlated([], None) == {
        "window_min": enrich.CORRELATION_WINDOW_MIN, "count": 0, "same_process_tree": 0,
        "max_severity": None, "rules": []}


def test_acelasi_arbore_de_procese():
    rel = {**_a("u1", "R1", "high"), "process": {"entity_id": "C", "parent": {"entity_id": "P"}}}
    alt = {**_a("u2", "R2", "high"), "process": {"entity_id": "X", "parent": {"entity_id": "Y"}}}
    s = enrich.summarize_correlated([rel, alt], None, {"P", "Q"})
    assert s["count"] == 2 and s["same_process_tree"] == 1


class FakeES:
    def __init__(self, hits=None, fail=False):
        self.hits, self.fail, self.calls = hits or [], fail, []

    def search(self, **kw):
        self.calls.append(kw)
        if self.fail:
            raise RuntimeError("x")
        return {"hits": {"hits": [{"_source": h} for h in self.hits]}}


ALERT = {"@timestamp": "2026-10-12T10:00:00Z", "host": {"name": "web-prod"},
         "kibana.alert.uuid": "self", "process": {"command_line": "x\" OR host.name:*"}}


def test_interogare_cu_filtre_term_si_range():
    es = FakeES([_a("u1", "R1", "high")])
    r = enrich.correlated_alerts(es, ALERT)
    assert r["count"] == 1
    f = es.calls[0]["query"]["bool"]["filter"]
    assert f[0] == {"term": {"host.name": "web-prod"}}
    assert f[1]["range"]["@timestamp"] == {"gte": "2026-10-12T09:30:00+00:00", "lte": "2026-10-12T10:30:00+00:00"}
    assert "OR host.name" not in str(es.calls[0])  # nimic din telemetrie in interogare


def test_esec_sau_date_lipsa_da_none():
    assert enrich.correlated_alerts(FakeES(fail=True), ALERT) is None
    assert enrich.correlated_alerts(FakeES(), {"host": {"name": "h"}}) is None


def test_enrich_complet():
    r = enrich.enrich(FakeES(), {**ALERT, "destination": {"ip": "203.0.113.7"}})
    assert r["correlated_alerts"]["count"] == 0
    assert [m["indicator"] for m in r["threat_intel_matches"]] == ["203.0.113.7"]


def test_fereastra_de_5_minute():
    es = FakeES()
    r = enrich.correlated_alerts(es, ALERT, 5)
    assert r["window_min"] == 5
    assert es.calls[0]["query"]["bool"]["filter"][1]["range"]["@timestamp"] == {
        "gte": "2026-10-12T09:55:00+00:00", "lte": "2026-10-12T10:05:00+00:00"}

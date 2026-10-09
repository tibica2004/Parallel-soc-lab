"""label_ui.py cu un Elasticsearch fals: autentificare, CSRF, escapare, scriere."""
import re

import pytest
from elasticsearch import ConflictError
from fastapi.testclient import TestClient

import label_ui

PW = "parola-de-test-lunga"
XSS = '<script>alert(1)</script>'


class FakeES:
    def __init__(self):
        self.docs = {
            "doc1": {"@timestamp": "2026-10-09T10:00:00Z", "source_path": "fast", "rule_name": XSS,
                     "entity_type": "host", "entity_id": "web-prod", "classification": "benign",
                     "confidence": 95, "proposed_action": "none", "investigation_id": "inv1",
                     "model_id": "m", "rarity_score": 0.0},
            "doc2": {"@timestamp": "2026-10-09T09:00:00Z", "source_path": "fast", "rule_name": "R2",
                     "entity_type": "host", "entity_id": "web-prod", "classification": "malicious",
                     "confidence": 95, "proposed_action": "escalate_human", "investigation_id": "inv2",
                     "model_id": "m", "rarity_score": 1.0},
        }
        self.audit = {"inv1": {"narrative": XSS, "escalate": False, "escalation_reasons": [],
                               "policy_decision": "none: ok"}}
        self.traces = {"inv1": {"totals": {"llm_calls": 1, "tokens": 50, "tool_calls": 1, "tool_errors": 0,
                                           "doc_refs": 1, "duration_ms": 1500},
                                "events": [{"type": "tool", "name": "tool_eql_sequence", "args": XSS,
                                            "rows": 1, "duration_ms": 30, "error": None,
                                            "doc_refs": [{"index": "idx", "id": "DOCX"}]},
                                           {"type": "llm", "role": "fast.verdict", "tokens": 50,
                                            "duration_ms": 900, "tool_calls": []}]}}
        self.traces_denied = False
        self.updates = []
        self.conflict = False

    def search(self, index, query, size=10, sort=None, from_=0, aggs=None, track_total_hits=None):
        if index == "soc-traces":
            if self.traces_denied:
                raise RuntimeError("403")
            inv = query["bool"]["filter"][0]["term"]["investigation_id.keyword"]
            hits = [{"_source": self.traces[inv]}] if inv in self.traces else []
            return {"hits": {"hits": hits}}
        if index == "soc-audit":
            inv = query["bool"]["filter"][0]["term"]["investigation_id.keyword"]
            hits = [{"_source": self.audit[inv]}] if inv in self.audit else []
            return {"hits": {"hits": hits}}
        unl = any("exists" in m for m in query["bool"].get("must_not", []))
        rows = [(k, d) for k, d in self.docs.items() if not (unl and d.get("ground_truth"))]
        return {"hits": {"total": {"value": len(rows)},
                         "hits": [{"_id": k, "_source": d} for k, d in rows][:size]},
                "aggregations": {"g": {"labeled": {"doc_count": 3, "out": {"buckets": [
                    {"key": "TP", "doc_count": 2}, {"key": "FN", "doc_count": 1}]}}}}}

    def get(self, index, id):
        if id not in self.docs:
            from elasticsearch import NotFoundError
            raise NotFoundError("nf", meta=type("M", (), {"status": 404})(), body={})
        return {"_id": id, "_source": dict(self.docs[id]), "_seq_no": 7, "_primary_term": 1}

    def update(self, index, id, doc, if_seq_no, if_primary_term):
        if self.conflict:
            raise ConflictError("conflict", meta=type("M", (), {"status": 409})(), body={})
        self.updates.append((index, id, doc, if_seq_no, if_primary_term))
        self.docs[id].update(doc)


@pytest.fixture
def es():
    return FakeES()


@pytest.fixture
def client(es):
    return TestClient(label_ui.create_app(password=PW, es=es, session_secret="s" * 32),
                      follow_redirects=False)


def _login(client):
    r = client.post("/login", data={"password": PW})
    assert r.status_code == 303
    page = client.get("/v/doc1").text
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


def test_parola_scurta_refuza_pornirea():
    with pytest.raises(RuntimeError):
        label_ui.create_app(password="scurta", es=FakeES())


@pytest.mark.parametrize("path", ["/", "/v/doc1"])
def test_fara_login_redirect(client, path):
    r = client.get(path)
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_parola_gresita_si_limita(client):
    for _ in range(label_ui.LOGIN_MAX_FAILS):
        assert client.post("/login", data={"password": "gresit"}).status_code == 401
    assert client.post("/login", data={"password": PW}).status_code == 429


def test_antete_de_securitate(client):
    h = client.get("/login").headers
    assert "script-src 'none'" in h["content-security-policy"] and h["x-frame-options"] == "DENY"


def test_continut_din_telemetrie_e_escapat(client):
    _login(client)
    for page in (client.get("/").text, client.get("/v/doc1").text):
        assert XSS not in page and "&lt;script&gt;" in page


def test_contorul_global_de_etichete(client):
    _login(client)
    page = client.get("/?status=unlabeled").text
    assert "Etichetate: 3" in page and "TP 2" in page and "FN 1" in page


def test_eticheta_fara_csrf_respinsa(client, es):
    _login(client)
    r = client.post("/v/doc1/label", data={"ground_truth": "attack", "csrf": "fals"})
    assert r.status_code == 403 and es.updates == []


def test_eticheta_scrisa(client, es):
    csrf = _login(client)
    r = client.post("/v/doc1/label", data={"ground_truth": "attack", "notes": "rce ratat", "csrf": csrf})
    assert r.status_code == 303 and r.headers["location"] == "/v/doc2"   # urmatorul neetichetat
    index, doc_id, fields, seq, term = es.updates[0]
    assert (index, doc_id, seq, term) == ("verdicts-history", "doc1", 7, 1)
    assert fields["ground_truth"] == "attack" and fields["label_source"] == "human"
    assert fields["label_outcome"] == "FN" and fields["notes"] == "rce ratat"
    assert set(fields) == {"ground_truth", "label_source", "label_outcome", "labeled_at", "notes", "label_history"}


@pytest.mark.parametrize("data", [{"ground_truth": "TP"}, {"ground_truth": "attack", "notes": "x" * 501}])
def test_eticheta_invalida_400(client, es, data):
    csrf = _login(client)
    assert client.post("/v/doc1/label", data={**data, "csrf": csrf}).status_code == 400
    assert es.updates == []


@pytest.mark.parametrize("doc_id", ["nu-exista", "a%22b"])
def test_doc_inexistent_sau_invalid(client, es, doc_id):
    csrf = _login(client)
    assert client.get(f"/v/{doc_id}").status_code == 404
    assert client.post(f"/v/{doc_id}/label", data={"ground_truth": "attack", "csrf": csrf}).status_code in (400, 404)
    assert es.updates == []


def test_conflict_nu_suprascrie(client, es):
    csrf = _login(client)
    es.conflict = True
    r = client.post("/v/doc1/label", data={"ground_truth": "benign", "csrf": csrf})
    assert r.status_code == 303 and r.headers["location"] == "/v/doc1?error=conflict"
    assert "modificat intre timp" in client.get("/v/doc1?error=conflict").text


def test_logout(client):
    csrf = _login(client)
    client.post("/logout", data={"csrf": csrf})
    assert client.get("/").status_code == 303


def test_urma_afisata_si_escapata(client):
    _login(client)
    page = client.get("/v/doc1").text
    assert "tool_eql_sequence" in page and "_id:DOCX" in page and "fast.verdict" in page
    assert XSS not in page


def test_urma_lipsa_sau_fara_drept(client, es):
    _login(client)
    assert "Nicio urma" in client.get("/v/doc2").text
    es.traces_denied = True
    r = client.get("/v/doc1")
    assert r.status_code == 200 and "Nicio urma" in r.text

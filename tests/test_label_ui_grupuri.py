"""Faza 24: etichetarea pe grupuri in label_ui — coada, vot unul cate unul si in bloc, verdictul
sistemului ascuns pana la vot, mai multi oameni (consens), API autentificat, L2 (fara ground_truth
pe alerte), retrogradarea imediata la attack pe un grup inchis de cascada."""
import hashlib
import re

import pytest
from fastapi.testclient import TestClient

import label_ui

PW = "parola-de-test-lunga"
B1, B2, B3 = "b" + "1" * 24, "b" + "2" * 24, "b" + "3" * 24
XSS = "<script>alert(1)</script>"
TOKEN = "token-de-test-foarte-lung-1234567890"


class FakeES:
    """soc-buckets cu get/index si control de concurenta (seq_no)."""

    def __init__(self):
        self.docs = {}
        self.seq = {}
        for bid, cnt, p in ((B1, 50, 0.5), (B2, 5, 0.99), (B3, 500, 0.5)):
            self.docs[bid] = {"bucket_id": bid, "pipeline": "executie_web", "dp_version": 1,
                              "values": {"rule": "r0", "user_class": XSS[:10] if bid == B3 else "root"},
                              "count": cnt, "first_seen": "2026-11-20T00:00:00+00:00",
                              "last_seen": "2026-11-27T00:00:00+00:00", "votes": [], "consensus": "none",
                              "votes_attack": 0, "votes_benign": 0, "cascade_closed": 0, "examples": [],
                              "system": {"step": "model", "decision": "benign", "confidence": 97,
                                         "p_attack": p, "outlier": False, "mode": "shadow",
                                         "model_hash": "SISTEM-SECRET-HASH"},
                              "tier2_summary": {"text": XSS, "chain_id": None, "at": "2026-11-27T00:00:00"}}
            self.seq[bid] = 1
        self.writes = []

    def get(self, index, id):
        from elasticsearch import NotFoundError
        if index != "soc-buckets" or id not in self.docs:
            raise NotFoundError("nf", meta=type("M", (), {"status": 404})(), body={})
        return {"_id": id, "_source": dict(self.docs[id]), "_seq_no": self.seq[id], "_primary_term": 1}

    def index(self, index, id, document, if_seq_no=None, if_primary_term=None, op_type=None):
        assert index == "soc-buckets"
        assert if_seq_no == self.seq.get(id)
        self.docs[id] = document
        self.seq[id] = self.seq.get(id, 0) + 1
        self.writes.append((id, document))

    def search(self, index, query, size=10, sort=None, **k):
        assert index == "soc-buckets"
        allowed = query["bool"]["filter"][0]["terms"]["consensus"]
        rows = [d for d in self.docs.values() if d["consensus"] in allowed]
        return {"hits": {"hits": [{"_source": dict(d)} for d in rows]}}


@pytest.fixture
def es():
    return FakeES()


@pytest.fixture
def demotions():
    return []


def app(es, demotions, users=None, trained=None):
    return label_ui.create_app(password=PW, es=es, learning_es=es, session_secret="s" * 32, users=users,
                               api_tokens={hashlib.sha256(TOKEN.encode()).hexdigest(): "robot"},
                               on_attack_label=lambda p, d, l: demotions.append((p, d.get("bucket_id"), l)),
                               train=lambda pid: (trained.append(pid) if trained is not None else None) or [{"pipeline": pid}])


def login(c, user=None, pw=PW):
    data = {"password": pw} | ({"username": user} if user else {})
    r = c.post("/login", data=data)
    assert r.status_code == 303, r.text
    page = c.get("/buckets").text
    return re.search(r'name="csrf" value="([^"]+)"', page).group(1)


@pytest.fixture
def client(es, demotions):
    return TestClient(app(es, demotions), follow_redirects=False)


def test_coada_e_ordonata_de_cod_si_ascunde_verdictul_sistemului(client):
    login(client)
    page = client.get("/buckets").text
    # incertitudine x volum: B3 (500, p=0.5) inaintea B1 (50, p=0.5) inaintea B2 (5, p=0.99)
    assert page.index(B3[:9]) < page.index(B1[:9]) < page.index(B2[:9])
    assert "SISTEM-SECRET-HASH" not in page and "97" not in page.split("Voturi")[1]
    assert XSS not in page and "&lt;script" in page


def test_pagina_grupului_ascunde_sistemul_pana_la_votul_omului(client, es):
    csrf = login(client)
    page = client.get(f"/b/{B1}").text
    assert "SISTEM-SECRE" not in page and "Ce a decis sistemul" not in page
    assert "&lt;script&gt;" in page and XSS not in page            # rezumatul Tier 2 apare, escapat
    r = client.post(f"/b/{B1}/label", data={"label": "benign", "csrf": csrf})
    assert r.status_code == 303
    page = client.get(f"/b/{B1}").text
    assert "Ce a decis sistemul" in page and "SISTEM-SECRE" in page


def test_votul_scrie_doar_in_grup_cu_om_autentificat_si_fara_ground_truth(client, es):
    csrf = login(client)
    client.post(f"/b/{B1}/label", data={"label": "attack", "csrf": csrf, "notes": "vazut in Kibana"})
    doc = es.docs[B1]
    assert doc["votes"][-1]["user"] == "operator" and doc["votes"][-1]["label_source"] == "human"
    assert doc["consensus"] == "attack" and doc["votes_attack"] == 1
    assert "ground_truth" not in doc                                  # L2: grupul nu e verdict
    assert all(w[0] == B1 for w in es.writes)


def test_fara_csrf_sau_fara_login_nu_se_voteaza(client, es):
    r = client.post(f"/b/{B1}/label", data={"label": "attack"})
    assert r.status_code == 303 and es.writes == []                  # spre /login
    login(client)
    assert client.post(f"/b/{B1}/label", data={"label": "attack", "csrf": "rau"}).status_code == 403
    assert es.writes == []
    csrf = login(client)
    assert client.post(f"/b/{B1}/label", data={"label": "malicious", "csrf": csrf}).status_code == 400
    assert client.post("/b/nu-e-grup/label", data={"label": "attack", "csrf": csrf}).status_code == 400


def test_etichetare_in_bloc(client, es):
    csrf = login(client)
    r = client.post("/buckets/label", data={"bucket_ids": [B1, B2], "label": "benign", "csrf": csrf})
    assert r.status_code == 303
    assert es.docs[B1]["consensus"] == es.docs[B2]["consensus"] == "benign"
    assert es.docs[B3]["consensus"] == "none"


def test_mai_multi_oameni_vot_majoritar_egalitatea_nedecisa(es, demotions):
    users = {"ana": label_ui.hash_password("parola-ana-lunga1"), "dan": label_ui.hash_password("parola-dan-lunga1")}
    a = TestClient(app(es, demotions, users=users), follow_redirects=False)
    d = TestClient(app(es, demotions, users=users), follow_redirects=False)
    assert a.post("/login", data={"username": "ana", "password": "gresita-gresita"}).status_code == 401
    ca, cd = login(a, "ana", "parola-ana-lunga1"), login(d, "dan", "parola-dan-lunga1")
    a.post(f"/b/{B1}/label", data={"label": "attack", "csrf": ca})
    d.post(f"/b/{B1}/label", data={"label": "benign", "csrf": cd})
    assert es.docs[B1]["consensus"] == "tie"
    assert {v["user"] for v in es.docs[B1]["votes"]} == {"ana", "dan"}
    a.post(f"/b/{B1}/label", data={"label": "benign", "csrf": ca})   # ana se razgandeste
    assert es.docs[B1]["consensus"] == "benign" and es.docs[B1]["votes_benign"] == 2


def test_atac_pe_grup_cere_retrogradarea_imediata(client, es, demotions):
    csrf = login(client)
    client.post(f"/b/{B1}/label", data={"label": "benign", "csrf": csrf})
    assert demotions == []
    client.post(f"/b/{B1}/label", data={"label": "attack", "csrf": csrf})
    assert demotions == [("executie_web", B1, "attack")]


def test_api_cere_token_si_voteaza_in_numele_lui(client, es):
    assert client.post("/api/feedback", json={"bucket_ids": [B1], "label": "attack"}).status_code == 401
    assert client.post("/api/feedback", json={"bucket_ids": [B1], "label": "attack"},
                       headers={"Authorization": "Bearer gresit"}).status_code == 401
    h = {"Authorization": f"Bearer {TOKEN}"}
    r = client.post("/api/feedback", json={"bucket_ids": [B1, "b" + "9" * 24], "label": "attack"}, headers=h)
    assert r.status_code == 200 and r.json()["voted"] == [B1] and r.json()["missing"] == ["b" + "9" * 24]
    assert es.docs[B1]["votes"][-1]["user"] == "robot"
    assert client.post("/api/feedback", json={"bucket_ids": [B1], "label": "attack", "x": 1},
                       headers=h).status_code == 400
    # cookie de sesiune fara token: API-ul nu il accepta (fara CSRF pe API)
    login(client)
    assert client.post("/api/feedback", json={"bucket_ids": [B1], "label": "benign"}).status_code == 401


def test_api_decizie_si_antrenare(es, demotions):
    trained = []
    c = TestClient(app(es, demotions, trained=trained), follow_redirects=False)
    h = {"Authorization": f"Bearer {TOKEN}"}
    assert c.get(f"/api/decision/{B1}").status_code == 401
    r = c.get(f"/api/decision/{B1}", headers=h)
    assert r.status_code == 200 and r.json()["bucket_id"] == B1 and "votes" not in r.json()
    assert c.get("/api/decision/b" + "9" * 24, headers=h).status_code == 404
    assert c.post("/api/train", json={"pipeline": "executie_web"}, headers=h).status_code == 200
    assert c.post("/api/train", json={"pipeline": "../x"}, headers=h).status_code == 400
    assert trained == ["executie_web"]


def test_parola_hash_si_tokenuri():
    e = label_ui.hash_password("o-parola-lunga")
    assert label_ui.check_password("o-parola-lunga", e) and not label_ui.check_password("alta", e)
    assert label_ui.parse_users(f"ana:{e},RAU:{e},x") == {"ana": e}
    h = hashlib.sha256(b"t").hexdigest()
    assert label_ui.parse_tokens(f"robot:{h},rau:123") == {h: "robot"}

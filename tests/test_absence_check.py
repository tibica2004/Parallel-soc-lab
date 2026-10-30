"""Pasul 3.D: absenta si integritate. ES fals, fara retea, fara Discord."""
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

import absence_check as A
import notify
import orchestrator

NOW = datetime(2026, 10, 30, 9, 0, tzinfo=timezone.utc)


class FakeES:
    """search -> ultimul @timestamp per index (ages: index -> minute sau None); index -> captat."""

    def __init__(self, ages=None, fail=()):
        self.ages, self.fail, self.indexed, self.queries = ages or {}, set(fail), [], []

    def search(self, index, size=0, query=None, aggs=None):
        self.queries.append((index, query))
        if index in self.fail:
            raise ConnectionError("es cazut")
        age = self.ages.get(index, 1.0)
        v = None if age is None else (NOW - timedelta(minutes=age)).isoformat().replace("+00:00", "Z")
        return {"aggregations": {"last": {"value_as_string": v}}}

    def index(self, index, document):
        self.indexed.append((index, document))


@pytest.fixture(autouse=True)
def izolat(monkeypatch, tmp_path):
    monkeypatch.setattr(notify, "_STATE", tmp_path / "dedup.json")
    sent = []
    monkeypatch.setattr(notify, "notify_human", lambda *a, **k: sent.append((a, k)) or True)
    return sent


def _run(inc=None):
    return A.Run(NOW, inc if inc is not None else FakeES())


# ---------------- fluxurile ----------------

def test_toate_fluxurile_proaspete_nicio_problema():
    run = _run()
    A.check_streams(FakeES(), run)
    assert run.kinds == [] and not run.failed
    assert set(run.ages) == {s[0] for s in A.STREAMS}


def test_flux_tacut_scrie_incident_si_pagineaza(izolat):
    inc = FakeES()
    run = _run(inc)
    A.check_streams(FakeES({"logs-auditd_manager.auditd-*": 45}), run)
    assert run.kinds == ["telemetry_silence:auditd"]
    (idx, doc), = inc.indexed
    assert idx == "soc-incidents" and doc["type"] == "integrity_alert"
    assert doc["kind"] == "telemetry_silence" and doc["subject"] == "auditd"
    assert doc["age_min"] == 45 and doc["threshold_min"] == 10 and doc["severity"] == "high"
    assert "@timestamp" in doc and doc["status"] == "open"
    assert izolat[0][1]["dedup_key"] == "absence:telemetry_silence:auditd"


def test_flux_fara_date_in_24h_e_tacut():
    run = _run()
    A.check_streams(FakeES({"logs-suricata.eve-*": None}), run)
    assert run.kinds == ["telemetry_silence:suricata"] and run.ages["suricata"] is None


def test_toate_tacute_adauga_alerta_critica():
    inc = FakeES()
    run = _run(inc)
    A.check_streams(FakeES({s[1]: None for s in A.STREAMS}), run)
    assert "telemetry_silence:all_streams" in run.kinds
    assert [d for _, d in inc.indexed if d["subject"] == "all_streams"][0]["severity"] == "critical"


def test_pragul_e_per_flux():
    run = _run()
    # 12 min: peste pragul de 10 (auditd), sub cel de 15 (fisiere)
    A.check_streams(FakeES({"logs-auditd_manager.auditd-*": 12, "logs-endpoint.events.file-*": 12}), run)
    assert run.kinds == ["telemetry_silence:auditd"]


def test_suricata_filtrat_dupa_agent_name_si_hostul_e_term():
    es = FakeES()
    A.check_streams(es, _run())
    q = dict(es.queries)
    assert {"term": {"agent.name": "web-prod"}} in q["logs-suricata.eve-*"]["bool"]["filter"]
    assert {"term": {"host.name": "web-prod"}} in q["logs-system.syslog-*"]["bool"]["filter"]


def test_apache_nu_e_verificat():
    # poate tacea ore legitim (fara trafic); revine cu generatorul benign (pasul 4)
    assert not any("apache" in s[1] for s in A.STREAMS)


def test_flux_ilizibil_e_esec_nu_tacere():
    run = _run()
    A.check_streams(FakeES(fail={"logs-system.auth-*"}), run)
    assert run.failed and run.kinds == ["check_failed:stream_auth"]


# ---------------- dedup si inregistrare ----------------

def test_incident_dedup_10_minute():
    inc = FakeES()
    for _ in range(3):
        A.check_streams(FakeES({"logs-system.syslog-*": 30}), _run(inc))
    assert len(inc.indexed) == 1


def test_fara_cheie_de_incidente_e_esec_dar_pagineaza(izolat):
    run = A.Run(NOW, None)
    A.check_streams(FakeES({"logs-system.syslog-*": 30}), run)
    assert run.failed and izolat


def test_schema_respinge_campuri_in_plus_si_tipuri_necunoscute():
    with pytest.raises(ValidationError):
        A.IntegrityAlert(timestamp=NOW, kind="telemetry_silence", severity="high", host="h",
                         subject="s", detail="d", exploit="x")
    with pytest.raises(ValidationError):
        A.IntegrityAlert(timestamp=NOW, kind="altceva", severity="high", host="h",
                         subject="s", detail="d")


# ---------------- fleet-server ----------------

class R:
    def __init__(self, ok=True, status_code=200, body=None):
        self.ok, self.status_code, self._b = ok, status_code, body or {}

    def json(self):
        return self._b


@pytest.mark.parametrize("resp,problema", [
    (R(body={"name": "fleet-server", "status": "HEALTHY"}), False),
    (R(body={"status": "DEGRADED"}), True),
    (R(ok=False, status_code=503), True),
    (ConnectionError("refuzat"), True),
])
def test_fleet_server(monkeypatch, resp, problema):
    def get(url, timeout):
        if isinstance(resp, Exception):
            raise resp
        return resp
    monkeypatch.setattr(A.requests, "get", get)
    run = _run()
    A.check_fleet_server(run)
    assert (run.kinds == ["fleet_down:fleet_server"]) is problema


# ---------------- pulsul ----------------

def test_pulsul_ok_si_alert():
    m = FakeES()
    A.write_heartbeat(m, _run())
    run = _run()
    run.kinds.append("fleet_down:fleet_server")
    A.write_heartbeat(m, run)
    assert [d["result"] for _, d in m.indexed] == ["ok", "alert"]
    assert all(i == "soc-metrics" and d["type"] == "integrity_check" for i, d in m.indexed)


def test_fara_cheie_de_metrici_e_esec():
    run = _run()
    A.write_heartbeat(None, run)
    assert run.failed


# ---------------- orchestratorul pazeste pulsul ----------------

class W:
    def __init__(self, age):
        self.age = age

    def search(self, **kw):
        assert kw["query"] == {"term": {"type.keyword": "integrity_check"}}
        v = None if self.age is None else (NOW - timedelta(minutes=self.age)).isoformat()
        return {"aggregations": {"last": {"value_as_string": v}}}


@pytest.mark.parametrize("age,pagineaza", [(1, False), (4.9, False), (6, True), (None, True)])
def test_orchestrator_pagineaza_cand_pulsul_lipseste(monkeypatch, izolat, age, pagineaza):
    monkeypatch.setattr(orchestrator, "WRITER", W(age))
    orchestrator._integrity_watch(NOW)
    assert bool(izolat) is pagineaza
    if pagineaza:
        assert izolat[0][1]["dedup_key"] == "integrity:checker_down"


def test_orchestrator_nu_cade_daca_es_cade(monkeypatch, izolat):
    class Boom:
        def search(self, **kw):
            raise ConnectionError("x")
    monkeypatch.setattr(orchestrator, "WRITER", Boom())
    orchestrator._integrity_watch(NOW)   # nu ridica
    assert izolat == []

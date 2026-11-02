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


# ---------------- 1b.2: hash-uri pe web-prod prin soc-reader ----------------

H1, H2, H3 = "a" * 64, "b" * 64, "c" * 64


@pytest.fixture
def hashes(monkeypatch, tmp_path):
    ref, state = tmp_path / "canary.sha256", tmp_path / "cron.sha256"
    monkeypatch.setattr(A, "CANARY_REF", str(ref))
    monkeypatch.setattr(A, "CRON_STATE", str(state))
    out = {}
    def run(cmd):
        assert isinstance(cmd, A.reader.ReaderCommand)      # doar comenzi din enumerare
        if isinstance(out.get(cmd), Exception):
            raise out[cmd]
        return out.get(cmd, "")
    monkeypatch.setattr(A.reader, "run", run)
    return ref, state, out


def _sums(d):
    return "".join(f"{h}  {p}\n" for p, h in d.items())


def test_hash_diff():
    assert A.hash_diff({"/a": H1, "/b": H2}, {"/a": H3, "/c": H1}) == {
        "added": ["/c"], "removed": ["/b"], "changed": ["/a"]}


def test_canar_identic_cu_referinta(hashes):
    ref, _, out = hashes
    ref.write_text(_sums({"/usr/local/bin/soc-canary": H1, "/etc/cron.d/soc-canary": H2}))
    out[A.reader.ReaderCommand.CANARY_HASH] = _sums({"/usr/local/bin/soc-canary": H1, "/etc/cron.d/soc-canary": H2})
    run = _run()
    A.check_canary_hash(run)
    assert run.kinds == [] and not run.failed


def test_canar_modificat_e_critic(hashes):
    ref, _, out = hashes
    ref.write_text(_sums({"/usr/local/bin/soc-canary": H1, "/etc/cron.d/soc-canary": H2}))
    out[A.reader.ReaderCommand.CANARY_HASH] = _sums({"/usr/local/bin/soc-canary": H3, "/etc/cron.d/soc-canary": H2})
    inc = FakeES()
    run = _run(inc)
    A.check_canary_hash(run)
    assert run.kinds == ["canary_tampered:canary_hash"]
    assert inc.indexed[0][1]["severity"] == "critical"
    # referinta NU se actualizeaza singura: o scrie omul
    assert H1 in ref.read_text()


def test_canar_fara_referinta_nu_trece_drept_ok(hashes):
    run = _run()
    A.check_canary_hash(run)
    assert run.failed and run.kinds == ["check_failed:canary_ref"]


def test_cron_invata_apoi_raporteaza_o_data(hashes):
    _, state, out = hashes
    out[A.reader.ReaderCommand.CRON_HASH] = _sums({"/etc/crontab": H1, "/etc/cron.d/php": H2})
    run = _run()
    A.check_cron_hash(run)                       # prima rulare: invata, fara alerta
    assert run.kinds == [] and A.reader.parse_sha256sum(state.read_text()) == {
        "/etc/crontab": H1, "/etc/cron.d/php": H2}
    out[A.reader.ReaderCommand.CRON_HASH] = _sums({"/etc/crontab": H1, "/etc/cron.d/php": H2,
                                                   "/etc/cron.d/evil": H3})
    run = _run()
    A.check_cron_hash(run)
    assert run.kinds == ["cron_changed:cron"]
    run = _run()
    A.check_cron_hash(run)                       # aceeasi stare: raportat o singura data
    assert run.kinds == []


def test_cron_raspuns_gol_e_esec(hashes):
    with pytest.raises(A.reader.ReaderError):
        A.check_cron_hash(_run())


def test_main_hash_doar_la_10_minute_si_esecul_escaladeaza(monkeypatch, hashes):
    ref, _, out = hashes
    ref.write_text(_sums({"/usr/local/bin/soc-canary": H1}))
    out[A.reader.ReaderCommand.CANARY_HASH] = A.reader.ReaderError("DENIED de gate")
    for fn in ("check_services", "check_fleet_server", "check_backup", "check_canary", "check_streams",
               "check_orchestrator_cycles", "check_llm_probe", "check_es_health",
               "check_suricata_rules"):
        monkeypatch.setattr(A, fn, lambda *a, **k: None)
    monkeypatch.setattr(A, "_es", lambda: FakeES())
    monkeypatch.setattr(A, "write_heartbeat", lambda m, run: seen.append(run))
    monkeypatch.setattr(A, "_client", lambda var, req: FakeES())
    seen = []

    class T(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls._t
    monkeypatch.setattr(A, "datetime", T)
    T._t = NOW.replace(minute=7)
    assert A.main() == 0 and seen[-1].kinds == []          # nu e minutul de hash
    T._t = NOW.replace(minute=10)
    out[A.reader.ReaderCommand.CRON_HASH] = _sums({"/etc/crontab": H1})
    assert A.main() == 1
    assert "check_failed:check_canar_hash" in seen[-1].kinds and seen[-1].failed


# --- pasul 7: orchestrator blocat / lent, sonda LLM tacuta ------------------------------

class _MetricsES:
    """Raspunde la _last_age_min (agregarea max) si la numararea ciclurilor lente."""
    def __init__(self, last: str | None, slow: int = 0):
        self.last, self.slow = last, slow

    def search(self, index, size=0, query=None, aggs=None, **kw):
        if aggs:
            return {"aggregations": {"last": {"value_as_string": self.last}}}
        return {"hits": {"total": {"value": self.slow}}}


def test_orchestrator_blocat_cand_ultimul_ciclu_e_vechi():
    run = _run()
    old = (run.now - timedelta(minutes=A.CYCLE_MAX_AGE_MIN + 1)).isoformat()
    A.check_orchestrator_cycles(_MetricsES(old), run)
    assert run.kinds == ["orchestrator_stalled:soc-orchestrator"]


def test_orchestrator_fara_niciun_ciclu_e_blocat():
    run = _run()
    A.check_orchestrator_cycles(_MetricsES(None), run)
    assert run.kinds == ["orchestrator_stalled:soc-orchestrator"]


def test_orchestrator_lent_si_normal():
    run = _run()
    A.check_orchestrator_cycles(_MetricsES(run.now.isoformat(), slow=A.SLOW_COUNT), run)
    assert run.kinds == ["orchestrator_slow:soc-orchestrator"]
    run = _run()
    A.check_orchestrator_cycles(_MetricsES(run.now.isoformat(), slow=A.SLOW_COUNT - 1), run)
    assert run.kinds == []


def test_sonda_llm_tacuta():
    run = _run()
    A.check_llm_probe(_MetricsES((run.now - timedelta(minutes=9)).isoformat()), run)
    assert run.kinds == ["probe_missing:soc-llm-probe"]
    run = _run()
    A.check_llm_probe(_MetricsES(run.now.isoformat()), run)
    assert run.kinds == []


# --- pasul 11: sanatatea Elasticsearch ------------------------------------------------

def _nodes(avail, total=100, heap=50):
    return {"nodes": {"n1": {"name": "es01", "fs": {"total": {"total_in_bytes": total,
                                                              "available_in_bytes": avail}},
                             "jvm": {"mem": {"heap_used_percent": heap}}}}}


def test_es_galben_e_normal_rosu_nu():
    assert A.es_health_problems({"status": "yellow"}, _nodes(85)) == []
    kinds = [k for k, _, _ in A.es_health_problems({"status": "red", "unassigned_shards": 3}, _nodes(85))]
    assert kinds == ["es_red"]


def test_es_disc_si_heap_peste_prag():
    probs = A.es_health_problems({"status": "green"}, _nodes(avail=15, heap=95))
    assert {k for k, _, _ in probs} == {"es_disk", "es_heap"}
    assert A.es_health_problems({"status": "green"}, _nodes(avail=25, heap=90)) == []


# --- pasul 12: vechimea regulilor Suricata --------------------------------------------

class _EsqlES:
    def __init__(self, values):
        self.values = values

    class _E:
        pass

    @property
    def esql(self):
        outer = self
        class Q:
            def query(self, query, format):
                assert "soc-suricata-update" in query and 'STARTS_WITH(message, "OK")' in query
                return {"values": outer.values}
        return Q()


def test_reguli_suricata_oprit_implicit(monkeypatch):
    monkeypatch.setattr(A, "SURICATA_RULES_CHECK", False)
    run = _run()
    A.check_suricata_rules(_EsqlES([]), run)
    assert run.kinds == []


def test_reguli_suricata_vechi_sau_lipsa(monkeypatch):
    monkeypatch.setattr(A, "SURICATA_RULES_CHECK", True)
    run = _run()
    A.check_suricata_rules(_EsqlES([]), run)
    assert run.kinds == ["suricata_rules_stale:suricata_rules"]
    run = _run()
    old = (run.now - timedelta(hours=30)).isoformat()
    A.check_suricata_rules(_EsqlES([[old]]), run)
    assert run.kinds == ["suricata_rules_stale:suricata_rules"]
    run = _run()
    A.check_suricata_rules(_EsqlES([[(run.now - timedelta(hours=3)).isoformat()]]), run)
    assert run.kinds == []

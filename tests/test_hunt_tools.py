"""Faza 22 G: uneltele Tier 2 fara text liber in interogari (principiul 3).
Fara Elasticsearch: _esql si ES.eql.search sunt inlocuite cu dubluri care inregistreaza sau arunca."""
from __future__ import annotations

import pytest

import elastic_tools as T


class _Boom(Exception):
    pass


@pytest.fixture
def no_es(monkeypatch):
    """Orice interogare = esec: testele pentru intrari respinse dovedesc ca nu se interogheaza."""
    def boom(*a, **k):
        raise _Boom("interogare nepermisa")
    monkeypatch.setattr(T, "_esql", boom)
    monkeypatch.setattr(T.ES.eql, "search", boom, raising=False)


@pytest.fixture
def capture(monkeypatch):
    calls: dict = {"esql": [], "eql": []}

    def esql(q, params=None):
        calls["esql"].append((q, list(params or [])))
        return []

    def eql(**kw):
        calls["eql"].append(kw)
        return {"hits": {"sequences": [], "events": []}}
    monkeypatch.setattr(T, "_esql", esql)
    monkeypatch.setattr(T.ES.eql, "search", eql, raising=False)
    return calls


# --- tool_rarity_of ------------------------------------------------------------------------

@pytest.mark.parametrize("field", ["process.name | LIMIT 1", "host.name", "1=1", "", "process.title",
                                   "process.name == \"x\" OR true"])
def test_rarity_camp_nepermis_fara_interogare(no_es, field):
    out = T.tool_rarity_of.invoke({"field": field, "value": "bash"})
    assert "error" in out and set(out["allowed"]) == set(T.RARITY_FIELDS)


@pytest.mark.parametrize("field", sorted(T.RARITY_FIELDS))
def test_rarity_camp_permis_interogare_parametrizata(capture, field):
    out = T.tool_rarity_of.invoke({"field": field, "value": "x' OR 1=1", "host_name": "web-prod"})
    assert "error" not in out and out["occurrences_90d"] == 0
    q, params = capture["esql"][-1]
    assert f"WHERE {field} == ?" in q and "host.name == ?" in q
    assert params == ["x' OR 1=1", "web-prod"]      # valoarea doar ca parametru
    assert "1=1" not in q and "LIKE" not in q.upper()
    assert f"FROM {T._RARITY_INDEX[field]}" in q      # indexul vine din catalog, nu din model


# --- tool_eql_pattern ----------------------------------------------------------------------

@pytest.mark.parametrize("pid", ["sequence by host.id [any where true]", "", "webshell", "WEBSHELL_WRITE_THEN_EXEC"])
def test_eql_pattern_necunoscut_fara_interogare(no_es, pid):
    out = T.tool_eql_pattern.invoke({"pattern_id": pid, "host_name": "web-prod"})
    assert "error" in out and out["allowed"] == sorted(T.EQL_PATTERNS)


@pytest.mark.parametrize("pid", sorted(T.EQL_PATTERNS))
def test_eql_pattern_cunoscut_host_in_filter_nu_in_text(capture, pid):
    host = 'web-prod" or true'
    out = T.tool_eql_pattern.invoke({"pattern_id": pid, "host_name": host, "minutes": 45})
    assert "error" not in out and out["minutes"] == 45
    kw = capture["eql"][-1]
    assert kw["query"] == T.EQL_PATTERNS[pid]["query"] and kw["index"] == T.EQL_PATTERNS[pid]["index"]
    assert host not in kw["query"]
    filters = kw["filter"]["bool"]["filter"]
    assert {"term": {"host.name": host}} in filters
    assert {"range": {"@timestamp": {"gte": "now-45m"}}} in filters


def test_eql_pattern_indexul_e_fix_endpoint():
    for p in T.EQL_PATTERNS.values():
        assert "sequence by host.id" in p["query"] and "maxspan" in p["query"]
        for idx in p["index"].split(","):
            assert idx in (T.PROC_IDX, T.FILE_IDX, T.NET_IDX)


def test_numele_vechi_nu_mai_exista():
    assert not hasattr(T, "tool_eql_sequence")
    names = {t.name for t in T.HUNT_TOOLS}
    assert "tool_eql_pattern" in names and "tool_eql_sequence" not in names


# --- plafonul pe minute --------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [(0, 1), (-5, 1), (1, 1), (30, 30), ("90", 90), (1440, 1440),
                                          (99999, 1440), (2.9, 2)])
def test_minutes_plafonat(raw, expected):
    assert T._minutes(raw) == expected


@pytest.mark.parametrize("raw", ["5 minutes | LIMIT 1", "", "abc", None])
def test_minutes_nenumeric_ridica(raw):
    with pytest.raises((ValueError, TypeError)):
        T._minutes(raw)


def test_toate_uneltele_cu_minute_folosesc_plafonul(capture):
    T.tool_process_tree.invoke({"host_name": "h", "entity_id": "e", "minutes": 99999})
    T.tool_egress_for_host.invoke({"host_name": "h", "minutes": 0})
    T.tool_apache_requests.invoke({"host_name": "h", "minutes": -1})
    T.tool_suricata_alerts.invoke({"source_ip": "1.2.3.4", "minutes": 5000})
    windows = [q.split("NOW() - ")[1].split(" minutes")[0] for q, _ in capture["esql"]]
    assert windows == ["1440", "1", "1", "1440"]
    T.tool_eql_pattern.invoke({"pattern_id": "cron_write_then_exec", "host_name": "h", "minutes": 100000})
    assert capture["eql"][-1]["filter"]["bool"]["filter"][1] == {"range": {"@timestamp": {"gte": "now-1440m"}}}

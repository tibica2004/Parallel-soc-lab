"""Trasarea: ID-uri fara continut, modelul vede acelasi rezultat, contextul
trece prin firul cu plafon si prin ToolNode, evidence_refs construite de cod."""
import sys
import types
import uuid
from datetime import datetime, timezone

import pytest
from langchain_core.messages import AIMessage
from langgraph.prebuilt import ToolNode

import degraded
import elastic_tools
import orchestrator
import tracing
from schemas import EvidenceRef, Verdict

TS = "2026-10-09T10:00:00.000Z"


def _row(i):
    return {"_id": f"id{i}", "_index": ".ds-logs-endpoint.events.process-default",
            "@timestamp": TS, "process.name": "dash", "process.command_line": 'sh -c "id"'}


# ---------------- functii pure ----------------

def test_extract_refs_scoate_id_din_ce_vede_modelul():
    clean, refs, n = tracing.extract_refs({"rows": [_row(1), _row(2)], "count": 2})
    assert n == 2 and [r["id"] for r in refs] == ["id1", "id2"]
    assert all("_id" not in r and "_index" not in r for r in clean["rows"])
    assert clean["rows"][0]["process.command_line"] == 'sh -c "id"' and clean["count"] == 2


def test_extract_refs_eql_si_agregate():
    _, refs, n = tracing.extract_refs({"sequences": [], "events": [
        {"_id": "e1", "_index": "idx", "_source": {"@timestamp": TS}}]})
    assert n == 1 and refs == [{"index": "idx", "id": "e1", "timestamp": TS}]
    clean, refs, n = tracing.extract_refs({"rows": [{"destination.ip": "1.2.3.4", "bytes": 10}]})
    assert refs == [] and n == 1
    assert tracing.extract_refs("text") == ("text", [], None)


def test_fara_caz_deschis_nu_inregistreaza():
    f = tracing.traced_tool("t", lambda **k: {"rows": [_row(1)]})
    assert f(x=1) == {"rows": [{k: v for k, v in _row(1).items() if k not in ("_id", "_index")}]}
    tracing.record_llm("fast", 10, 5)   # nu crapa


def test_unealta_inregistrata_cu_argumente_si_eroare():
    ok = tracing.traced_tool("ok", lambda **k: {"rows": [_row(1)]})
    def boom(**k):
        raise RuntimeError("ES cazut")
    bad = tracing.traced_tool("bad", boom)
    with tracing.case() as tr:
        ok(host_name="web-prod", query="x" * 2000)
        with pytest.raises(RuntimeError):
            bad(host_name="web-prod")
        tracing.record_llm("investigator_a", 120, 900, ["ok"])
    e1, e2, e3 = tr.events
    assert e1["name"] == "ok" and e1["rows"] == 1 and e1["doc_refs"][0]["id"] == "id1"
    assert len(e1["args"]) == tracing.MAX_ARGS_CHARS and e1["error"] is None
    assert e2["error"] == "RuntimeError" and e2["doc_refs"] == []
    assert e3 == {"type": "llm", "role": "investigator_a", "tokens": 120, "duration_ms": 900, "tool_calls": ["ok"]}
    t = tr.totals()
    assert (t["tool_calls"], t["tool_errors"], t["llm_calls"], t["tokens"], t["doc_refs"]) == (2, 1, 1, 120, 1)


def test_refs_unice_si_limitate():
    with tracing.case() as tr:
        f = tracing.traced_tool("t", lambda **k: {"rows": [_row(i) for i in range(40)]})
        f(); f()                                       # aceleasi 40 de doua ori
        g = tracing.traced_tool("g", lambda **k: {"rows": [_row(i) for i in range(40, 80)]})
        g()
    refs = tr.refs()
    assert len(refs) == 50 and len({r.doc_id for r in refs}) == 50
    assert all(isinstance(r, EvidenceRef) for r in refs)


def test_ref_fara_timestamp_ignorata():
    with tracing.case() as tr:
        tracing.traced_tool("t", lambda **k: {"rows": [{"_id": "a", "_index": "i"}]})()
    assert tr.refs() == []


def test_cazurile_nu_se_amesteca():
    f = tracing.traced_tool("t", lambda **k: {"rows": [_row(1)]})
    with tracing.case() as a:
        f()
    with tracing.case() as b:
        pass
    assert len(a.events) == 1 and b.events == [] and tracing.current() is None


def test_contextul_trece_prin_firul_cu_plafon():
    f = tracing.traced_tool("t", lambda **k: {"rows": [_row(1)]})
    with tracing.case() as tr:
        degraded.run_with_timeout(lambda: f(), 2)
    assert len(tr.events) == 1


def test_contextul_trece_prin_toolnode(monkeypatch):
    """ToolNode (langgraph) ruleaza uneltele in executor propriu: urma trebuie sa ajunga."""
    monkeypatch.setattr(elastic_tools, "_esql", lambda q, params=None: [_row(1), _row(2)])
    from langgraph.graph import END, START, MessagesState, StateGraph
    g = StateGraph(MessagesState)
    g.add_node("tools", ToolNode(elastic_tools.HUNT_TOOLS))
    g.add_edge(START, "tools"); g.add_edge("tools", END)
    node = g.compile()
    msg = AIMessage(content="", tool_calls=[{"name": "tool_process_tree", "id": "c1",
                                             "args": {"host_name": "web-prod", "entity_id": "E1"}}])
    with tracing.case() as tr:
        out = degraded.run_with_timeout(lambda: node.invoke({"messages": [msg]}), 5)
    ev = [e for e in tr.events if e["type"] == "tool"]
    assert len(ev) == 1 and ev[0]["name"] == "tool_process_tree" and len(ev[0]["doc_refs"]) == 2
    assert "id1" not in out["messages"][-1].content     # modelul nu vede ID-urile


def test_uneltele_cer_id_urile_documentelor(monkeypatch):
    seen = []
    monkeypatch.setattr(elastic_tools, "_esql", lambda q, params=None: (seen.append(q), [])[1])
    elastic_tools.tool_process_tree.invoke({"host_name": "h", "entity_id": "e"})
    elastic_tools.tool_apache_requests.invoke({"host_name": "h"})
    elastic_tools.tool_suricata_alerts.invoke({"source_ip": "1.2.3.4"})
    assert all("METADATA _id, _index" in q and "KEEP _id, _index" in q for q in seen)


def test_minutes_fortat_numar(monkeypatch):
    monkeypatch.setattr(elastic_tools, "_esql", lambda q, params=None: [])
    with pytest.raises(Exception):
        elastic_tools.tool_egress_for_host.invoke({"host_name": "h", "minutes": "5 minutes | LIMIT 1"})


# ---------------- orchestrator ----------------

def _verdict():
    return Verdict(investigation_id=str(uuid.uuid4()), source_path="fast", entity_type="host",
                   entity_id="web-prod", classification="malicious", confidence=95,
                   rarity_score=1.0, model_id="m")


def test_alerta_si_urma_devin_evidence_refs(monkeypatch):
    calls = []
    monkeypatch.setattr(orchestrator, "show", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "persist", lambda *a, **k: calls.append(("p", a, k)))
    monkeypatch.setattr(orchestrator, "persist_trace", lambda doc: calls.append(("t", doc)))
    tool = tracing.traced_tool("t", lambda **k: {"rows": [_row(7)]})
    def invoke(inp, config=None):
        tool()
        tracing.record_llm("fast.verdict", 300, 1200)
        return {"verdict": _verdict(), "narrative": "", "context": {"pair_in_baseline": True}}
    monkeypatch.setitem(sys.modules, "fast_path", types.SimpleNamespace(
        build_fast_path=lambda: types.SimpleNamespace(invoke=invoke), lookup_asset=lambda h: {}))
    alert = {"@timestamp": TS, "host": {"name": "web-prod"}, "kibana.alert.rule.name": "R",
             "process": {"entity_id": "E1"}, "_soc_ref": {"index": ".internal.alerts-x", "id": "AL1"}}
    orchestrator.process_alerts([alert], orchestrator.BoundedSeen())
    (_, (v, *_), _), (_, doc) = calls
    assert [(r.index, r.doc_id) for r in v.evidence_refs] == [(".internal.alerts-x", "AL1"),
                                                              (".ds-logs-endpoint.events.process-default", "id7")]
    assert doc["chain_id"] == v.chain_id and doc["investigation_id"] == v.investigation_id
    assert doc["totals"]["tokens"] == 300 and doc["totals"]["tool_calls"] == 1 and doc["failure"] is None


def test_urma_si_pentru_cazurile_fara_model(monkeypatch):
    docs = []
    monkeypatch.setattr(orchestrator, "show", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "persist", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "persist_trace", docs.append)
    alert = {"@timestamp": TS, "host": {"name": "web-prod"}, "kibana.alert.rule.name": "R",
             "_soc_ref": {"index": "i", "id": "AL2"}}
    orchestrator.process_alerts([alert], orchestrator.BoundedSeen(), model_ok=False)
    assert docs[0]["failure"] == "model_unavailable" and docs[0]["events"] == []


def test_persist_trace_esec_semnalat_o_data(monkeypatch, capsys):
    from elasticsearch import AuthorizationException
    def deny(index, document, id=None):
        raise AuthorizationException("403", meta=type("M", (), {"status": 403})(), body={})
    monkeypatch.setattr(orchestrator, "WRITER", types.SimpleNamespace(index=deny))
    monkeypatch.setattr(orchestrator, "_trace_warned", False)
    orchestrator.persist_trace({"a": 1}); orchestrator.persist_trace({"a": 2})
    assert capsys.readouterr().out.count("soc-traces a esuat") == 1


def test_with_evidence_unic_si_validat():
    r = EvidenceRef(index="i", doc_id="d", timestamp=datetime.now(timezone.utc))
    v = orchestrator.with_evidence(_verdict(), [r, r, None])
    assert len(v.evidence_refs) == 1
    v2 = orchestrator.with_evidence(v, [EvidenceRef(index="i", doc_id=str(n), timestamp=r.timestamp) for n in range(80)])
    assert len(v2.evidence_refs) == 50


def test_fetch_alerts_adauga_referinta(monkeypatch):
    monkeypatch.setattr(orchestrator, "ES", types.SimpleNamespace(search=lambda **k: {"hits": {"hits": [
        {"_index": ".internal.alerts-x", "_id": "AL9", "_source": {"@timestamp": TS}}]}}))
    a, = orchestrator.fetch_alerts_between(datetime.now(timezone.utc), datetime.now(timezone.utc), 5)
    assert a["_soc_ref"] == {"index": ".internal.alerts-x", "id": "AL9"}
    assert orchestrator.alert_ref(a).doc_id == "AL9"


def test_fast_path_inregistreaza_tokenii(monkeypatch):
    import fast_path
    resp = types.SimpleNamespace(content='{"classification":"benign","confidence":90}',
                                 usage_metadata={"total_tokens": 777})
    monkeypatch.setattr(fast_path, "llm_fast", types.SimpleNamespace(invoke=lambda msgs: resp))
    with tracing.case() as tr:
        out = fast_path._ask("sys", {"x": 1}, {}, "fast.verdict")
    assert out["classification"] == "benign"
    assert tr.events[0]["role"] == "fast.verdict" and tr.events[0]["tokens"] == 777

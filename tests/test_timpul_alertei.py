"""Faza 25: verdictul se socoteste fata de momentul alertei, nu fata de momentul prelucrarii.
Fara model si fara Elasticsearch: ES si _esql sunt dubluri."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from elasticlab.contracts.schemas import Case, EntityType, EscalationReason as R, RarityFinding
from elasticlab.core.escalation import EscalationDecision
from elasticlab.tier2 import case_adapter

CID = str(uuid.uuid4())
ESC = EscalationDecision(escalate=True, reasons=[R.SUSPICIOUS])
T_EVT = datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)


def _alert(**kw):
    a = {"@timestamp": "2026-11-23T10:04:00Z", "kibana.alert.original_time": "2026-11-23T10:00:00Z",
         "host": {"name": "web-prod"}, "kibana.alert.rule.name": "RCE: Web server spawns shell",
         "process": {"entity_id": "Kw1Y4COo3NG/M4W+r5fQ==", "name": "id", "parent": {"name": "dash"}}}
    a.update(kw)
    return a


def _finding(at=None):
    return RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                         detail={"parent": "dash", "child": "id"}, rarity_score=1.0, observed_at=at)


# ---------------- contractele ----------------

def test_cazul_din_alerta_poarta_ora_evenimentului():
    assert case_adapter.from_alert(_alert(), ESC, CID).observed_at == T_EVT


def test_fara_original_time_cade_pe_timestamp():
    a = _alert()
    del a["kibana.alert.original_time"]
    assert case_adapter.from_alert(a, ESC, CID).observed_at == datetime(2026, 11, 23, 10, 4, tzinfo=timezone.utc)


def test_alerta_fara_timp_lasa_ancora_goala():
    a = _alert()
    del a["kibana.alert.original_time"]
    a["@timestamp"] = "nu e o data"
    assert case_adapter.from_alert(a, ESC, CID).observed_at is None


def test_cazul_din_finding_pastreaza_momentul_sweep_ului():
    assert case_adapter.from_finding(_finding(T_EVT), CID).observed_at == T_EVT
    assert case_adapter.from_finding(_finding(), CID).observed_at is None


def test_momentul_fara_fus_orar_e_respins():
    with pytest.raises(ValidationError):
        Case(chain_id=CID, origin="tier1_alert", host="web-prod", observed_at=datetime(2026, 11, 23, 10, 0))
    with pytest.raises(ValidationError):
        _finding(datetime(2026, 11, 23, 10, 0))


# ================================================================================================
# Intarziere simulata: aceeasi alerta prelucrata imediat (+5 min) si dupa 60 de minute (+65 min).
#
# `Lume` e un Elasticsearch fals cu ceas: ce s-a intamplat dupa ceas nu exista inca, iar NOW()
# din interogari e ceasul. Pe host continua activitatea dupa alerta (alte alerte, alt copil al
# procesului, un verdict scris si etichetat cat a asteptat cazul). Cu ancora, ce vede sistemul
# e acelasi la +5 si la +65; fara ancora (controlul) difera, deci lumea chiar pune la incercare.
# ================================================================================================

import hashlib  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
from datetime import timedelta  # noqa: E402

from elasticlab.core import eventtime  # noqa: E402

M = timedelta(minutes=1)
T = T_EVT
IMEDIAT, INTARZIAT = T + 5 * M, T + 65 * M
ISO_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
UNIT = {"minutes": "minutes", "hours": "hours", "days": "days"}


def _proc(at, eid, name, parent, peid, user="www-data", cmd=None):
    return {"@timestamp": eventtime.iso(at), "process.entity_id": eid, "process.name": name,
            "process.parent.name": parent, "process.parent.entity_id": peid, "user.name": user,
            "process.executable": f"/usr/bin/{name}", "process.command_line": cmd or name,
            "process.working_directory": "/var/www/html"}


PROCS = [
    _proc(T - 2 * M, "E0", "dash", "apache2", "A0"),
    _proc(T, "E1", "crontab", "dash", "E0", cmd="crontab -l"),           # procesul din alerta
    _proc(T + 3 * M, "E2", "whoami", "crontab", "E1"),                    # urmeaza imediat
    _proc(T + 40 * M, "E3", "curl", "crontab", "E1", cmd="curl http://x/"),  # mult dupa alerta
]
ALERTS = [{"@timestamp": eventtime.iso(T + d * M)} for d in (-30, 0, 20)]
NET = [{"@timestamp": eventtime.iso(T + d * M), "destination.ip": f"203.0.113.{i}", "process.name": "x"}
       for i, d in enumerate((1, 45))]
APACHE = [{"@timestamp": eventtime.iso(T + d * M), "url.path": f"/p{d}"} for d in (-1, 30)]
VERDICTS = [  # verdicts-history: unul vechi, unul scris (si etichetat) cat a asteptat alerta
    {"@timestamp": eventtime.iso(T - 1440 * M), "entity_id": "web-prod", "classification": "benign",
     "ground_truth": "benign", "rule_name": "RCE: Web server spawns shell", "notes": "vechi"},
    {"@timestamp": eventtime.iso(T + 15 * M), "entity_id": "web-prod", "classification": "malicious",
     "ground_truth": "attack", "rule_name": "RCE: Web server spawns shell", "notes": "in coada"},
]
ASSET = {"criticality": "high", "role": "web", "normal_admins": ["tiberiu"],
         "maintenance_windows": [{"start_at": eventtime.iso(T - 10 * M), "end_at": eventtime.iso(T + 30 * M),
                                  "reason": "test"}]}


def _ts(d):
    return eventtime.parse(d["@timestamp"])


class Lume:
    def __init__(self, clock):
        self.clock = clock
        self.esql_calls, self.search_calls = [], []
        self.eql = self

    # --- ES|QL -------------------------------------------------------------------------------
    def _window(self, q, params):
        m = re.search(r"NOW\(\) - (\d+) (minutes|hours|days)", q)
        if m:
            return self.clock - timedelta(**{m.group(2): int(m.group(1))}), self.clock
        if "TO_DATETIME(?)" in q:
            lo, hi = [eventtime.parse(p) for p in params if isinstance(p, str) and ISO_RE.match(p)]
            return lo, hi
        return None, None

    def esql(self, q, params=None):
        params = list(params or [])
        self.esql_calls.append((q, params))
        lo, hi = self._window(q, params)
        if "STATS cnt = COUNT(*)" in q:   # raritate: aparitiile valorii cerute
            rows = [r for r in PROCS if r["process.name"] in params]
        elif "process-*" in q:
            rows = PROCS
        elif ".alerts-security" in q:
            rows = ALERTS
        elif "network-*" in q:
            rows = NET
        elif "apache" in q:
            rows = APACHE
        else:
            rows = []
        rows = [r for r in rows if _ts(r) <= self.clock and (lo is None or lo <= _ts(r) <= hi)]
        if "process.parent.entity_id == ?" in q and "OR" in q:          # arborele de procese
            rows = [r for r in rows if r["process.entity_id"] in params or r["process.parent.entity_id"] in params]
        elif "process.entity_id == ?" in q:
            rows = [r for r in rows if r["process.entity_id"] in params]
            if "user.Ext.real.name" in q:
                return []
        if "STATS n = COUNT(*)" in q:
            return [{"n": len(rows)}]
        if "STATS cnt = COUNT(*)" in q:
            ts = sorted(r["@timestamp"] for r in rows)
            return [{"cnt": len(rows), "first_seen": ts[0] if ts else None, "last_seen": ts[-1] if ts else None}]
        if "SORT @timestamp DESC" in q:
            rows = sorted(rows, key=_ts, reverse=True)
        lim = re.search(r"LIMIT (\d+)", q)
        return [dict(r) for r in rows[: int(lim.group(1)) if lim else None]]

    # --- Query DSL -----------------------------------------------------------------------------
    def get(self, index, id):
        return {"_source": ASSET}

    def count(self, index, query):
        return {"count": 0}

    def search(self, index, size=10, query=None, sort=None, **kw):
        self.search_calls.append(query)
        filters = (query or {}).get("bool", {}).get("filter", [query] if query else [])
        docs = [d for d in VERDICTS if _ts(d) <= self.clock]
        for f in filters:
            if "range" in f:
                docs = [d for d in docs if _ts(d) <= eventtime.parse(f["range"]["@timestamp"]["lte"])]
            if "exists" in f:
                docs = [d for d in docs if d.get(f["exists"]["field"])]
        docs = sorted(docs, key=_ts, reverse=True)[:size]
        return {"hits": {"hits": [{"_source": d} for d in docs]}}

    # --- EQL (ES.eql.search) -------------------------------------------------------------------
    def search_eql(self, index, query, size, filter):
        rng = filter["bool"]["filter"][1]["range"]["@timestamp"]
        if str(rng["gte"]).startswith("now-"):
            lo, hi = self.clock - timedelta(minutes=int(rng["gte"][4:-1])), self.clock
        else:
            lo, hi = eventtime.parse(rng["gte"]), eventtime.parse(rng["lte"])
        ev = [r for r in PROCS if _ts(r) <= self.clock and lo <= _ts(r) <= hi]
        return {"hits": {"sequences": [], "events": [{"_source": r} for r in ev]}}


class _Eql:
    def __init__(self, lume):
        self.search = lume.search_eql


def _instaleaza(monkeypatch, lume):
    from elasticlab.tier1 import fast_path
    from elasticlab.tier2 import elastic_tools, hunt_path
    es = type("ES", (), {})()
    es.get, es.count, es.search, es.eql = lume.get, lume.count, lume.search, _Eql(lume)
    es.esql = type("Q", (), {"query": None})()
    for mod in (fast_path, hunt_path, elastic_tools):
        monkeypatch.setattr(mod, "ES", es)
        monkeypatch.setattr(mod, "_esql", lume.esql)


def _case(at=T):
    return Case(chain_id=CID, origin="tier1_alert", host="web-prod", entity_id="E1", parent="dash",
                child="crontab", rule_name="RCE: Web server spawns shell",
                escalation_reasons=[R.SUSPICIOUS], rarity_score=1.0, observed_at=at)


# ---------------- contextul preadus al Tier 2 ----------------

def _prefetch(monkeypatch, clock, at):
    from elasticlab.tier2 import hunt_path
    _instaleaza(monkeypatch, Lume(clock))
    return hunt_path.prefetch_context(_case(at))


def test_contextul_tier2_nu_depinde_de_intarziere(monkeypatch):
    imediat = _prefetch(monkeypatch, IMEDIAT, T)
    intarziat = _prefetch(monkeypatch, INTARZIAT, T)
    assert imediat == intarziat
    assert imediat["recent_host_alerts"] == 2                  # -30 si 0; cea de la +20 nu
    assert [v["classification"] for v in imediat["past_verdicts"]] == ["benign"]
    assert imediat["execution"]["entity_id"] == "E1" and imediat["in_maintenance_window"] is True


def test_control_fara_ancora_contextul_difera(monkeypatch):
    """Fara momentul cazului (forma veche, NOW()), aceeasi lume da alt context la +65:
    testul de mai sus chiar pune la incercare ancora."""
    imediat = _prefetch(monkeypatch, IMEDIAT, None)
    intarziat = _prefetch(monkeypatch, INTARZIAT, None)
    assert imediat["recent_host_alerts"] != intarziat["recent_host_alerts"]
    assert imediat["past_verdicts"] != intarziat["past_verdicts"]


# ---------------- uneltele Tier 2 ----------------

CALLS = [
    ("tool_process_tree", {"host_name": "web-prod", "entity_id": "E1", "minutes": 30}),
    ("tool_egress_for_host", {"host_name": "web-prod", "minutes": 15}),
    ("tool_apache_requests", {"host_name": "web-prod", "minutes": 15}),
    ("tool_eql_pattern", {"pattern_id": "web_child_then_egress", "host_name": "web-prod", "minutes": 30}),
    ("tool_suricata_alerts", {"source_ip": "203.0.113.9", "minutes": 60}),
    ("tool_rarity_of", {"field": "process.name", "value": "curl", "host_name": "web-prod"}),
]


def _tools(monkeypatch, clock, at):
    from elasticlab.tier2 import elastic_tools
    lume = Lume(clock)
    _instaleaza(monkeypatch, lume)
    tools = {t.name: t for t in elastic_tools.HUNT_TOOLS}
    with eventtime.anchored(at):
        out = {n: tools[n].invoke(a) for n, a in CALLS}
    return out, lume


def test_uneltele_nu_depind_de_intarziere(monkeypatch):
    imediat, lume = _tools(monkeypatch, IMEDIAT, T)
    intarziat, _ = _tools(monkeypatch, INTARZIAT, T)
    assert imediat == intarziat
    assert [r["process.entity_id"] for r in imediat["tool_process_tree"]["rows"]] == ["E1", "E2"]
    assert imediat["tool_rarity_of"]["occurrences_90d"] == 0       # curl apare abia la +40
    assert not any("NOW()" in q for q, _ in lume.esql_calls)


def test_control_uneltele_fara_ancora_difera(monkeypatch):
    imediat, _ = _tools(monkeypatch, IMEDIAT, None)
    intarziat, lume = _tools(monkeypatch, INTARZIAT, None)
    assert imediat["tool_process_tree"] != intarziat["tool_process_tree"]
    # la +65 arborele vechi (ultimele 30 de minute) nu mai contine procesul din alerta
    assert "E1" not in [r["process.entity_id"] for r in intarziat["tool_process_tree"]["rows"]]
    assert all("NOW()" in q for q, _ in lume.esql_calls)


def test_uneltele_fara_caz_in_curs_trimit_interogarea_veche(monkeypatch):
    """In afara unei investigatii (sweep, apel manual) textul si parametrii sunt cei de dinainte."""
    _, lume = _tools(monkeypatch, IMEDIAT, None)
    q, params = lume.esql_calls[0]
    assert "@timestamp >= NOW() - 30 minutes" in q and params == ["web-prod", "E1", "E1"]


# ---------------- verdictul Tier 2 cap la cap (graful real, model fals) ----------------

class ModelFals:
    """Cheama uneltele o data, apoi da un verdict care depinde de TOT ce a vazut (amprenta
    mesajelor): alt context sau alte rezultate de unelte -> alt verdict."""
    def __init__(self):
        self.seen = []

    def invoke(self, messages):
        from langchain_core.messages import AIMessage, ToolMessage
        contents = [m.content if isinstance(m.content, str) else json.dumps(m.content) for m in messages]
        self.seen.append(contents)
        if not any(isinstance(m, ToolMessage) for m in messages):
            return AIMessage(content="", tool_calls=[{"name": n, "args": a, "id": f"c{i}"}
                                                     for i, (n, a) in enumerate(CALLS)])
        h = int(hashlib.sha256(json.dumps(contents).encode()).hexdigest(), 16)
        return AIMessage(content=json.dumps({
            "classification": ["benign", "suspicious", "malicious"][h % 3], "confidence": 50 + h % 50,
            "proposed_action": "escalate_human", "action_target": None, "mitre_techniques": [],
            "evidence": {"process_chain": True}, "hypotheses_considered": [], "narrative": f"amprenta {h % 997}"}))


def _hunt(monkeypatch, clock, at):
    from elasticlab.tier2 import hunt_path
    if getattr(__import__("langgraph.prebuilt").prebuilt, "__stub__", False):
        pytest.skip("langgraph lipseste (stub de test)")
    _instaleaza(monkeypatch, Lume(clock))
    a, b = ModelFals(), ModelFals()
    monkeypatch.setattr(hunt_path, "INVESTIGATOR_A", hunt_path._build_investigator(a))
    monkeypatch.setattr(hunt_path, "INVESTIGATOR_B", hunt_path._build_investigator(b))
    v = hunt_path.build_hunt_path().invoke({"case": _case(at)}, config={"recursion_limit": 80})["verdict"]
    return v, a.seen + b.seen


def _cheie(v):
    """Verdictul fara identificatorul investigatiei si momentul scrierii (aleatoriu / ceas real)."""
    return v.model_dump(mode="json", exclude={"investigation_id", "created_at"})


def test_verdictul_tier2_nu_depinde_de_intarziere(monkeypatch):
    v1, seen1 = _hunt(monkeypatch, IMEDIAT, T)
    v2, seen2 = _hunt(monkeypatch, INTARZIAT, T)
    assert seen1 == seen2                 # modelul a vazut exact aceleasi mesaje
    assert _cheie(v1) == _cheie(v2)
    # uneltele au rulat cu adevarat (prin ToolNode, in firele LangGraph) si au vazut ancora:
    # copilul de la +3 e in rezultate, cel de la +40 nu, si nicio unealta n-a cazut
    flat = json.dumps(seen2)
    assert "E2" in flat and "E3" not in flat and "Unealta a esuat" not in flat


def test_control_verdictul_tier2_fara_ancora_vede_altceva(monkeypatch):
    _, seen1 = _hunt(monkeypatch, IMEDIAT, None)
    _, seen2 = _hunt(monkeypatch, INTARZIAT, None)
    assert seen1 != seen2


# ---------------- calea rapida (Tier 1) cap la cap ----------------

def _alerta_rapida():
    return {"@timestamp": eventtime.iso(T + 4 * M), "kibana.alert.original_time": eventtime.iso(T),
            "kibana.alert.rule.name": "RCE: Web server spawns shell", "kibana.alert.severity": "high",
            "host": {"name": "web-prod"}, "user": {"name": "tiberiu"},
            "process": {"name": "crontab", "executable": "/usr/bin/crontab", "command_line": "crontab -l",
                        "entity_id": "E1", "parent": {"name": "bash", "entity_id": "E0"}}}


class ModelRapidFals:
    def __init__(self):
        self.seen = []

    def invoke(self, messages):
        from langchain_core.messages import AIMessage
        contents = [m.content for m in messages]
        self.seen.append(contents)
        h = int(hashlib.sha256(json.dumps(contents).encode()).hexdigest(), 16)
        return AIMessage(content=json.dumps({
            "uniqueness": "RARE", "pattern_notes": "x", "classification": ["benign", "suspicious"][h % 2],
            "confidence": 50 + h % 50, "proposed_action": "none", "action_target": None,
            "mitre_techniques": [], "narrative": f"amprenta {h % 997}"}))


def _rapid(monkeypatch, clock):
    from elasticlab.tier1 import fast_path
    if getattr(__import__("langgraph.graph").graph, "__stub__", False):
        pytest.skip("langgraph lipseste (stub de test)")
    lume = Lume(clock)
    _instaleaza(monkeypatch, lume)
    m = ModelRapidFals()
    monkeypatch.setattr(fast_path, "llm_fast", m)
    out = fast_path.build_fast_path().invoke({"alert": _alerta_rapida()}, config={"recursion_limit": 25})
    return out, m.seen, lume


def test_calea_rapida_nu_depinde_de_intarziere(monkeypatch):
    o1, seen1, _ = _rapid(monkeypatch, IMEDIAT)
    o2, seen2, lume = _rapid(monkeypatch, INTARZIAT)
    assert o1["context"] == o2["context"] and seen1 == seen2
    assert _cheie(o1["verdict"]) == _cheie(o2["verdict"])
    # fereastra de mentenanta (pana la +30) se judeca la ora evenimentului, nu la +65
    assert o2["context"]["in_maintenance_window"] is True
    # istoricul etichetat: doar ce era scris la momentul alertei
    assert o2["context"]["fp_rate_same_rule"] == 1.0
    assert any({"range": {"@timestamp": {"lte": eventtime.iso(T)}}} in q["bool"]["filter"]
               for q in lume.search_calls)

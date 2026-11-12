"""Faza 22 H: fereastra findings-urilor in execution_facts si contextul preadus o singura data.
Fara Elasticsearch: _esql si prefetch_context sunt dubluri."""
from __future__ import annotations

import re

import hunt_path
from schemas import ActionType, EntityType, RarityFinding

ROW = {"@timestamp": "2026-11-05T10:00:00Z", "user.name": "www-data", "process.executable": "/usr/bin/id",
       "process.command_line": "id", "process.parent.name": "dash", "process.working_directory": "/var/www",
       "process.parent.entity_id": "p1", "process.entity_id": "c1"}


def _finding(child="id") -> RarityFinding:
    return RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                         detail={"parent": "dash", "child": child}, rarity_score=1.0)


def _esql_with_event_at(age_min: int):
    """Dublura: intoarce randul doar daca fereastra din interogare acopera varsta evenimentului."""
    seen = []

    def fake(q, params=None):
        seen.append(q)
        m = re.search(r"NOW\(\) - (\d+) minutes", q)
        if m and int(m.group(1)) >= age_min:
            return [ROW]
        return []
    fake.seen = seen
    return fake


def test_finding_de_45_min_se_rezolva(monkeypatch):
    fake = _esql_with_event_at(45)
    monkeypatch.setattr(hunt_path, "_esql", fake)
    facts = hunt_path.execution_facts(_finding())
    assert facts["resolved"] is True and facts["matched_by"] == "exact_pair"
    assert facts["ran_as_user"] == "www-data"
    assert all(f"NOW() - {hunt_path.FINDING_LOOKBACK_MIN} minutes" in q for q in fake.seen if "minutes" in q)


def test_fereastra_implicita_90_si_din_mediu(monkeypatch):
    assert hunt_path.FINDING_LOOKBACK_MIN == 90
    fake = _esql_with_event_at(100)
    monkeypatch.setattr(hunt_path, "_esql", fake)
    assert hunt_path.execution_facts(_finding())["resolved"] is False
    monkeypatch.setattr(hunt_path, "FINDING_LOOKBACK_MIN", 120)
    assert hunt_path.execution_facts(_finding())["resolved"] is True


def test_fallback_doar_copil_foloseste_aceeasi_fereastra(monkeypatch):
    calls = []

    def fake(q, params=None):
        calls.append(q)
        return [ROW] if "STARTS_WITH" in q else []
    monkeypatch.setattr(hunt_path, "_esql", fake)
    facts = hunt_path.execution_facts(_finding())
    assert facts["matched_by"] == "child_only"
    windows = [re.search(r"NOW\(\) - (\d+) minutes", q).group(1) for q in calls if "minutes" in q]
    assert windows == [str(hunt_path.FINDING_LOOKBACK_MIN)] * 2
    assert all("SORT @timestamp DESC" in q and "LIMIT 3" in q for q in calls if "minutes" in q)


# --- contextul din seed ajunge in finalize ----------------------------------------------------

def test_seed_pune_contextul_in_stare(monkeypatch):
    monkeypatch.setattr(hunt_path, "prefetch_context", lambda x: {"ran_by_web_service_account": True, "k": 1})
    out = hunt_path._i_seed({"finding": _finding(), "role_note": ""})
    assert out["prefetch_ctx"] == {"ran_by_web_service_account": True, "k": 1}


def test_primary_propaga_contextul(monkeypatch):
    class _A:
        def invoke(self, inp, config=None):
            return {"draft": {"classification": "benign"}, "prefetch_ctx": {"k": 1}}
    monkeypatch.setattr(hunt_path, "INVESTIGATOR_A", _A())
    out = hunt_path.node_primary({"finding": _finding()})
    assert out["prefetch_ctx"] == {"k": 1}


def test_finalize_nu_reinterogheaza_si_aplica_podeaua_din_contextul_salvat(monkeypatch):
    def boom(x):
        raise AssertionError("finalize a reapelat prefetch_context")
    monkeypatch.setattr(hunt_path, "prefetch_context", boom)
    monkeypatch.setattr(hunt_path, "_esql", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ES apelat")))
    state = {"finding": _finding(), "investigation_id": "i",
             "prefetch_ctx": {"ran_by_web_service_account": True, "via_sudo_by": None,
                              "execution": {"resolved": True, "parent": "dash"}},
             "merged_draft": {"classification": "benign", "confidence": 95, "proposed_action": "none"}}
    v = hunt_path.node_finalize(state)["verdict"]
    assert v.classification.value != "benign" and v.proposed_action is ActionType.ESCALATE_HUMAN


def test_finalize_fara_context_salvat_cade_pe_apelul_actual(monkeypatch):
    calls = []
    monkeypatch.setattr(hunt_path, "prefetch_context", lambda x: (calls.append(1), {})[1])
    state = {"finding": _finding(), "investigation_id": "i",
             "merged_draft": {"classification": "benign", "confidence": 95, "proposed_action": "none"}}
    v = hunt_path.node_finalize(state)["verdict"]
    assert calls == [1] and v.classification.value == "benign"

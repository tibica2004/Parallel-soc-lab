"""
Poarta fazei 1: niciun camp din telemetrie nu ajunge in textul interogarii.
_esql e inlocuit cu o inregistrare a apelurilor; verificam textul si parametrii.
"""
import pytest

import hunt_path
from schemas import EntityType, RarityFinding

EVIL = [
    'x" OR true | LIMIT 10000 //',
    'bash" | EVAL p = "1',
    "sh*",
    'a?b',
    "id\n| DROP user.name",
]


class Recorder:
    def __init__(self, responses):
        self.calls = []
        self._responses = list(responses)

    def __call__(self, query, params=None):
        self.calls.append((query, list(params or [])))
        return self._responses.pop(0) if self._responses else []


def _finding(host="web-prod", parent="dash", child="id"):
    return RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST,
                         entity_id=host, detail={"parent": parent, "child": child},
                         rarity_score=1.0)


@pytest.mark.parametrize("evil", EVIL)
def test_execution_facts_nu_interpoleaza(monkeypatch, evil):
    rec = Recorder([[], []])  # perechea exacta goala -> si fallback-ul ruleaza
    monkeypatch.setattr(hunt_path, "_esql", rec)
    facts = hunt_path.execution_facts(_finding(parent=evil, child=evil))
    assert facts == {"resolved": False}
    assert len(rec.calls) == 2
    for query, params in rec.calls:
        assert evil not in query
        assert evil in params
        assert "LIKE" not in query.upper()
    assert "STARTS_WITH(process.name, ?)" in rec.calls[1][0]


@pytest.mark.parametrize("evil", EVIL)
def test_execution_facts_intoarce_curat(monkeypatch, evil):
    row = {"user.name": "www-data", "process.executable": "/usr/bin/" + evil,
           "process.command_line": evil, "process.parent.name": "sudo",
           "process.working_directory": "/", "process.parent.entity_id": evil,
           "process.entity_id": "E1"}
    rec = Recorder([[row], [{"user.Ext.real.name": "tiberiu"}]])
    monkeypatch.setattr(hunt_path, "_esql", rec)
    facts = hunt_path.execution_facts(_finding(child=evil))
    assert facts["resolved"] is True
    assert facts["matched_by"] == "exact_pair"
    assert facts["ran_as_user"] == "www-data"
    assert facts["sudo_invoked_by"] == "tiberiu"
    assert facts["command_line"] == evil[:200]   # e data, nu interogare
    sudo_query, sudo_params = rec.calls[1]
    assert evil not in sudo_query and sudo_params == [evil]


@pytest.mark.parametrize("evil", EVIL)
def test_recent_host_alerts_nu_interpoleaza(monkeypatch, evil):
    rec = Recorder([[{"n": 3}]])
    monkeypatch.setattr(hunt_path, "_esql", rec)
    assert hunt_path.recent_host_alerts(evil, minutes="45") == 3
    query, params = rec.calls[0]
    assert evil not in query and params == [evil]
    assert "NOW() - 45 minutes" in query


def test_recent_host_alerts_minutes_doar_numar(monkeypatch):
    monkeypatch.setattr(hunt_path, "_esql", Recorder([]))
    with pytest.raises(ValueError):
        hunt_path.recent_host_alerts("web-prod", minutes="60 minutes | LIMIT 1")


def test_esec_esql_nu_rezolva(monkeypatch):
    def boom(query, params=None):
        raise RuntimeError("ES cazut")
    monkeypatch.setattr(hunt_path, "_esql", boom)
    assert hunt_path.execution_facts(_finding()) == {"resolved": False}
    assert hunt_path.recent_host_alerts("web-prod") == 0

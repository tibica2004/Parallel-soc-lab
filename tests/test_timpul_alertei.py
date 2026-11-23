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

"""Case: granita spre Tier 2. Fara verdictul Tier 1, identificatori validati."""
import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from schemas import AuditRecord, Case, EscalationReason as R, EvidenceRef, Verdict

CID = str(uuid.uuid4())


def _case(**kw):
    base = dict(chain_id=CID, origin="tier1_alert", host="web-prod",
                entity_id="KwY4COo3NGNUi/M4W/r5fQ==", parent="dash", child="id",
                rule_name="RCE: Web server spawns shell", escalation_reasons=[R.SUSPICIOUS])
    base.update(kw)
    return Case(**base)


def test_caz_valid():
    c = _case(evidence_refs=[EvidenceRef(index="i", doc_id="d", timestamp=datetime.now(timezone.utc))])
    assert c.origin == "tier1_alert" and c.escalation_reasons == [R.SUSPICIOUS]


@pytest.mark.parametrize("camp", ["classification", "confidence", "narrative", "verdict", "note"])
def test_verdictul_tier1_nu_poate_intra(camp):
    with pytest.raises(ValidationError):
        _case(**{camp: "benign"})


def test_campurile_lipsa_din_model():
    for camp in ("classification", "confidence", "narrative"):
        assert camp not in Case.model_fields


def test_tier1_fara_motive_respins():
    with pytest.raises(ValidationError):
        _case(escalation_reasons=[])


def test_sweep_fara_motive_permis():
    assert _case(origin="rarity_sweep", escalation_reasons=[]).origin == "rarity_sweep"


@pytest.mark.parametrize("kw", [
    {"origin": "tier4"},
    {"chain_id": "nu-e-uuid"},
    {"host": "web-prod; rm -rf /"},
    {"entity_id": 'x" OR true'},
    {"child": "id\n| DROP user.name"},
    {"parent": "a" * 256},
    {"escalation_reasons": ["scos_de_model"]},
])
def test_valori_respinse(kw):
    with pytest.raises(ValidationError):
        _case(**kw)


def test_caz_imuabil():
    c = _case()
    with pytest.raises(ValidationError):
        c.host = "alt-host"


def test_chain_id_in_verdict_si_audit():
    v = Verdict(investigation_id="t", source_path="fast", entity_type="host", entity_id="web-prod",
                classification="benign", confidence=95, rarity_score=0.0, model_id="m", chain_id=CID)
    now = datetime.now(timezone.utc)
    a = AuditRecord(investigation_id="t", chain_id=CID, verdict=v, escalate=False,
                    escalation_reasons=[], narrative="", policy_decision="none",
                    action_executed="none", started_at=now, finished_at=now)
    assert a.chain_id == v.chain_id == CID
    with pytest.raises(ValidationError):
        Verdict(**{**v.model_dump(), "chain_id": "abc"})

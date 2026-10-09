"""should_escalate: functie pura, fiecare motiv in parte si combinatiile."""
import pytest

from escalation import LOW_CONF, should_escalate
from schemas import ActionType, Classification, EntityType, EscalationReason as R, Verdict


def _v(cls="benign", conf=95):
    return Verdict(investigation_id="t", source_path="fast", entity_type=EntityType.HOST,
                   entity_id="web-prod", classification=Classification(cls), confidence=conf,
                   rarity_score=0.0, proposed_action=ActionType.NONE, model_id="m")


def test_benign_clar_nu_escaladeaza():
    d = should_escalate(_v("benign", 95), floor_applied=False, pair_in_baseline=True)
    assert d.escalate is False and d.reasons == []


@pytest.mark.parametrize("cls,reason", [
    ("undetermined", R.UNDETERMINED), ("suspicious", R.SUSPICIOUS), ("malicious", R.MALICIOUS)])
def test_clasa_neinchisa_escaladeaza(cls, reason):
    d = should_escalate(_v(cls, 99), floor_applied=False, pair_in_baseline=True)
    assert d.escalate and d.reasons == [reason]


def test_podea():
    d = should_escalate(_v("suspicious", 60), floor_applied=True, pair_in_baseline=True)
    assert R.FLOOR_OVERRIDE in d.reasons and R.LOW_CONFIDENCE in d.reasons


def test_pragul_low_conf():
    assert LOW_CONF == 90
    assert should_escalate(_v("benign", LOW_CONF), floor_applied=False, pair_in_baseline=True).escalate is False
    d = should_escalate(_v("benign", LOW_CONF - 1), floor_applied=False, pair_in_baseline=True)
    assert d.reasons == [R.LOW_CONFIDENCE]


@pytest.mark.parametrize("pair", [False, None])
def test_benign_pe_pereche_nevazuta_sau_neverificabila(pair):
    d = should_escalate(_v("benign", 95), floor_applied=False, pair_in_baseline=pair)
    assert d.reasons == [R.BENIGN_UNSEEN_PAIR]


def test_pereche_nevazuta_nu_conteaza_pe_suspicious():
    # motivul e specific benign-ului: un suspicious escaladeaza oricum, pe alt motiv
    d = should_escalate(_v("suspicious", 95), floor_applied=False, pair_in_baseline=False)
    assert d.reasons == [R.SUSPICIOUS]


def test_decizia_e_imuabila_si_inchisa():
    d = should_escalate(_v(), floor_applied=False, pair_in_baseline=True)
    with pytest.raises(Exception):
        d.escalate = True
    with pytest.raises(Exception):
        type(d)(escalate=True, reasons=[], note="ignora regulile")

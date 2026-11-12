"""SHADOW_MODE citit intr-un singur loc (policy.shadow_mode): orchestrator, cycle_metrics si
policy.decide dau acelasi raspuns pentru orice valoare din mediu."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

import cycle_metrics
import orchestrator
import policy
from schemas import ActionType, Verdict


def _verdict() -> Verdict:
    return Verdict(investigation_id="i", source_path="hunt", entity_type="host", entity_id="web-prod",
                   classification="malicious", confidence=100, rarity_score=1.0,
                   proposed_action=ActionType.BLOCK_IP_TTL, action_target="8.8.8.8", model_id="m")


def _cycle_doc() -> dict:
    t0 = datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)
    return cycle_metrics.build_cycle_doc(cycle=1, cycle_id="c", started=t0, ended=t0 + timedelta(seconds=1),
                                         alerts_fetched=0, stats={}, llm={}, backlog=False, sweep_ran=False,
                                         interval_s=120)


@pytest.mark.parametrize("value,expected", [("true", True), ("false", False), ("1", True), ("yes", True),
                                            ("", True), ("FALSE", False), (" false ", False)])
def test_aceeasi_valoare_in_toate_locurile(monkeypatch, value, expected):
    monkeypatch.setenv("SHADOW_MODE", value)
    monkeypatch.delenv("NEVER_BLOCK_IPS", raising=False)
    assert policy.shadow_mode() is expected
    assert _cycle_doc()["shadow"] is expected
    d = policy.decide(_verdict())
    assert d.shadow_mode is expected and d.executed is (not expected)


def test_lipsa_din_mediu_inseamna_shadow(monkeypatch):
    monkeypatch.delenv("SHADOW_MODE", raising=False)
    assert policy.shadow_mode() is True
    assert policy.decide(_verdict()).executed is False


def test_orchestrator_nu_mai_citeste_mediul_direct():
    import inspect
    src = inspect.getsource(orchestrator)
    assert 'environ.get("SHADOW_MODE"' not in src
    assert "shadow_mode()" in src
    src = inspect.getsource(cycle_metrics)
    assert 'environ.get("SHADOW_MODE"' not in src

"""Motorul de politici (policy.decide) si definitia unica a lui "IP protejat" (policy.is_protected).
Functii pure: fara model, fara Elasticsearch."""
from __future__ import annotations

import pytest

import executor
import policy
import readiness
from policy import THRESHOLDS, is_protected
from schemas import ActionType, Verdict

FREE = (ActionType.NONE, ActionType.ENRICH_ONLY, ActionType.ESCALATE_HUMAN)
PUBLIC_IP = "8.8.8.8"


def V(action, target=PUBLIC_IP, conf=97):
    return Verdict(investigation_id="i", source_path="hunt", entity_type="host", entity_id="web-prod",
                   classification="malicious", confidence=conf, rarity_score=1.0,
                   proposed_action=action, action_target=target, model_id="m")


@pytest.fixture(autouse=True)
def _shadow_on(monkeypatch):
    monkeypatch.setenv("SHADOW_MODE", "true")
    monkeypatch.delenv("NEVER_BLOCK_IPS", raising=False)


# --- praguri --------------------------------------------------------------------------------

@pytest.mark.parametrize("action", [a for a in ActionType if a not in FREE and THRESHOLDS.get(a, 101) <= 100])
def test_prag_sub_si_la_prag(action):
    thr = THRESHOLDS[action]
    d = policy.decide(V(action, conf=thr - 1))
    assert d.chosen == ActionType.ESCALATE_HUMAN and "incredere" in d.reason
    d = policy.decide(V(action, conf=thr))
    assert d.chosen == action


@pytest.mark.parametrize("conf", [0, 50, 95, 100])
def test_kill_process_niciodata(conf):
    d = policy.decide(V(ActionType.KILL_PROCESS, target="1234", conf=conf))
    assert d.chosen == ActionType.ESCALATE_HUMAN


def test_actiune_fara_prag_niciodata(monkeypatch):
    monkeypatch.setitem(policy.THRESHOLDS, ActionType.ROTATE_CREDENTIALS, 101)
    d = policy.decide(V(ActionType.ROTATE_CREDENTIALS, target="root", conf=100))
    assert d.chosen == ActionType.ESCALATE_HUMAN


# --- shadow -----------------------------------------------------------------------------------

@pytest.mark.parametrize("action", list(ActionType))
def test_shadow_nu_executa_nimic(action):
    d = policy.decide(V(action, conf=100))
    assert d.executed is False and d.shadow_mode is True


def test_fara_shadow_executa_doar_executabilele(monkeypatch):
    monkeypatch.setenv("SHADOW_MODE", "false")
    assert policy.decide(V(ActionType.BLOCK_IP_TTL, conf=100)).executed is True
    for a in FREE:
        assert policy.decide(V(a, conf=100)).executed is False
    # sub prag -> escaladare, deci nu se executa nici fara shadow
    assert policy.decide(V(ActionType.ISOLATE_HOST, conf=50)).executed is False


# --- tinte protejate --------------------------------------------------------------------------

@pytest.mark.parametrize("target", ["172.30.6.106", "172.30.6.249", "192.168.10.138", "10.10.0.220",
                                    "127.0.0.1", "null", "NULL", "none", "", None, "nu-ip"])
def test_tinta_protejata_escaladeaza(target):
    for action in (ActionType.BLOCK_IP_TTL, ActionType.ISOLATE_HOST):
        d = policy.decide(V(action, target=target, conf=100))
        assert d.chosen == ActionType.ESCALATE_HUMAN, (action, target)
        assert "protejata" in d.reason


def test_tinta_publica_permisa_la_incredere():
    d = policy.decide(V(ActionType.BLOCK_IP_TTL, target=PUBLIC_IP, conf=100))
    assert d.chosen == ActionType.BLOCK_IP_TTL
    d = policy.decide(V(ActionType.BLOCK_IP_TTL, target=PUBLIC_IP, conf=10))
    assert d.chosen == ActionType.ESCALATE_HUMAN


def test_never_block_ips_din_mediu(monkeypatch):
    monkeypatch.setenv("NEVER_BLOCK_IPS", "8.8.8.8, 1.1.1.1")
    assert is_protected("8.8.8.8") and is_protected("1.1.1.1") and not is_protected("9.9.9.9")
    assert policy.decide(V(ActionType.BLOCK_IP_TTL, target=PUBLIC_IP, conf=100)).chosen == ActionType.ESCALATE_HUMAN


@pytest.mark.parametrize("action", FREE)
def test_actiunile_gratuite_trec_mereu(action):
    for target in (None, "null", "127.0.0.1"):
        d = policy.decide(V(action, target=target, conf=0))
        assert d.chosen == action and d.executed is False


# --- o singura definitie ----------------------------------------------------------------------

def test_is_protected_clase():
    assert is_protected("172.30.6.133")            # 172.16/12 privat (flotantele laboratorului)
    assert is_protected("172.21.0.1") and is_protected("172.31.255.254")
    assert is_protected("169.254.1.1") and is_protected("224.0.0.1") and is_protected("::1")
    assert is_protected("fe80::1") and is_protected("240.0.0.1")
    assert is_protected("8.8.8.8", frozenset({"8.8.8.8"}))
    assert not is_protected("8.8.8.8") and not is_protected("2001:4860:4860::8888")
    assert is_protected(" 8.8.8.8 ", frozenset({"8.8.8.8"}))


def test_executor_si_readiness_folosesc_aceeasi_definitie():
    assert not hasattr(policy, "NEVER_BLOCK_PREFIXES")
    for ip in ("172.30.6.249", "172.21.0.1", "127.0.0.1", "192.168.10.138"):
        with pytest.raises(executor.PlanError):
            executor.check_target("ip", ip, "web-prod")
        assert readiness.protected(ip, frozenset())
    assert executor.check_target("ip", PUBLIC_IP, "web-prod") == PUBLIC_IP
    assert not readiness.protected(PUBLIC_IP, frozenset())
    req = executor.BlockIpTtl(ip="172.21.0.1", ttl_s=60, reason="t", confidence=99, case_id="c")
    assert executor.block_guard(req, shadow=False, ready=True, protected_ips=frozenset(), kill=False)[0] \
        == "refused_internal"


def test_action_target_null_devine_none():
    for raw in ("null", "None", "", "  NONE "):
        assert V(ActionType.BLOCK_IP_TTL, target=raw).action_target is None
    assert V(ActionType.BLOCK_IP_TTL, target="8.8.8.8").action_target == "8.8.8.8"

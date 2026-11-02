"""Pasul 9: criteriile de readiness si garzile block_ip_ttl (doar dry-run; nimic nu se executa)."""
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

import executor as X
import readiness as R

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


def test_ip_protejat():
    assert R.protected("192.168.10.138", frozenset()) and R.protected("127.0.0.1", frozenset())
    assert R.protected("172.30.6.133", frozenset())          # 172.16/12 privat
    assert R.protected("203.0.113.5", frozenset())            # documentatie = rezervat
    assert R.protected("8.8.8.8", frozenset({"8.8.8.8"}))     # lista explicita
    assert not R.protected("8.8.8.8", frozenset()) and R.protected("nu-ip", frozenset())


def test_criterii_si_ready_doar_cu_toate():
    good = [R.c1(96, 4, 168, 168), R.count_criterion("c2", 0, "x"), R.count_criterion("c3", 0, "x"),
            R.c4({"@timestamp": "2026-11-02T12:00:00Z", "passed": True, "identical_pct": 100.0},
                 datetime(2026, 11, 2, tzinfo=timezone.utc)),
            R.count_criterion("c5", 0, "x"), R.c6({"a": 0.01}), R.c7(0.93), R.c8(3.0), R.c9(7)]
    assert R.result(good, NOW).ready
    bad = good[:-1] + [R.c9(1)]
    r = R.result(bad, NOW)
    assert not r.ready and "SNAT" in r.criteria[-1].reason


def test_benign_gen_trebuie_activ_in_fiecare_ora():
    assert not R.c1(99, 0, 167, 168).passed and R.c1(99, 0, 168, 168).passed


def test_necalculabil_e_picat_nu_sarit():
    for c in (R.count_criterion("c2", None, "403"), R.c8(None, "necalculabil: 403"), R.c9(None),
              R.c6({}), R.c7(None), R.c4(None, None)):
        assert c.passed is False


def test_injectie_mai_veche_decat_bump_nu_trece():
    c = R.c4({"@timestamp": "2026-11-01T12:00:00Z", "passed": True},
             datetime(2026, 11, 2, tzinfo=timezone.utc))
    assert not c.passed and "prompturi schimbate" in c.reason


def _req(ip="198.51.99.7", conf=95):
    return X.BlockIpTtl(ip=ip, ttl_s=600, reason="r", confidence=conf, case_id="c")


def test_garzile_in_ordinea_contractului():
    g = X.block_guard
    assert g(_req(), shadow=True, ready=True, protected_ips=frozenset(), kill=True)[0] == "refused_kill"
    assert g(_req(), shadow=True, ready=True, protected_ips=frozenset(), kill=False)[0] == "would_block"
    assert g(_req(), shadow=False, ready=False, protected_ips=frozenset(), kill=False)[0] == "refused_not_ready"
    assert g(_req("192.168.10.5"), shadow=False, ready=True, protected_ips=frozenset(), kill=False)[0] == "refused_internal"
    assert g(_req("198.51.99.7"), shadow=False, ready=True, protected_ips=frozenset({"198.51.99.7"}),
             kill=False)[0] == "refused_internal"
    assert g(_req(conf=89), shadow=False, ready=True, protected_ips=frozenset(), kill=False)[0] == "refused_confidence"
    assert g(_req(), shadow=False, ready=True, protected_ips=frozenset(), blocks_last_hour=10,
             kill=False)[0] == "refused_rate"
    assert g(_req(), shadow=False, ready=True, protected_ips=frozenset(), kill=False)[0] == "not_implemented"


def test_cererea_de_block_e_stricta():
    with pytest.raises(ValidationError):
        X.BlockIpTtl(ip="198.51.99.7", ttl_s=7200, reason="r", confidence=95, case_id="c")
    with pytest.raises(ValidationError):
        X.BlockIpTtl(ip="not-an-ip", ttl_s=60, reason="r", confidence=95, case_id="c")
    with pytest.raises(ValidationError):
        X.BlockIpTtl(ip="198.51.99.7", ttl_s=60, reason="r", confidence=95, case_id="c", payload="x")

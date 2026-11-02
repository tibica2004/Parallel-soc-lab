"""Pasul 7: documentul type=cycle, totalurile LLM per ciclu si watchdog-ul systemd."""
from __future__ import annotations

import os
import socket
from datetime import datetime, timedelta, timezone

import cycle_metrics as cm
import sdnotify
import tracing

T0 = datetime(2026, 11, 2, 10, 0, tzinfo=timezone.utc)


def _doc(stats, llm=None, **kw):
    return cm.build_cycle_doc(cycle=3, cycle_id="c", started=T0, ended=T0 + timedelta(seconds=42.5),
                              alerts_fetched=kw.get("fetched", 7), stats=stats, llm=llm or {},
                              backlog=False, sweep_ran=False, interval_s=120)


def test_document_ciclu_numara_corect():
    d = _doc({"total": 5, "escalated": 2, "tier2": 1, "tier2_skipped": 1, "no_model": 1,
              "fail_case_timeout": 1, "fail_processing_error": 2, "honeytoken_hits": 1},
             {"llm_calls": 4, "tokens": 900, "llm_ms": 3000})
    assert d["type"] == "cycle" and d["duration_s"] == 42.5 and d["queue_depth"] == 7
    assert d["closed_t1"] == 3 and d["escalated"] == 2 and d["escalated_t2"] == 1
    assert d["model_timeouts"] == 1 and d["model_errors"] == 2 and d["honeytoken_hits"] == 1
    assert d["escalation_rate"] == 0.4 and d["tokens"] == 900 and d["llm_calls"] == 4


def test_ciclu_gol_fara_impartire_la_zero():
    d = _doc({}, fetched=0)
    assert d["escalation_rate"] is None and d["alerts_processed"] == 0 and d["failures"] == {}


def test_shadow_din_mediu(monkeypatch):
    monkeypatch.setenv("SHADOW_MODE", "true")
    assert _doc({})["shadow"] is True
    monkeypatch.setenv("SHADOW_MODE", "false")
    assert _doc({})["shadow"] is False


def test_scrierea_nu_arunca():
    class Rupt:
        def index(self, **kw):
            raise ConnectionError("es cazut")
    assert "ConnectionError" in cm.write(Rupt(), {"x": 1})
    assert cm.write(None, {}) is not None


def test_totaluri_llm_per_ciclu_se_reseteaza():
    tracing.take_llm_totals()
    tracing.record_llm("fast", 100, 50)
    tracing.record_llm("fast", None, 10)
    assert tracing.take_llm_totals() == {"llm_calls": 2, "tokens": 100, "llm_ms": 60}
    assert tracing.take_llm_totals() == {"llm_calls": 0, "tokens": 0, "llm_ms": 0}


def test_watchdog_fara_socket_e_noop(monkeypatch):
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    assert sdnotify.watchdog() is False


def test_watchdog_trimite_pe_socket(monkeypatch, tmp_path):
    path = str(tmp_path / "notify.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(path)
    try:
        monkeypatch.setenv("NOTIFY_SOCKET", path)
        assert sdnotify.watchdog() is True
        assert srv.recv(64) == b"WATCHDOG=1"
        assert sdnotify.ready() is True and srv.recv(64) == b"READY=1"
    finally:
        srv.close()


def test_watchdog_socket_mort_nu_arunca(monkeypatch, tmp_path):
    monkeypatch.setenv("NOTIFY_SOCKET", str(tmp_path / "nu-exista.sock"))
    assert sdnotify.watchdog() is False


# --- sonda LLM (pasul 7.4) ---------------------------------------------------------
import llm_probe as lp


def test_baza_nativa_ollama():
    assert lp.native_base("http://localhost:11434/v1") == "http://localhost:11434"
    assert lp.native_base("http://localhost:11434/v1/") == "http://localhost:11434"
    assert lp.native_base("http://gpu:11434") == "http://gpu:11434"


def test_sonda_cere_modelul_configurat():
    assert lp.evaluate(None, "qwen3:14b") == (False, [], "fara raspuns")
    ok, names, why = lp.evaluate({"models": [{"name": "alt:7b"}]}, "qwen3:14b")
    assert not ok and "lipseste" in why
    assert lp.evaluate({"models": [{"name": "qwen3:14b"}]}, "qwen3:14b")[0] is True


def test_esecuri_consecutive():
    n = 0
    for ok in (False, False, True, False):
        n = lp.next_failures(n, ok)
    assert n == 1
    assert lp.next_failures(2, False) == lp.FAIL_LIMIT

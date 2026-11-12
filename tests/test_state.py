"""state.load_cursor: "lipsa" nu e "eroare". Client ES fals, fara retea."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from elasticsearch import ApiError, NotFoundError

import state


class _Meta:
    status = 404
    headers: dict = {}


class _Fake:
    def __init__(self, behaviour):
        self.behaviour = behaviour

    def get(self, index, id):
        b = self.behaviour
        if isinstance(b, Exception):
            raise b
        return {"_source": b}


def _not_found() -> NotFoundError:
    return NotFoundError("not found", _Meta(), {"found": False})


def test_lipsa_cursorului_porneste_de_la_lookback(monkeypatch):
    monkeypatch.setattr(state, "_writer", lambda: _Fake(_not_found()))
    before = datetime.now(timezone.utc)
    got = state.load_cursor()
    expected = before - timedelta(minutes=state.DEFAULT_LOOKBACK_MIN)
    assert abs((got - expected).total_seconds()) < 5


def test_cursor_existent_se_intoarce_exact(monkeypatch):
    monkeypatch.setattr(state, "_writer", lambda: _Fake({"last_ts": "2026-11-05T10:00:00Z"}))
    assert state.load_cursor() == datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("err", [TimeoutError("timeout"), ConnectionError("refuzat"),
                                 RuntimeError("ES_WRITER_API_KEY lipseste")])
def test_alta_eroare_se_propaga_nu_se_inlocuieste_cu_lookback(monkeypatch, err):
    monkeypatch.setattr(state, "_writer", lambda: _Fake(err))
    with pytest.raises(type(err)):
        state.load_cursor()


def test_403_se_propaga(monkeypatch):
    class _M:
        status = 403
        headers: dict = {}
    monkeypatch.setattr(state, "_writer", lambda: _Fake(ApiError("forbidden", _M(), {})))
    with pytest.raises(ApiError):
        state.load_cursor()

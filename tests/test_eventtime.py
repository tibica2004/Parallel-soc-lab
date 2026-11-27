"""Faza 25: functiile pure din elasticlab/core/eventtime.py."""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from elasticlab.core import eventtime as E

T = datetime(2026, 11, 23, 10, 0, 0, 123456, tzinfo=timezone.utc)


def test_parse_forme():
    assert E.parse("2026-11-23T10:00:00.123456Z") == T
    assert E.parse("2026-11-23T12:00:00.123456+02:00") == T
    assert E.parse(T) == T
    naiv = E.parse("2026-11-23T10:00:00")
    assert naiv.tzinfo is not None and naiv.utcoffset() == timedelta(0)


@pytest.mark.parametrize("v", [None, "", "ieri", 1700000000, [], "2026-13-40T00:00:00Z"])
def test_parse_invalid_e_none(v):
    assert E.parse(v) is None


def test_alert_time_original_time_inaintea_timestamp():
    a = {"@timestamp": "2026-11-23T10:05:00Z", "kibana.alert.original_time": "2026-11-23T10:00:00Z"}
    assert E.alert_time(a) == datetime(2026, 11, 23, 10, 0, tzinfo=timezone.utc)
    imbricat = {"@timestamp": "2026-11-23T10:05:00Z", "kibana": {"alert": {"original_time": "2026-11-23T10:01:00Z"}}}
    assert E.alert_time(imbricat).minute == 1
    assert E.alert_time({"@timestamp": "2026-11-23T10:05:00Z"}).minute == 5
    assert E.alert_time({}) is None and E.alert_time({"@timestamp": "nu"}) is None


def test_iso_forma_to_datetime():
    assert E.iso(T) == "2026-11-23T10:00:00.123Z"
    assert E.iso(T.astimezone(timezone(timedelta(hours=2)))) == "2026-11-23T10:00:00.123Z"


def test_esql_window_fara_ancora_e_forma_veche():
    assert E.esql_window(None, 15, "minutes") == ("@timestamp >= NOW() - 15 minutes", [])
    assert E.esql_window(None, "168", "hours") == ("@timestamp >= NOW() - 168 hours", [])


def test_esql_window_cu_ancora():
    clause, params = E.esql_window(T, 15, "minutes")
    assert clause == "@timestamp >= TO_DATETIME(?) AND @timestamp <= TO_DATETIME(?)"
    assert "NOW()" not in clause and clause.count("?") == len(params) == 2
    assert params == ["2026-11-23T09:45:00.123Z", "2026-11-23T10:10:00.123Z"]


def test_esql_window_nu_accepta_text():
    with pytest.raises(ValueError):
        E.esql_window(T, "15 minutes | LIMIT 1", "minutes")
    with pytest.raises(ValueError):
        E.esql_window(None, 15, "minutes | DROP x")


def test_dsl_range():
    assert E.dsl_range(None, 30, "minutes") == {"gte": "now-30m"}
    assert E.dsl_range(None, 2, "hours") == {"gte": "now-2h"}
    assert E.dsl_range(T, 30, "minutes") == {"gte": "2026-11-23T09:30:00.123Z", "lte": "2026-11-23T10:10:00.123Z"}


def test_until():
    assert E.until(None) is None
    assert E.until(T) == {"range": {"@timestamp": {"lte": "2026-11-23T10:00:00.123Z"}}}


def test_fereastra_nu_depinde_de_ceas():
    """Aceeasi ancora -> aceeasi fereastra, oricand ar fi calculata."""
    assert E.esql_window(T, 60, "minutes") == E.esql_window(T, 60, "minutes")
    assert E.bounds(T, timedelta(minutes=60)) == (T - timedelta(minutes=60), T + E.DUPA_EVENIMENT)


def test_anchored_se_reface_si_la_exceptie():
    assert E.current() is None
    with E.anchored(T):
        assert E.current() == T
        with E.anchored(None):
            assert E.current() is None
        assert E.current() == T
    with pytest.raises(RuntimeError):
        with E.anchored(T):
            raise RuntimeError("x")
    assert E.current() is None


def test_ancora_nu_trece_in_alt_fir_neinrudit():
    """Un fir pornit fara copierea contextului nu vede ancora altui caz."""
    seen = []
    with E.anchored(T):
        th = threading.Thread(target=lambda: seen.append(E.current()))
        th.start()
        th.join()
    assert seen == [None]

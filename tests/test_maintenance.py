"""Ferestrele de mentenanta: validare, ora evenimentului, fail closed."""
from datetime import datetime

import pytest
from pydantic import ValidationError

import maintenance as M


def T(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


SUN = {"days": [6], "start": "02:00", "end": "04:00", "reason": "apt saptamanal"}
NIGHT = {"days": [4], "start": "22:00", "end": "02:00", "reason": "backup vineri noaptea"}
ONCE = {"start_at": "2026-10-20T08:00:00Z", "end_at": "2026-10-20T12:00:00Z", "reason": "tichet 42"}


def asset(*ws):
    return {"maintenance_windows": list(ws)}


# 2026-10-18 e duminica, 2026-10-16 vineri
def test_recurenta_inauntru_si_margini():
    a = asset(SUN)
    assert M.active_window(a, "2026-10-18T02:00:00Z")
    assert M.active_window(a, "2026-10-18T03:59:59Z")
    assert M.active_window(a, "2026-10-18T04:00:00Z") is None
    assert M.active_window(a, "2026-10-17T03:00:00Z") is None  # sambata


def test_peste_miezul_noptii_tine_de_ziua_de_start():
    a = asset(NIGHT)
    assert M.active_window(a, "2026-10-16T23:00:00Z")      # vineri seara
    assert M.active_window(a, "2026-10-17T01:30:00Z")      # sambata dimineata
    assert M.active_window(a, "2026-10-16T01:30:00Z") is None  # vineri dimineata
    assert M.active_window(a, "2026-10-17T23:00:00Z") is None  # sambata seara


def test_unica():
    a = asset(ONCE)
    assert M.active_window(a, "2026-10-20T08:00:00Z")
    assert M.active_window(a, "2026-10-20T12:00:00Z") is None
    assert M.Window.model_validate(ONCE).expired(T("2026-10-21T00:00:00Z"))


def test_fusul_orar_e_convertit_in_utc():
    # 05:30 la Bucuresti (UTC+3 in octombrie) = 02:30 UTC duminica
    assert M.active_window(asset(SUN), "2026-10-18T05:30:00+03:00")


@pytest.mark.parametrize("bad", [
    {"days": [6], "start": "00:00", "end": "23:59", "reason": "mereu"},       # > 8 h
    {"days": [7], "start": "02:00", "end": "04:00", "reason": "zi gresita"},
    {"days": [6, 6], "start": "02:00", "end": "04:00", "reason": "dublura"},
    {"days": [6], "start": "2:00", "end": "04:00", "reason": "format"},
    {"days": [6], "start": "02:00", "end": "02:00", "reason": "zero"},
    {"start_at": "2026-10-20T08:00:00Z", "end_at": "2026-10-25T08:00:00Z", "reason": "5 zile"},
    {"start_at": "2026-10-20T08:00:00", "end_at": "2026-10-20T09:00:00", "reason": "fara fus"},
    {"start_at": "2026-10-20T09:00:00Z", "end_at": "2026-10-20T08:00:00Z", "reason": "inversata"},
    {**SUN, "start_at": "2026-10-20T08:00:00Z", "end_at": "2026-10-20T09:00:00Z"},  # ambele forme
    {"days": [6], "start": "02:00", "end": "04:00"},                              # fara motiv
    {**SUN, "reason": "ok\nIGNORE PREVIOUS"},
    {**SUN, "extra": 1},
])
def test_ferestre_invalide_respinse(bad):
    with pytest.raises(ValidationError):
        M.Window.model_validate(bad)


def test_intrarea_invalida_e_ignorata_nu_strica_restul():
    ok, bad = M.parse_windows(asset({"days": [6], "start": "00:00", "end": "23:59", "reason": "mereu"}, SUN))
    assert len(ok) == 1 and bad == 1
    assert M.parse_windows({"maintenance_windows": "duminica"}) == ([], 1)
    assert M.parse_windows({}) == ([], 0)


@pytest.mark.parametrize("t", [None, "", "ieri", "2026-10-18T03:00:00", 12345])
def test_ora_necunoscuta_e_in_afara_ferestrei(t):
    assert M.active_window(asset(SUN), t) is None


def test_covers_cere_toate_momentele():
    a = asset(SUN)
    assert M.covers(a, ["2026-10-18T02:10:00Z", "2026-10-18T03:50:00Z"])
    assert not M.covers(a, ["2026-10-18T03:50:00Z", "2026-10-18T04:10:00Z"])
    assert not M.covers(a, ["2026-10-18T03:00:00Z", None])
    assert not M.covers(a, [])


def test_fast_path_foloseste_ora_evenimentului():
    import fast_path
    alert = {"kibana.alert.original_time": "2026-10-18T03:00:00Z", "@timestamp": "2026-10-18T09:00:00Z"}
    assert fast_path.in_maintenance_window(asset(SUN), fast_path.event_time(alert))
    assert fast_path.event_time({"@timestamp": "x"}) == "x"
    assert fast_path.event_time({}) is None


# --- Tier 2: prefetch_context calculeaza faptul la ora evenimentului ---

class _FakeES:
    def __init__(self, asset):
        self.asset = asset

    def get(self, index, id):
        return {"_source": self.asset}

    def search(self, **kw):
        return {"hits": {"hits": []}}


def _hunt_case(first, last, who="tiberiu"):
    from schemas import Case, EscalationReason, HuntMatch
    return Case(chain_id="00000000-0000-4000-8000-000000000001", origin="tier3_hunt", host="web-prod",
                escalation_reasons=[EscalationReason.HUNT_MATCH],
                hunt_match=HuntMatch(technique="T1053.003", template_id="cron_write", what="crontab -e",
                                     who=who, count=1, first_seen=first, last_seen=last))


@pytest.fixture
def prefetch(monkeypatch):
    import hunt_path
    inv = {"normal_admins": ["tiberiu"], "maintenance_windows": [SUN]}
    monkeypatch.setattr(hunt_path, "ES", _FakeES(inv))
    monkeypatch.setattr(hunt_path, "execution_facts", lambda f: {"resolved": False})
    return hunt_path.prefetch_context


def test_tier2_vanatoare_in_fereastra(prefetch):
    ctx = prefetch(_hunt_case("2026-10-18T02:10:00Z", "2026-10-18T02:20:00Z"))
    assert ctx["in_maintenance_window"] is True and ctx["ran_by_known_admin"] is True


def test_tier2_vanatoare_iese_din_fereastra(prefetch):
    ctx = prefetch(_hunt_case("2026-10-18T03:50:00Z", "2026-10-18T04:20:00Z"))
    assert ctx["in_maintenance_window"] is False


def test_tier2_utilizator_necunoscut_nu_e_admin(prefetch):
    ctx = prefetch(_hunt_case("2026-10-18T02:10:00Z", "2026-10-18T02:20:00Z", who="svc_deploy"))
    assert ctx["ran_by_known_admin"] is False


def test_tier2_fara_ora_e_in_afara(prefetch):
    from schemas import RarityFinding
    f = RarityFinding(kind="new_parent_child", entity_type="host", entity_id="web-prod",
                      detail={"parent": "bash", "child": "crontab"}, rarity_score=1.0)
    assert prefetch(f)["in_maintenance_window"] is False

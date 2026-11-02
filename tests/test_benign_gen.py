"""Pasul 4: functiile pure din benign_gen.py si fp_rate.py (fara retea, fara browser, fara ES)."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

import benign_gen as bg
import fp_rate as fr

T0 = datetime(2026, 11, 2, 10, 0, 0, tzinfo=timezone.utc)


def iso(t: datetime) -> str:
    return t.isoformat()


# --- benign_gen ------------------------------------------------------------------

@pytest.mark.parametrize("p", ["/", "/?s=test", "/wp-json/wp/v2/posts?per_page=10", "/?p=12",
                               "/feed/", "/wp-login.php", "/wp-cron.php?doing_wp_cron=",
                               "/wp-json/wp/v2/posts?author=3&per_page=5&context=edit",
                               "/wp-json/wp/v2/media", "/wp-login.php?action=logout"])
def test_cai_normale_permise(p):
    assert bg.safe_path(p)


@pytest.mark.parametrize("p", ["/../etc/passwd", "/?s=<script>", "/?s=a'b", "/a%20b", "//x",
                               "/?id=1 OR 1=1", "/?p=1;id", "relative", "/?s=a|b", "/X.php"])
def test_cai_suspecte_refuzate(p):
    assert not bg.safe_path(p)


def test_toate_tintele_fixe_din_cod_sunt_sigure():
    import inspect
    import re
    src = inspect.getsource(bg.Session)
    for lit in re.findall(r'"(/[^"{]*)"', src):
        if lit.startswith("/wp-") or lit in ("/", "/feed/"):
            assert bg.safe_path(lit), lit


def test_profil_zi_noapte():
    rnd = random.Random(1)
    for _ in range(50):
        assert 120 <= bg.next_delay_s(12, rnd) <= 360
        assert 900 <= bg.next_delay_s(3, rnd) <= 2400
    assert bg.is_day(8) and not bg.is_day(20) and not bg.is_day(7)


def test_plan_sesiune_coerent():
    rnd = random.Random(7)
    for _ in range(200):
        p = bg.plan_session(rnd)
        assert p[0] == bg.Action.BROWSE
        if bg.Action.LOGIN in p:
            assert p.index(bg.Action.LOGIN) < p.index(bg.Action.LOGOUT)
            assert len([a for a in p if a in (bg.Action.CREATE_POST, bg.Action.EDIT_POST,
                                              bg.Action.UPLOAD_MEDIA)]) == 1


def test_document_adevar():
    d = bg.gt_doc(run_id="r", action_id="a", action="browse_public", target="/", src_ip="1.2.3.4",
                  phase="start")
    assert d["expected_alert"] is False and d["phase"] == "start" and d["source"] == "benign_gen"
    with pytest.raises(ValueError):
        bg.gt_doc(run_id="r", action_id="a", action="x", target="/", src_ip="1", phase="mijloc")


def test_marcaj_user_agent():
    assert "soc-benign/1.0" in bg.UA and "sqlmap" not in bg.UA.lower()


def test_configuratie_lipsa_refuzata(monkeypatch):
    for k in ("BENIGN_BASE_URL", "BENIGN_WP_PASSWORD"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(RuntimeError):
        bg.Cfg.from_env()


# --- fp_rate ---------------------------------------------------------------------

BIPS = frozenset({"192.168.10.150"})


def _alert(rule, t, ip=None, ua=None):
    a = {"@timestamp": iso(t), "kibana.alert.rule.name": rule}
    if ip:
        a["source"] = {"ip": ip}
    if ua:
        a["user_agent"] = {"original": ua}
    return a


def test_atribuire_ip_si_ua():
    assert fr.attribute(_alert("r", T0, ip="192.168.10.150"), BIPS, [], []) == "benign_ip"
    assert fr.attribute(_alert("r", T0, ip="172.30.6.133", ua="x soc-benign/1.0"), BIPS, [], []) \
        == "benign_ua"
    assert fr.attribute(_alert("r", T0, ip="172.30.6.133"), BIPS, [], []) is None


def test_atribuire_pe_timp_doar_pentru_alerte_de_host():
    gt = [{"@timestamp": iso(T0), "action_id": "a", "phase": "start"},
          {"@timestamp": iso(T0 + timedelta(seconds=3)), "action_id": "a", "phase": "end"}]
    w = fr.gen_windows(gt)
    assert fr.attribute(_alert("r", T0 + timedelta(seconds=7)), BIPS, w, []) == "benign_time"
    assert fr.attribute(_alert("r", T0 + timedelta(seconds=9)), BIPS, w, []) is None
    # o cerere de retea de la alt client in aceeasi secunda NU devine benign
    assert fr.attribute(_alert("r", T0 + timedelta(seconds=1), ip="172.30.6.133"), BIPS, w, []) is None


def test_actiune_fara_end_are_fereastra_limitata():
    w = fr.gen_windows([{"@timestamp": iso(T0), "action_id": "a", "phase": "start"}])
    assert w[0][1] == T0 + timedelta(seconds=65)


def test_fereastra_update():
    w = fr.update_windows([{"@timestamp": iso(T0), "action": "wp_update"}])
    assert fr.attribute(_alert("r", T0 + timedelta(minutes=9)), BIPS, [], w) == "benign_update"
    assert fr.attribute(_alert("r", T0 + timedelta(minutes=11)), BIPS, [], w) is None


def test_rata_per_regula_si_recalibrare():
    alerts = [_alert("A", T0, ip="192.168.10.150")] + [_alert("A", T0, ip="9.9.9.9")] * 9 \
        + [_alert("B", T0, ip="9.9.9.9")] * 50 + [_alert("B", T0, ip="192.168.10.150")]
    r = fr.per_rule(alerts, BIPS, [], [])
    assert r["A"]["fp_rate"] == 0.1 and r["A"]["recalibrate"] is True
    assert r["B"]["fp_count"] == 1 and r["B"]["recalibrate"] is False
    txt = fr.report_text(r, T0, T0, 3)
    assert txt.index(" A ") < txt.index(" B ") and "NU dezactivat" in txt


def test_ip_set_ignora_gunoiul():
    assert fr.ip_set("192.168.10.150, x 10.0.0.1") == frozenset({"192.168.10.150", "10.0.0.1"})

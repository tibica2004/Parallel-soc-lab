"""Executorul (doar dry-run): functii pure, fara ES, fara retea, fara subprocess."""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

import executor as X
from policy import Decision
from schemas import ActionPlan, ActionType, AuditRecord, PlanStep, Verdict

NOW = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)
GOOD = X.LabelStats(labeled=60, tp=59, fp=1, fn_recent=0)


def V(action, target, conf=97, entity="web-prod"):
    return Verdict(investigation_id="i", source_path="hunt", entity_type="host", entity_id=entity,
                   classification="malicious", confidence=conf, rarity_score=1.0,
                   proposed_action=action, action_target=target, model_id="m")


def D(action):
    return Decision(proposed=action, chosen=action, executed=False, shadow_mode=True, reason="r")


AGENT = "bb87e0aa-55b3-41f7-a6a1-4e73d653d6dd"


def P(action, target, **kw):
    if action is ActionType.ISOLATE_HOST:
        kw.setdefault("agent_id", AGENT)
    return X.plan(V(action, target), D(action), NOW, **kw)


# ---------------- nimic nu se executa ----------------

def test_modulul_nu_poate_executa():
    src = open(X.__file__).read()
    for bad in ("subprocess", "os.system", "paramiko", "requests", "urllib", "Popen"):
        assert bad not in src.split('"""', 2)[2], bad


def test_planul_e_mereu_dry_run():
    assert P(ActionType.BLOCK_IP_TTL, "8.8.8.8").mode == "dry-run"
    with pytest.raises(ValidationError):
        ActionPlan.model_validate({**P(ActionType.BLOCK_IP_TTL, "8.8.8.8").model_dump(), "mode": "live"})


def test_actiunile_gratuite_nu_au_plan():
    for a in (ActionType.NONE, ActionType.ENRICH_ONLY, ActionType.ESCALATE_HUMAN):
        assert P(a, None) is None


@pytest.mark.parametrize("a", [ActionType.KILL_PROCESS, ActionType.ROTATE_CREDENTIALS])
def test_ireversibilele_nu_au_executor(a):
    with pytest.raises(X.PlanError):
        P(a, "1234")


# ---------------- tinte validate dupa tip ----------------

@pytest.mark.parametrize("t", ["10.0.0.5", "172.20.99.240", "127.0.0.1", "192.168.1.1", "::1", "8.8.8.8; rm",
                               "not-an-ip", None])
def test_block_ip_respinge_intern_sau_invalid(t):
    with pytest.raises((X.PlanError, ValidationError)):
        P(ActionType.BLOCK_IP_TTL, t)


@pytest.mark.parametrize("t", ["0", "-1", "12a", "99999999"])
def test_pid_invalid(t):
    with pytest.raises(X.PlanError):
        P(ActionType.FREEZE_PROCESS, t)


@pytest.mark.parametrize("t", ["drop.php", "/etc/passwd", "/var/www/../etc/shadow", "/var/www/a b.php",
                               "/usr/bin/bash"])
def test_carantina_doar_in_zonele_permise(t):
    with pytest.raises((X.PlanError, ValidationError)):
        P(ActionType.QUARANTINE_FILE, t)


def test_izolare_fara_agent_id_valid_fara_plan():
    for a in (None, "<agent>", "abc"):
        with pytest.raises(X.PlanError):
            X.plan(V(ActionType.ISOLATE_HOST, "web-prod"), D(ActionType.ISOLATE_HOST), NOW, agent_id=a)


def test_izolare_doar_pe_hostul_verdictului():
    with pytest.raises(X.PlanError):
        P(ActionType.ISOLATE_HOST, "alt-host")


# ---------------- pasi si rollback ----------------

def test_block_ip_argv_rollback_si_expirare():
    p = P(ActionType.BLOCK_IP_TTL, "8.8.8.8", stats=GOOD)
    assert p.steps[0].argv == ["nft", "add", "element", "inet", "soc", "blocklist", "{", "8.8.8.8",
                               "timeout", "3600s", "}"]
    assert p.rollback[0].argv[:3] == ["nft", "delete", "element"]
    assert p.expires_at == NOW + timedelta(hours=1)


def test_freeze_cu_cont_si_expirare():
    p = P(ActionType.FREEZE_PROCESS, "4242")
    assert p.steps[0].argv == ["kill", "-STOP", "4242"] and p.rollback[0].argv == ["kill", "-CONT", "4242"]
    assert p.expires_at == NOW + timedelta(minutes=30)


def test_carantina_fara_expirare_cu_restaurare():
    p = P(ActionType.QUARANTINE_FILE, "/var/www/html/drop.php")
    assert p.expires_at is None
    mv, back = p.steps[1].argv, p.rollback[0].argv
    assert mv[:3] == ["mv", "--", "/var/www/html/drop.php"] and back == ["mv", "--", mv[3], mv[2]]


def test_fiecare_actiune_are_rollback():
    for a, t in [(ActionType.BLOCK_IP_TTL, "8.8.8.8"), (ActionType.FREEZE_PROCESS, "7"),
                 (ActionType.QUARANTINE_FILE, "/tmp/x"), (ActionType.ISOLATE_HOST, "web-prod")]:
        assert P(a, t).rollback, a


def test_pas_cu_sir_de_shell_respins():
    with pytest.raises(ValidationError):
        PlanStep(kind="ssh_argv", argv=["kill", "-STOP", "1\n; reboot"])
    with pytest.raises(ValidationError):
        PlanStep(kind="kibana_api", argv=["x"], method="POST", path="/api")


# ---------------- absolvire si aprobare ----------------

def test_fara_etichete_cere_aprobare():
    p = P(ActionType.BLOCK_IP_TTL, "8.8.8.8", stats=X.LabelStats(3, 2, 1, 0))
    assert not p.graduated and p.requires_approval and "3/50" in p.approval_reason


def test_statistici_lipsa_inseamna_neabsolvit():
    assert X.graduation(None)[0] is False


def test_absolvire_pe_praguri():
    assert X.graduation(GOOD)[0]
    assert not X.graduation(X.LabelStats(60, 55, 5, 0))[0]          # precizie 92%
    assert not X.graduation(X.LabelStats(60, 60, 0, 1))[0]          # un atac ratat recent


def test_clasa_absolvita_ieftina_ar_executa_automat():
    p = P(ActionType.BLOCK_IP_TTL, "8.8.8.8", stats=GOOD, criticality="high")
    assert p.graduated and not p.requires_approval
    assert X.summary(p).startswith("dry-run: block_ip_ttl") and "ar executa automat" in X.summary(p)


def test_izolarea_cere_mereu_aprobare():
    p = P(ActionType.ISOLATE_HOST, "web-prod", stats=GOOD, criticality="low")
    assert p.graduated and p.requires_approval and "aprobare umana mereu" in p.approval_reason
    assert p.steps[0].kind == "kibana_api" and p.steps[0].path.endswith("/isolate")
    assert p.steps[0].body["endpoint_ids"] == [AGENT] and p.rollback[0].path.endswith("/unisolate")


def test_planul_intra_in_audit():
    v = V(ActionType.BLOCK_IP_TTL, "8.8.8.8")
    a = AuditRecord(investigation_id="i", verdict=v, narrative="", policy_decision="x",
                    action_executed=ActionType.BLOCK_IP_TTL, started_at=NOW, finished_at=NOW,
                    execution_plan=P(ActionType.BLOCK_IP_TTL, "8.8.8.8"))
    assert a.model_dump(mode="json")["execution_plan"]["mode"] == "dry-run"


# ---------------- orchestratorul ----------------

def test_orchestrator_eroare_la_plan_nu_pierde_auditul(monkeypatch):
    import orchestrator
    monkeypatch.setattr(orchestrator, "make_plan", lambda v, d: (_ for _ in ()).throw(RuntimeError("x")))
    saved = {}
    monkeypatch.setattr(orchestrator, "persist", lambda *a, **k: saved.update(k))
    monkeypatch.setattr(orchestrator, "show", lambda *a, **k: None)
    orchestrator._record("LENT", "e", V(ActionType.ISOLATE_HOST, "web-prod"), "", NOW)
    assert saved["plan"] is None and "eroare la plan" in saved["action_result"]


def test_orchestrator_tinta_invalida_ramane_la_om(monkeypatch):
    import orchestrator
    monkeypatch.setattr(X, "fetch_stats", lambda es, a, now: None)
    monkeypatch.setattr(X, "fetch_criticality", lambda es, h: "high")
    monkeypatch.setattr(X, "fetch_agent_id", lambda es, h: None)
    plan, result = orchestrator.make_plan(V(ActionType.QUARANTINE_FILE, "drop.php"),
                                          D(ActionType.QUARANTINE_FILE))
    assert plan is None and "fara plan" in result and "ramane la om" in result

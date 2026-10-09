"""
MOD DEGRADAT — ce face sistemul cand modelul nu poate judeca.

Regula: esecul escaladeaza, nu inchide. Model cazut, tunel cazut, timeout,
exceptie in graf -> verdict `undetermined` + `escalate_human`, scris de COD,
cu motivul intr-o enumerare inchisa. Niciodata un benign implicit.

Plus doua plase:
  - restanta: peste BACKLOG_THRESHOLD alerte intr-un ciclu, coada se ordoneaza
    dupa severitate si criticitatea activului, iar alertele grave (critical)
    escaladeaza direct, fara model — nu asteapta in spatele celor minore
  - plafon de timp per caz: un model blocat nu tine ciclul pe loc

Fara Elasticsearch. Singurul acces la retea e verificarea de sanatate a
modelului, cu functia de citire injectabila (testabil fara retea).
"""

from __future__ import annotations

import contextvars
import json
import os
import threading
import urllib.request
import uuid
from typing import Any, Callable

from escalation import EscalationDecision
from llm import base_url, model_name
from schemas import (ActionType, Classification, EntityType, EscalationReason,
                     FailureKind, HOST_RE, Verdict)

BACKLOG_THRESHOLD = int(os.environ.get("BACKLOG_THRESHOLD", "20"))
CASE_TIMEOUT_FAST_S = float(os.environ.get("CASE_TIMEOUT_FAST_S", "90"))
CASE_TIMEOUT_HUNT_S = float(os.environ.get("CASE_TIMEOUT_HUNT_S", "600"))
HEALTH_TIMEOUT_S = 5

# Grava = escaladeaza direct sub restanta. Decis cu Tiberiu: doar critical.
SEVERE_LEVELS = {"critical"}
_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
_CRITICALITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

NARRATIVE = {
    FailureKind.MODEL_UNAVAILABLE: "Model indisponibil (verificarea de sanatate a esuat). "
                                   "Caz escaladat fara verdict de model.",
    FailureKind.CASE_TIMEOUT: "Plafonul de timp per caz a fost depasit. Caz escaladat fara verdict de model.",
    FailureKind.PROCESSING_ERROR: "Eroare la procesare. Caz escaladat fara verdict de model.",
    None: "Alerta grava in restanta: escaladata direct, fara model, ca sa nu astepte in coada.",
}


class CaseTimeout(Exception):
    pass


def _g(d: dict, path: str):
    if path in d:
        return d[path]
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


# --------------------------------------------------------------------------
# Restanta
# --------------------------------------------------------------------------


def is_backlog(n_alerts: int, threshold: int | None = None) -> bool:
    return n_alerts > (BACKLOG_THRESHOLD if threshold is None else threshold)


def is_severe(alert: dict) -> bool:
    return (_g(alert, "kibana.alert.severity") or "").lower() in SEVERE_LEVELS


def order_backlog(alerts: list[dict], criticality_of: Callable[[str], str | None]) -> list[dict]:
    """Cele grave primele, apoi dupa criticitatea activului, apoi cele mai vechi.
    Sortare stabila: la egalitate ramane ordinea cronologica."""
    def key(a: dict):
        sev = _SEVERITY_RANK.get((_g(a, "kibana.alert.severity") or "").lower(), -1)
        crit = _CRITICALITY_RANK.get((criticality_of(_g(a, "host.name") or "") or "").lower(), -1)
        return (-sev, -crit)
    return sorted(alerts, key=key)


# --------------------------------------------------------------------------
# Verdicte fara model
# --------------------------------------------------------------------------


def no_model_verdict(entity_id: str | None, source_path: str) -> Verdict:
    """Verdictul scris de cod cand modelul n-a judecat. Mereu undetermined +
    escalate_human; entitatea trece prin aceeasi validare ca orice verdict."""
    ent = entity_id if entity_id and HOST_RE.match(entity_id) else "unknown"
    return Verdict(
        investigation_id=str(uuid.uuid4()), source_path=source_path,
        entity_type=EntityType.HOST, entity_id=ent,
        classification=Classification.UNDETERMINED, confidence=0, rarity_score=1.0,
        proposed_action=ActionType.ESCALATE_HUMAN, model_id="none",
    )


def failure_escalation() -> EscalationDecision:
    return EscalationDecision(escalate=True,
                              reasons=[EscalationReason.UNDETERMINED, EscalationReason.TIER1_FAILURE])


def backlog_escalation() -> EscalationDecision:
    return EscalationDecision(escalate=True, reasons=[EscalationReason.BACKLOG_SEVERE])


# --------------------------------------------------------------------------
# Plafon de timp si sanatatea modelului
# --------------------------------------------------------------------------


def run_with_timeout(fn: Callable[[], Any], timeout_s: float) -> Any:
    """Ruleaza fn intr-un fir separat; dupa timeout_s ridica CaseTimeout.
    Firul blocat nu poate fi oprit din Python — il lasam sa se termine singur
    (e daemon, iar clientul LLM are oricum timeout propriu), rezultatul se ignora."""
    box: dict = {}
    ctx = contextvars.copy_context()   # urma cazului (tracing) trebuie sa ajunga si in fir

    def target():
        try:
            box["result"] = ctx.run(fn)
        except BaseException as e:   # transmis apelantului
            box["error"] = e

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout_s)
    if t.is_alive():
        raise CaseTimeout(f"depasit {timeout_s:.0f}s")
    if "error" in box:
        raise box["error"]
    return box.get("result")


def _fetch_json(url: str, timeout: float) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:   # adresa vine din mediu, nu din telemetrie
        return json.loads(r.read().decode("utf-8"))


def llm_healthy(role: str, fetch: Callable[[str, float], dict] = _fetch_json) -> bool:
    """Endpoint-ul rolului raspunde SI are modelul configurat incarcat.
    Prinde si tunelul cazut, si modelul lipsa de pe server."""
    try:
        data = fetch(base_url(role).rstrip("/") + "/models", HEALTH_TIMEOUT_S)
        ids = {m.get("id") for m in data.get("data", []) if isinstance(m, dict)}
        return model_name(role) in ids
    except Exception:
        return False

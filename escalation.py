"""
ESCALADARE Tier 1 -> Tier 2. Decisa de COD, nu de model.

Functie pura: fara LLM, fara Elasticsearch. Primeste verdictul caii rapide si
doua fapte calculate de cod; intoarce decizia si MOTIVELE. Motivele sunt o
enumerare inchisa, deci pot trece granita (ca ActionType).

Tier 2 primeste motivele si dovezile, NU verdictul Tier 1 (contra ancorarii).
"""
from __future__ import annotations

import os
from enum import Enum

from pydantic import BaseModel, ConfigDict

from schemas import Classification, Verdict

# PROVIZORIU. Se fixeaza din distributia reala a increderii, nu din intuitie.
LOW_CONF = int(os.environ.get("ESC_LOW_CONF", "70"))


class EscalationReason(str, Enum):
    UNDETERMINED = "undetermined"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    FLOOR_OVERRIDE = "floor_override"          # codul a rasturnat un benign al modelului
    LOW_CONFIDENCE = "low_confidence"
    BENIGN_UNSEEN_PAIR = "benign_unseen_pair"  # benign pe ceva nevazut in baseline


class EscalationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    escalate: bool
    reasons: list[EscalationReason]


def should_escalate(v: Verdict, *, floor_applied: bool,
                    pair_in_baseline: bool | None) -> EscalationDecision:
    r: list[EscalationReason] = []
    c = v.classification
    if c is Classification.UNDETERMINED:
        r.append(EscalationReason.UNDETERMINED)
    elif c is Classification.SUSPICIOUS:
        r.append(EscalationReason.SUSPICIOUS)
    elif c is Classification.MALICIOUS:
        r.append(EscalationReason.MALICIOUS)
    if floor_applied:
        r.append(EscalationReason.FLOOR_OVERRIDE)
    if v.confidence < LOW_CONF:
        r.append(EscalationReason.LOW_CONFIDENCE)
    # None = nu se poate verifica (ex. alerta de fisier fara parinte) -> tratat ca nevazut
    if c is Classification.BENIGN and pair_in_baseline is not True:
        r.append(EscalationReason.BENIGN_UNSEEN_PAIR)
    return EscalationDecision(escalate=bool(r), reasons=r)

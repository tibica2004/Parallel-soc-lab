"""
ESCALADARE Tier 1 -> Tier 2. Decisa de COD, nu de model.

Functie pura: fara LLM, fara Elasticsearch. Primeste verdictul caii rapide si
doua fapte calculate de cod; intoarce decizia si MOTIVELE. Motivele sunt o
enumerare inchisa, deci pot trece granita (ca ActionType).

Tier 2 primeste motivele si dovezile, NU verdictul Tier 1 (contra ancorarii).
"""
from __future__ import annotations

import os

from pydantic import BaseModel, ConfigDict

# EscalationReason sta in schemas.py (o foloseste si Case); re-exportata aici.
from schemas import Classification, EscalationReason, Verdict

# PROVIZORIU. Se fixeaza din distributia reala a increderii, nu din intuitie.
# 90: sub atat, un benign nu se inchide pe Tier 1 (preferam escaladarea).
LOW_CONF = int(os.environ.get("ESC_LOW_CONF", "90"))


class EscalationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    escalate: bool
    reasons: list[EscalationReason]


def should_escalate(v: Verdict, *, floor_applied: bool,
                    pair_in_baseline: bool | None, native_detection: bool = False,
                    honeytoken: bool = False, sensor_detection: bool = False) -> EscalationDecision:
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
    # Detectia proprie a EDR-ului nu se inchide pe Tier 1, oricat de sigur e modelul.
    if native_detection:
        r.append(EscalationReason.NATIVE_DETECTION)
    # Momeala atinsa: nu exista explicatie benigna pe care s-o accepte o masina.
    if honeytoken:
        r.append(EscalationReason.HONEYTOKEN)
    if sensor_detection:
        r.append(EscalationReason.SENSOR_DETECTION)
    return EscalationDecision(escalate=bool(r), reasons=r)

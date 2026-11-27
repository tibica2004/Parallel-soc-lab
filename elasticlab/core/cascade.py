"""Cascada Tier 1 (faza 24): ce decide fiecare pas, ca FUNCTIE PURA (tabelul de adevar e testat).

Pentru fiecare caz nou, dupa faptele calculate o singura data (pasul 0):

  1. clasa critica sau o podea care s-ar aplica  -> sare peste 2-3, merge la 4   (L4)
  2. grup cu consens uman: benign -> inchidere; attack -> motiv + pasul 4
  3. sursa de decizie activa si sigura: benign peste prag -> inchidere;
     atac probabil -> motiv + pasul 4; outlier sau nesigur -> pasul 4
  4. fast_path + should_escalate, ca azi

Cascada scurteaza drumul DOAR pentru inchideri. Inchiderea si motivele au efect doar cand
T1_CASCADE=on SI pipeline-ul are model activ; altfel decizia se inregistreaza (umbra) si cazul
merge la pasul 4 neschimbat. Din inchiderile efective, un esantion determinist (implicit 10%)
merge oricum la om, cu motivul `control_sample`: din el se masoara eroarea.

Erorile nu se trateaza aici: apelantul (tier1/cascade.py) prinde orice exceptie si intoarce
pasul ERROR, adica pasul 4 (L6).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from elasticlab.contracts.learning import (BucketKey, CascadeDecision, CascadeMode, CascadeStep,
                                           Consensus, ModelDecision, ModelState, PipelineConfig,
                                           Prediction)
from elasticlab.contracts.schemas import EscalationReason

MODES = {m.value: m for m in CascadeMode}


def mode_from_env(env) -> CascadeMode:
    """T1_CASCADE=off|shadow|on. Lipsa sau valoare necunoscuta = off (L5: oprirea de urgenta si
    implicitul sunt aceeasi stare)."""
    return MODES.get(str(env.get("T1_CASCADE", "off")).strip().lower(), CascadeMode.OFF)


def in_control_sample(key: str, pct: int) -> bool:
    """Alegere determinista: acelasi caz e mereu (sau niciodata) in esantion, deci o reluare nu
    schimba decizia. sha256, nu hash() (care e aleator intre procese)."""
    if pct <= 0:
        return False
    return int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16) % 100 < pct


@dataclass(frozen=True)
class CascadeInputs:
    mode: CascadeMode
    pipeline: PipelineConfig | None
    bucket: BucketKey | None = None
    critical: tuple[str, ...] = ()         # clasele critice (L4) care se aplica
    floor: bool = False                     # s-ar aplica o podea din fast_path (L4)
    consensus: Consensus = Consensus.NONE
    pipeline_active: bool = False           # pipeline-ul are model activ (controlorul)
    model_state: ModelState | None = None   # starea modelului care a dat predictia
    prediction: Prediction | None = None
    sample_key: str = ""
    extra: dict = field(default_factory=dict)


def decide(inp: CascadeInputs) -> CascadeDecision:
    base = dict(mode=inp.mode, pipeline=inp.pipeline.id if inp.pipeline else None,
                dp_version=inp.pipeline.decision_points_version if inp.pipeline else None,
                bucket_id=inp.bucket.bucket_id if inp.bucket else None,
                values=dict(inp.bucket.values) if inp.bucket else {},
                consensus=inp.consensus, model_state=inp.model_state, prediction=inp.prediction,
                pipeline_active=inp.pipeline_active)
    if inp.pipeline is None:
        return CascadeDecision(step=CascadeStep.NO_PIPELINE, **base)
    if inp.critical:
        return CascadeDecision(step=CascadeStep.CRITICAL, **base)
    if inp.floor:
        return CascadeDecision(step=CascadeStep.FLOOR, **base)

    effective = inp.mode is CascadeMode.ON and inp.pipeline_active
    step, would_close, reasons = CascadeStep.FAST_PATH, False, []
    if inp.consensus is Consensus.BENIGN:
        step, would_close = CascadeStep.HUMAN_LABEL, True
    elif inp.consensus is Consensus.ATTACK:
        step, reasons = CascadeStep.HUMAN_LABEL, [EscalationReason.BUCKET_LABELED_ATTACK.value]
    elif inp.prediction is not None:
        p = inp.prediction
        th = inp.pipeline.thresholds
        # Predictia unui model din umbra nu are efect nici in modul on.
        effective = effective and (p.source == "external" or inp.model_state is ModelState.ACTIVE)
        if p.decision is ModelDecision.BENIGN and p.confidence >= th.benign_close and not p.outlier:
            step, would_close = CascadeStep.MODEL, True
        elif p.decision is ModelDecision.ATTACK:
            step, reasons = CascadeStep.MODEL, [EscalationReason.MODEL_ATTACK_LIKELY.value]
        # nesigur sau outlier: pasul 4, fara motiv
    control = False
    applied = False
    if would_close:
        control = in_control_sample(inp.sample_key, inp.pipeline.thresholds.control_sample_pct)
        if control:
            reasons = [*reasons, EscalationReason.CONTROL_SAMPLE.value]
        else:
            applied = effective
    return CascadeDecision(step=step, would_close=would_close, applied=applied,
                           control_sample=control, reasons=reasons,
                           applied_reasons=effective and bool(reasons), **base)


def floor_would_apply(ctx: dict, web_exec: bool) -> bool:
    """Podelele din fast_path.node_finalize, citite din aceleasi fapte: daca s-ar aplica vreuna pe un
    benign, cascada nu are voie sa inchida (L4). Conservator: orice fapt de risc opreste inchiderea."""
    return bool(ctx.get("ran_by_web_service_account") or ctx.get("honeytoken")
                or (ctx.get("sensitive_action")
                    and not (ctx.get("in_maintenance_window") and ctx.get("ran_by_known_admin")))
                or web_exec)

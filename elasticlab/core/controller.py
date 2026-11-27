"""Controlorul de activare (faza 24): COD determinist, nu omul si nu agentul, decide starea
modelului fiecarui pipeline. Functie pura: ControllerInput -> lista de tranzitii.

  candidat -> umbra   automat, daca metricile de validare nu scad fata de modelul din umbra
                      (masurat pe ACEEASI validare) si etichetele s-au schimbat destul (altfel
                      reantrenarea orara ar reporni la fiecare ora ceasul de 7 zile al umbrei).
  umbra -> activ      automat, cand TOATE conditiile sunt adevarate (activation_blockers() == []).
  activ -> umbra      automat si imediat, la oricare declansator (demotion_reasons()).

Fiecare tranzitie are un motiv in clar; tier3 o aplica in registru, trimite notificarea, scrie
documentul in soc-metrics si auditul.
"""
from __future__ import annotations

from datetime import timedelta

from elasticlab.contracts.learning import (ControllerInput, ModelRecord, ModelState, Transition,
                                           ValidationMetrics)

MIN_LABELS_PER_CLASS = 50
MIN_CLOSURE_PRECISION = 0.95
MIN_SHADOW_DAYS = 7
MIN_SHADOW_DECISIONS = 100
MAX_CONTRADICTED = 0.02
MIN_LABEL_CHANGE = 5


def _t(inp: ControllerInput, rec: ModelRecord, to: ModelState, reason: str) -> Transition:
    return Transition(pipeline=inp.pipeline, model_hash=rec.model_hash, from_state=rec.state,
                      to_state=to, reason=reason[:300], at=inp.now)


def demotion_reasons(inp: ControllerInput) -> list[str]:
    s, th = inp.active_stats, inp.thresholds
    out = []
    if s.hash_mismatch:
        out.append("hash-ul modelului nu corespunde manifestului")
    if s.human_attack_on_closed_bucket:
        out.append("un om a etichetat attack un grup inchis de cascada")
    if s.control_labeled and s.control_disagreements / s.control_labeled > th.max_control_disagreement:
        out.append(f"dezacord pe esantionul de control {s.control_disagreements}/{s.control_labeled} "
                   f"> {th.max_control_disagreement:.0%}")
    if s.new_bucket_rate is not None and s.new_bucket_rate > th.max_new_bucket_rate:
        out.append(f"rata de grupuri noi {s.new_bucket_rate:.2f} > {th.max_new_bucket_rate:.2f}")
    if s.outlier_rate is not None and s.outlier_rate > th.max_outlier_rate:
        out.append(f"rata de outlieri {s.outlier_rate:.2f} > {th.max_outlier_rate:.2f}")
    return out


def not_worse(new: ValidationMetrics, old: ValidationMetrics | None) -> bool:
    """Metricile de validare nu scad: nu inchide mai multe atacuri, nu are precizie a inchiderilor
    sau recall pe attack mai mici. Fara referinta (prima umbra) -> adevarat."""
    if old is None:
        return True
    if new.closed_attacks > old.closed_attacks:
        return False
    for a, b in ((new.closure_precision(), old.closure_precision()), (new.recall, old.recall)):
        if b is not None and (a is None or a < b):
            return False
    return True


def activation_blockers(inp: ControllerInput) -> list[str]:
    """Conditiile umbra -> activ care NU sunt indeplinite (lista goala = se activeaza)."""
    sh = inp.shadow
    if sh is None:
        return ["niciun model in umbra"]
    out = []
    if inp.labels_attack < MIN_LABELS_PER_CLASS or inp.labels_benign < MIN_LABELS_PER_CLASS:
        out.append(f"etichete {inp.labels_attack} attack / {inp.labels_benign} benign "
                   f"(minim {MIN_LABELS_PER_CLASS} din fiecare)")
    val = inp.shadow_validation_now or sh.validation
    if val.closed_attacks:
        out.append(f"pe validare inchide {val.closed_attacks} atacuri")
    cp = val.closure_precision()
    if cp is None or cp < MIN_CLOSURE_PRECISION:
        out.append(f"precizia inchiderilor pe validare {cp} < {MIN_CLOSURE_PRECISION}")
    if inp.now - sh.state_since < timedelta(days=MIN_SHADOW_DAYS):
        out.append(f"in umbra de {(inp.now - sh.state_since).days} zile (minim {MIN_SHADOW_DAYS})")
    st = inp.shadow_stats
    if st.decisions < MIN_SHADOW_DECISIONS:
        out.append(f"{st.decisions} decizii in umbra (minim {MIN_SHADOW_DECISIONS})")
    if st.closures and st.contradicted / st.closures > MAX_CONTRADICTED:
        out.append(f"inchideri contrazise {st.contradicted}/{st.closures} > {MAX_CONTRADICTED:.0%}")
    if st.closures_on_attack_buckets:
        out.append(f"{st.closures_on_attack_buckets} inchideri pe grupuri etichetate attack")
    if not inp.regression_passed_for_shadow:
        out.append("nicio regresie trecuta pe setul de aur cu acest model si acest set de prompturi")
    return out


def step(inp: ControllerInput) -> list[Transition]:
    out: list[Transition] = []
    # 1. Retrogradarea: imediat, inaintea oricarei promovari din aceeasi rulare.
    if inp.active is not None:
        why = demotion_reasons(inp)
        if why:
            if inp.shadow is not None and inp.shadow.model_hash != inp.active.model_hash:
                out.append(_t(inp, inp.shadow, ModelState.RETIRED, "inlocuit de modelul retrogradat"))
            out.append(_t(inp, inp.active, ModelState.SHADOW, "retrogradat: " + "; ".join(why)))
            return out
    # 2. Candidat -> umbra.
    c = inp.candidate
    known = {r.model_hash for r in (inp.shadow, inp.active) if r is not None}
    if c is not None and c.model_hash not in known:
        if inp.shadow is None:
            out.append(_t(inp, c, ModelState.SHADOW, "primul model in umbra pentru pipeline"))
            return out
        if inp.labels_changed_since_shadow >= MIN_LABEL_CHANGE and not_worse(
                c.validation, inp.shadow_validation_now or inp.shadow.validation):
            out.append(_t(inp, inp.shadow, ModelState.RETIRED, "inlocuit de un candidat"))
            out.append(_t(inp, c, ModelState.SHADOW,
                          f"metricile de validare nu scad; {inp.labels_changed_since_shadow} etichete noi"))
            return out
    # 3. Umbra -> activ.
    sh = inp.shadow
    if sh is not None and (inp.active is None or inp.active.model_hash != sh.model_hash):
        if not activation_blockers(inp):
            if inp.active is not None:
                out.append(_t(inp, inp.active, ModelState.RETIRED, "inlocuit de modelul din umbra"))
            out.append(_t(inp, sh, ModelState.ACTIVE, "toate conditiile de activare indeplinite"))
    return out

"""
MOTOR DE POLITICI — traduce un verdict intr-o DECIZIE de actiune.

Principiul: pragul de incredere creste cu costul de reversibilitate al actiunii.
O actiune ireversibila nu se executa niciodata automat. Modelul PROPUNE o actiune
in verdict; motorul decide daca ea e permisa la increderea data — sau o coboara
la una mai ieftina, ori la escaladare.

SHADOW_MODE (implicit true): nimic nu se executa. Decizia se calculeaza si se
logheaza exact ca in productie, dar `executed=False`. Asa masori ce AR FI facut
sistemul, saptamani la rand, inainte sa-i dai voie sa actioneze.

Nimic din fisierul asta nu atinge Elasticsearch sau reteaua. E cod pur, testabil.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from schemas import ActionType, Verdict

# Pragul minim de incredere per actiune, dupa reversibilitate.
# 101 = imposibil automat (niciun verdict nu depaseste 100).
THRESHOLDS: dict[ActionType, int] = {
    ActionType.NONE: 0,
    ActionType.ENRICH_ONLY: 0,
    ActionType.ESCALATE_HUMAN: 0,
    # reversibile
    ActionType.BLOCK_IP_TTL: 85,     # firewall, expira singur
    ActionType.FREEZE_PROCESS: 85,   # SIGSTOP, pastreaza dovada
    ActionType.QUARANTINE_FILE: 90,  # mutare cu backup
    # scumpe
    ActionType.ISOLATE_HOST: 95,     # taie hostul din retea
    ActionType.ROTATE_CREDENTIALS: 95,
    # ireversibile — niciodata automat
    ActionType.KILL_PROCESS: 101,    # distruge payload-ul din memorie
}

# Cand actiunea propusa nu e permisa, coboram la asta (nu direct la "nimic":
# un caz care merita o actiune scumpa merita macar ochi uman).
FALLBACK = ActionType.ESCALATE_HUMAN

# Prefixe de tinta pe care nu le blocam niciodata ( retea interna, loopback).
NEVER_BLOCK_PREFIXES = ("127.", "10.", "172.16.", "172.17.", "172.18.",
                        "172.20.", "192.168.", "::1")


@dataclass
class Decision:
    proposed: ActionType          # ce a cerut verdictul
    chosen: ActionType            # ce permite politica
    executed: bool                # a fost executata? (False in shadow)
    shadow_mode: bool
    reason: str


def _shadow() -> bool:
    return os.environ.get("SHADOW_MODE", "true").lower() != "false"


def _target_protected(action: ActionType, target: str | None) -> bool:
    """Nu bloca/izola tinte interne — risc de a te taia singur din propria retea."""
    if action not in (ActionType.BLOCK_IP_TTL, ActionType.ISOLATE_HOST):
        return False
    if not target:
        return True  # actiune de blocare fara tinta clara: refuz
    return target.startswith(NEVER_BLOCK_PREFIXES)


def decide(verdict: Verdict) -> Decision:
    """Decizia determinista. Nu executa nimic — doar alege si explica."""
    proposed = verdict.proposed_action
    conf = verdict.confidence
    shadow = _shadow()

    # 1. Actiunile gratuite trec mereu.
    if proposed in (ActionType.NONE, ActionType.ENRICH_ONLY, ActionType.ESCALATE_HUMAN):
        chosen, reason = proposed, "actiune fara cost, permisa"

    # 2. Tinta protejata -> nu blocam intern, escaladam.
    elif _target_protected(proposed, verdict.action_target):
        chosen, reason = FALLBACK, f"tinta protejata sau lipsa ({verdict.action_target}); escaladat"

    # 3. Prag de incredere pe reversibilitate.
    elif conf >= THRESHOLDS.get(proposed, 101):
        chosen, reason = proposed, f"incredere {conf} >= prag {THRESHOLDS[proposed]}"

    else:
        chosen = FALLBACK
        reason = f"incredere {conf} < prag {THRESHOLDS.get(proposed, 101)} pentru {proposed.value}; escaladat"

    # 4. In shadow, nimic nu se executa — dar decizia e calculata la fel.
    #    Chiar in afara shadow, actiunile gratuite nu "se executa" (nu fac nimic in lume).
    executable = chosen not in (ActionType.NONE, ActionType.ENRICH_ONLY, ActionType.ESCALATE_HUMAN)
    executed = executable and not shadow

    return Decision(proposed=proposed, chosen=chosen, executed=executed,
                    shadow_mode=shadow, reason=reason)

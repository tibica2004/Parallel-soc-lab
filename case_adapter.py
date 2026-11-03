"""
CASE ADAPTER — alerta escaladata / finding de raritate -> Case pentru Tier 2.

Functie pura: fara model, fara Elasticsearch. Ce trece:
  - identitatea cazului (chain_id, host, process.entity_id, parinte, copil, regula)
  - motivele escaladarii (enumerare inchisa, decise de cod)
  - fapte calculate de cod (raritatea perechii fata de baseline)
  - referinte opace la documente (evidence_refs)
Ce NU trece, niciodata: classification, confidence, narrative de la Tier 1
(principiul 7 — un investigator care vede "suspicious/70" se ancoreaza in el).
Case are extra="forbid", deci si o greseala aici ar crapa, nu ar strecura verdictul.

Campurile din telemetrie (nume de procese) se curata de caractere de control si
se trunchiaza; un entity_id cu forma invalida se lasa deoparte (Tier 2 cade pe
cautarea dupa parinte-copil), in loc sa blocheze cazul.
"""

from __future__ import annotations

import re

from escalation import EscalationDecision
from schemas import ENTITY_ID_RE, Case, EvidenceRef, RarityFinding

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _g(d: dict, path: str):
    if path in d:
        return d[path]
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def _clean(v, limit: int) -> str | None:
    if not isinstance(v, str) or not v:
        return None
    return _CONTROL.sub(" ", v)[:limit]


def _entity(v) -> str | None:
    return v if isinstance(v, str) and ENTITY_ID_RE.match(v) else None


def from_alert(alert: dict, escalation: EscalationDecision, chain_id: str,
               facts: dict | None = None, refs: list[EvidenceRef] | tuple = ()) -> Case:
    """
    Alerta escaladata de Tier 1 -> Case.

    `facts` = contextul DETERMINIST calculat de Tier 1 (build_context), nu verdictul:
    de acolo luam parintele reconstruit (alertele de fisier nu-l au) si perechea
    fata de baseline. Orice alt camp din facts e ignorat.
    """
    facts = facts or {}
    ex = facts.get("execution") or {}
    pair = facts.get("pair_in_baseline")
    return Case(
        chain_id=chain_id,
        origin="tier1_alert",
        # Senzorii de retea (Suricata) nu pun host.name; hostul e observer.hostname /
        # agent.name (acelasi COALESCE ca in sweep-urile din elastic_tools). Fara fallback,
        # orice alerta de senzor escaladata la Tier 2 crapa pe host gol.
        host=_g(alert, "host.name") or _g(alert, "observer.hostname") or _g(alert, "agent.name") or "",
        entity_id=_entity(ex.get("entity_id") or _g(alert, "process.entity_id")),
        parent=_clean(ex.get("parent") or _g(alert, "process.parent.name"), 255),
        child=_clean(ex.get("process") or _g(alert, "process.name"), 255),
        rule_name=_clean(_g(alert, "kibana.alert.rule.name"), 256),
        escalation_reasons=list(escalation.reasons),
        evidence_refs=[r for r in refs if r is not None][:50],
        rarity_score=0.0 if pair is True else 1.0,
    )


def from_finding(finding: RarityFinding, chain_id: str) -> Case:
    """Finding de raritate -> Case (fara motive: nu vine din Tier 1)."""
    d = finding.detail or {}
    return Case(
        chain_id=chain_id,
        origin="rarity_sweep",
        host=finding.entity_id,
        parent=_clean(d.get("parent"), 255),
        child=_clean(d.get("child"), 255),
        evidence_refs=list(finding.evidence_refs)[:50],
        rarity_score=finding.rarity_score,
    )

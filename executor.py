"""
EXECUTORUL — traduce o Decision intr-un PLAN concret de actiune. DOAR dry-run.

Nu exista in fisierul asta niciun cod care sa execute ceva (nici subprocess, nici
ssh, nici cereri HTTP). Planul se scrie in audit si arata ce s-ar fi facut,
cum s-ar fi anulat si daca ar fi cerut aprobare. Trecerea la executie reala e o
decizie a omului, dupa absolvire si rollback testat in laborator, nu un flag.

Contractul fiecarei actiuni (din conversatia de proiectare):
  - pasi concreti ca argv (niciodata sir de shell) sau apel API;
  - rollback obligatoriu: nu exista actiune fara planul de anulare;
  - expirare pentru cele ieftine: se anuleaza singure daca nu sunt confirmate;
  - raza de impact: criticitatea activului din asset-inventory;
  - absolvire: o clasa 'ar executa automat' doar cu >= MIN_LABELS etichete umane
    si precizie >= MIN_PRECISION la pragul ei; altfel 'ar cere aprobare'.
kill_process si rotate_credentials nu au executor: ireversibile, raman la om.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from policy import NEVER_BLOCK_PREFIXES, THRESHOLDS, Decision
from schemas import ActionPlan, ActionType, PlanStep, Reversibility, Verdict

# Absolvire (aprobate de Tiberiu, 2026-10-15)
MIN_LABELS = 50
MIN_PRECISION = 0.95
FN_WINDOW_DAYS = 30
LABEL_WINDOW_DAYS = 90

QUARANTINE_DIR = "/var/lib/soc-quarantine"
NFT_SET = ("inet", "soc", "blocklist")
# Unde are voie carantina sa mute fisiere: locurile unde scrie un atacator web.
QUARANTINE_ROOTS = ("/var/www/", "/tmp/", "/var/tmp/", "/dev/shm/", "/home/")

PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._\-]+/)*[A-Za-z0-9._\-]+$")
PID_RE = re.compile(r"^[1-9][0-9]{0,6}$")
HOST_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,253}$")
AGENT_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


@dataclass(frozen=True)
class Contract:
    reversibility: Reversibility
    target_kind: str                 # ip | pid | path | host
    ttl: timedelta | None            # anulare automata; None = rollback doar de om
    always_approval: bool            # scumpe: aprobare umana chiar daca e absolvita
    side_effects: str


CONTRACTS: dict[ActionType, Contract] = {
    ActionType.BLOCK_IP_TTL: Contract(Reversibility.CHEAP, "ip", timedelta(hours=1), False,
                                      "IP-ul extern nu mai ajunge la host; expira singur"),
    ActionType.FREEZE_PROCESS: Contract(Reversibility.CHEAP, "pid", timedelta(minutes=30), False,
                                        "procesul e oprit (SIGSTOP), memoria si dovezile raman"),
    # Fara expirare: restaurarea automata a unui webshell ar fi mai rea decat carantina.
    ActionType.QUARANTINE_FILE: Contract(Reversibility.CHEAP, "path", None, False,
                                         "fisierul e mutat intr-un director 0700, cu cale de restaurare"),
    ActionType.ISOLATE_HOST: Contract(Reversibility.EXPENSIVE, "host", None, True,
                                      "hostul iese din retea, cu exceptia agentului Elastic"),
}


class PlanError(ValueError):
    """Tinta invalida sau actiune fara executor: nu se face plan, se escaladeaza."""


# ------------------------------------------------------------------------------
# Functii pure
# ------------------------------------------------------------------------------

def check_target(kind: str, target: str | None, host: str) -> str:
    if not target:
        raise PlanError("tinta lipsa")
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            raise PlanError(f"IP invalid: {target!r}")
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast \
                or target.startswith(NEVER_BLOCK_PREFIXES):
            raise PlanError(f"IP intern sau protejat: {target}")
        return str(ip)
    if kind == "pid":
        if not PID_RE.match(target):
            raise PlanError(f"PID invalid: {target!r}")
        return target
    if kind == "path":
        if not PATH_RE.match(target) or "/../" in target or "/./" in target:
            raise PlanError(f"cale invalida: {target!r}")
        if not target.startswith(QUARANTINE_ROOTS):
            raise PlanError(f"cale in afara zonelor de carantina: {target}")
        return target
    if kind == "host":
        if target != host:
            raise PlanError(f"tinta {target!r} nu e hostul verdictului ({host})")
        return target
    raise PlanError(f"tip de tinta necunoscut: {kind}")


def _ssh(*argv: str) -> PlanStep:
    return PlanStep(kind="ssh_argv", argv=list(argv))


def build_steps(action: ActionType, target: str, ttl: timedelta | None,
                agent_id: str | None = None) -> tuple[list[PlanStep], list[PlanStep]]:
    """(pasi, rollback). Argv-uri fixe; tinta e deja validata dupa tipul ei."""
    if action is ActionType.BLOCK_IP_TTL:
        secs = f"{int(ttl.total_seconds())}s"
        return ([_ssh("nft", "add", "element", *NFT_SET, "{", target, "timeout", secs, "}")],
                [_ssh("nft", "delete", "element", *NFT_SET, "{", target, "}")])
    if action is ActionType.FREEZE_PROCESS:
        return [_ssh("kill", "-STOP", target)], [_ssh("kill", "-CONT", target)]
    if action is ActionType.QUARANTINE_FILE:
        q = f"{QUARANTINE_DIR}/{hashlib.sha256(target.encode()).hexdigest()[:24]}"
        return ([_ssh("install", "-d", "-m", "700", QUARANTINE_DIR), _ssh("mv", "--", target, q)],
                [_ssh("mv", "--", q, target)])
    if action is ActionType.ISOLATE_HOST:
        if not agent_id or not AGENT_RE.match(agent_id):
            raise PlanError(f"agent.id necunoscut sau invalid pentru {target}")
        body = {"endpoint_ids": [agent_id], "comment": "soc: plan dry-run"}
        return ([PlanStep(kind="kibana_api", method="POST", path="/api/endpoint/action/isolate", body=body)],
                [PlanStep(kind="kibana_api", method="POST", path="/api/endpoint/action/unisolate", body=body)])
    raise PlanError(f"{action.value} nu are executor")


@dataclass(frozen=True)
class LabelStats:
    labeled: int        # verdicte cu aceasta actiune, etichetate de om, la pragul ei
    tp: int
    fp: int
    fn_recent: int      # atacuri ratate (FN) in ultimele FN_WINDOW_DAYS, pe tot sistemul


def graduation(stats: LabelStats | None) -> tuple[bool, str]:
    """Absolvirea unei clase, din etichete umane. Fara date -> neabsolvita."""
    if stats is None:
        return False, "statisticile de etichete nu sunt disponibile"
    if stats.labeled < MIN_LABELS:
        return False, f"{stats.labeled}/{MIN_LABELS} etichete umane"
    prec = stats.tp / max(stats.tp + stats.fp, 1)
    if prec < MIN_PRECISION:
        return False, f"precizie {prec:.0%} < {MIN_PRECISION:.0%}"
    if stats.fn_recent > 0:
        return False, f"{stats.fn_recent} atacuri ratate in {FN_WINDOW_DAYS} zile"
    return True, f"{stats.labeled} etichete, precizie {prec:.0%}, 0 FN in {FN_WINDOW_DAYS} zile"


def plan(verdict: Verdict, decision: Decision, now: datetime, stats: LabelStats | None = None,
         criticality: str | None = None, agent_id: str | None = None) -> ActionPlan | None:
    """None pentru actiunile gratuite. PlanError pentru tinte invalide (apelantul
    escaladeaza). Nu executa nimic."""
    action = decision.chosen
    if action in (ActionType.NONE, ActionType.ENRICH_ONLY, ActionType.ESCALATE_HUMAN):
        return None
    c = CONTRACTS.get(action)
    if c is None:
        raise PlanError(f"{action.value} nu are executor (ireversibila, ramane la om)")
    host = verdict.entity_id if verdict.entity_type.value == "host" else None
    if not host or not HOST_RE.match(host):
        raise PlanError("verdictul nu are un host ca entitate")
    target = check_target(c.target_kind, verdict.action_target, host)
    steps, rollback = build_steps(action, target, c.ttl, agent_id)
    grad, grad_why = graduation(stats)
    reasons = []
    if not grad:
        reasons.append(f"clasa neabsolvita ({grad_why})")
    if c.always_approval:
        reasons.append(f"actiune {c.reversibility.value}: aprobare umana mereu")
    if criticality in (None, "high", "critical") and c.reversibility is Reversibility.EXPENSIVE:
        reasons.append(f"activ cu criticitate {criticality or 'necunoscuta'}")
    return ActionPlan(
        action=action, host=host, target=target, reversibility=c.reversibility,
        steps=steps, rollback=rollback, expires_at=(now + c.ttl) if c.ttl else None,
        asset_criticality=criticality, graduated=grad, graduation_reason=grad_why[:300],
        requires_approval=bool(reasons), approval_reason="; ".join(reasons)[:300])


def summary(p: ActionPlan) -> str:
    what = "ar cere aprobare" if p.requires_approval else "ar executa automat"
    exp = f", expira {p.expires_at:%H:%M} UTC" if p.expires_at else ""
    return f"dry-run: {p.action.value} pe {p.target} ({p.host}) {what}{exp}"[:500]


# ------------------------------------------------------------------------------
# I/O: doar citire (cheia read-only). Orice esec -> None, deci neabsolvit.
# ------------------------------------------------------------------------------

def fetch_stats(es, action: ActionType, now: datetime) -> LabelStats | None:
    try:
        base = [{"term": {"label_source.keyword": "human"}},
                {"range": {"@timestamp": {"gte": (now - timedelta(days=LABEL_WINDOW_DAYS)).isoformat()}}}]
        mine = base + [{"term": {"proposed_action.keyword": action.value}},
                       {"range": {"confidence": {"gte": THRESHOLDS[action]}}}]
        r = es.search(index="verdicts-history", size=0, query={"bool": {"filter": mine}},
                      aggs={"o": {"terms": {"field": "label_outcome.keyword", "size": 4}}})
        by = {b["key"]: b["doc_count"] for b in r["aggregations"]["o"]["buckets"]}
        fn = es.count(index="verdicts-history", query={"bool": {"filter": [
            {"term": {"label_source.keyword": "human"}}, {"term": {"label_outcome.keyword": "FN"}},
            {"range": {"@timestamp": {"gte": (now - timedelta(days=FN_WINDOW_DAYS)).isoformat()}}}]}})["count"]
        return LabelStats(labeled=r["hits"]["total"]["value"], tp=by.get("TP", 0), fp=by.get("FP", 0), fn_recent=fn)
    except Exception:
        return None


def fetch_criticality(es, host: str) -> str | None:
    try:
        r = es.search(index="asset-inventory", size=1, query={"term": {"host.name.keyword": host}})
        hits = r["hits"]["hits"]
        return str(hits[0]["_source"].get("criticality"))[:32] if hits else None
    except Exception:
        return None


def fetch_agent_id(es, host: str) -> str | None:
    """agent.id-ul Elastic Defend al hostului, din telemetria ultimei zile."""
    try:
        r = es.search(index="logs-endpoint.events.process-*", size=0, query={"bool": {"filter": [
            {"term": {"host.name": host}}, {"range": {"@timestamp": {"gte": "now-1d"}}}]}},
            aggs={"a": {"terms": {"field": "agent.id", "size": 2}}})
        b = r["aggregations"]["a"]["buckets"]
        return b[0]["key"] if len(b) == 1 else None      # doi agenti pe acelasi nume: ambiguu
    except Exception:
        return None

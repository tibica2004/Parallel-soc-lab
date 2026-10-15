"""
TIER 3 — SCRIEREA REGULILOR IN KIBANA. Implicit dry-run.

Doua bariere, independente:
  1. Kibana: cheia KIBANA_TIER3_API_KEY are drepturi DOAR in spatiul `tier3`
     (rolul soc_tier3_rules). Regulile omului stau in spatiul implicit, deci
     cheia nu le poate atinge, oricat ar gresi codul.
  2. Codul: orice regula atinsa trebuie sa aiba rule_id `t3-...` SI eticheta
     tier3-generated; altfel operatia e refuzata inainte de cerere.

Operatii permise: creare, oprire, promovare (scoate tier3-shadow, ridica
severitatea). Nimic altceva: fara exceptii, fara stergeri, fara reguli straine.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import rules as R

KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601")
SPACE = os.environ.get("KIBANA_TIER3_SPACE", "tier3")
RULES_API = "/api/detection_engine/rules"
PAYLOAD_KEYS = {"rule_id", "type", "language", "query", "index", "name", "description", "severity",
                "risk_score", "tags", "enabled", "interval", "from", "max_signals"}


class NotOwnRule(Exception):
    """Regula nu e generata de Tier 3: refuzata inainte de orice cerere."""


def is_own(rule: dict) -> bool:
    return (isinstance(rule.get("rule_id"), str) and rule["rule_id"].startswith("t3-")
            and R.TAG in (rule.get("tags") or []))


def check_payload(p: dict) -> None:
    """Corpul de creare: doar cheile cunoscute (deci niciun exceptions_list),
    regula proprie, in shadow."""
    extra = set(p) - PAYLOAD_KEYS
    if extra:
        raise NotOwnRule(f"chei nepermise in payload: {sorted(extra)}")
    if not is_own(p):
        raise NotOwnRule(f"payload fara t3- / {R.TAG}: {p.get('rule_id')!r}")
    if R.SHADOW_TAG not in p["tags"]:
        raise NotOwnRule("o regula noua intra doar in shadow")


def promotion_patch(rule: dict) -> dict:
    if not is_own(rule):
        raise NotOwnRule(rule.get("rule_id"))
    return {"rule_id": rule["rule_id"], "severity": "medium", "risk_score": 47,
            "tags": [t for t in rule["tags"] if t != R.SHADOW_TAG]}


def disable_patch(rule: dict) -> dict:
    if not is_own(rule):
        raise NotOwnRule(rule.get("rule_id"))
    return {"rule_id": rule["rule_id"], "enabled": False}


def status_of(rule: dict) -> R.RuleStatus:
    if not rule.get("enabled"):
        return R.RuleStatus.DISABLED
    return R.RuleStatus.SHADOW if R.SHADOW_TAG in (rule.get("tags") or []) else R.RuleStatus.PROMOTED


@dataclass
class Kibana:
    """Client minimal. dry_run=True: nu trimite nimic, doar inregistreaza ce ar face."""
    dry_run: bool = True
    calls: list = field(default_factory=list)

    def _req(self, method: str, path: str, **kw):
        url = f"{KIBANA_URL}/s/{SPACE}{path}"
        self.calls.append((method, url, kw.get("json")))
        if self.dry_run:
            return None
        import requests
        key = os.environ.get("KIBANA_TIER3_API_KEY")
        if not key:
            raise RuntimeError("KIBANA_TIER3_API_KEY lipseste")
        r = requests.request(method, url, timeout=30, headers={
            "Authorization": f"ApiKey {key}", "kbn-xsrf": "soc-tier3",
            "elastic-api-version": "2023-10-31"}, **kw)
        r.raise_for_status()
        return r.json()

    def find_own(self) -> list[dict]:
        if self.dry_run and not os.environ.get("KIBANA_TIER3_API_KEY"):
            return []
        import requests
        r = requests.get(f"{KIBANA_URL}/s/{SPACE}{RULES_API}/_find", timeout=30,
                         params={"filter": f'alert.attributes.tags:"{R.TAG}"', "per_page": 500},
                         headers={"Authorization": f"ApiKey {os.environ['KIBANA_TIER3_API_KEY']}",
                                  "elastic-api-version": "2023-10-31"})
        r.raise_for_status()
        # filtrul Kibana e doar o optimizare; decide is_own
        return [x for x in r.json().get("data", []) if is_own(x)]

    def create(self, payload: dict):
        check_payload(payload)
        return self._req("POST", RULES_API, json=payload)

    def promote(self, rule: dict):
        return self._req("PATCH", RULES_API, json=promotion_patch(rule))

    def disable(self, rule: dict):
        return self._req("PATCH", RULES_API, json=disable_patch(rule))


# ------------------------------------------------------------------------------
# Numaratorile pentru next_status (doar citire, cheia read-only)
# ------------------------------------------------------------------------------

def shadow_stats(es, rule: dict, now: datetime) -> R.ShadowStats:
    rid = rule["rule_id"]
    created = R._ts(rule.get("created_at") or now.isoformat())
    by_rule = {"term": {"kibana.alert.rule.rule_id": rid}}
    hour = es.count(index=R.ALERTS_IDX, query={"bool": {"filter": [
        by_rule, {"range": {"@timestamp": {"gte": (now - timedelta(hours=1)).isoformat()}}}]}})["count"]
    total = es.count(index=R.ALERTS_IDX, query={"bool": {"filter": [
        by_rule, {"range": {"@timestamp": {"gte": created.isoformat()}}}]}})["count"]
    fp = es.count(index=R.VERDICTS_IDX, query={"bool": {"filter": [
        {"term": {"rule_name.keyword": rule.get("name", "")}},
        {"term": {"label_source.keyword": "human"}},
        {"term": {"ground_truth.keyword": "benign"}}]}})["count"]
    return R.ShadowStats(alerts_last_hour=hour, alerts_total=total,
                         days_in_status=(now - created).total_seconds() / 86400, human_fp=fp)


def lifecycle(es, kb: Kibana, now: datetime | None = None, kill_switch: bool = False) -> list[dict]:
    """Un ciclu: pentru fiecare regula proprie, next_status -> promovare / oprire."""
    now = now or datetime.now(timezone.utc)
    out = []
    for rule in kb.find_own():
        cur = status_of(rule)
        stats = shadow_stats(es, rule, now)
        new, why = R.next_status(cur, stats, kill_switch=kill_switch)
        if new is not cur:
            (kb.promote if new is R.RuleStatus.PROMOTED else kb.disable)(rule)
        out.append({"rule_id": rule["rule_id"], "from": cur.value, "to": new.value, "reason": why,
                    "stats": stats.__dict__})
    return out

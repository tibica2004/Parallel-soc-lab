"""Alerte sintetice pentru testele de intrare si de incarcare (faza 26; refolosit la replay).

Nicio data din afara laboratorului: documentele au forma alertelor din
`.alerts-security.alerts-*` (campurile pe care le citeste intrarea), cu valori inventate.
Determinist pentru aceeasi samanta. Pur (fara retea).
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone

from elasticlab.core import honeytokens

RULES = ("Web server spawns shell", "Suspicious curl from web user", "New listening port",
         "SSH brute force", "WordPress plugin enumeration")
HOSTS = ("web-prod",)


def _iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def alert(t: datetime, *, rule: str, host: str = "web-prod", entity: str | None = None,
          source_ip: str | None = None, severity: str = "medium", rule_id: str | None = None,
          native: bool = False, idx: int = 0, rng: random.Random | None = None) -> dict:
    """Un document de alerta, cu `_soc_ref` ca dupa citire."""
    rng = rng or random.Random(idx)
    au = str(uuid.UUID(int=rng.getrandbits(128)))
    a = {
        "@timestamp": _iso(t), "kibana.alert.original_time": _iso(t - timedelta(seconds=2)),
        "kibana.alert.uuid": au, "kibana.alert.rule.name": rule,
        "kibana.alert.rule.rule_id": rule_id or f"soc-synth-{RULES.index(rule) if rule in RULES else 0}",
        "kibana.alert.severity": severity, "kibana.alert.workflow_status": "open",
        "host": {"name": host},
        "_soc_ref": {"index": ".internal.alerts-security.alerts-default-000001", "id": au},
    }
    if entity:
        a["process"] = {"entity_id": entity}
    if source_ip:
        a["source"] = {"ip": source_ip}
    if native:
        a["event"] = {"dataset": "endpoint.alerts"}
    return a


def burst(n: int = 10_000, dup_ratio: float = 0.9, *, minutes: float = 5.0, seed: int = 26,
          start: datetime | None = None, criticals: int = 0,
          sources: int = 50) -> list[dict]:
    """O rafala de `n` alerte in `minutes` minute, cu `dup_ratio` duplicate (aceeasi cheie de
    deduplicare ca un caz anterior). Cazurile distincte se impart pe RULES si pe `sources` IP-uri
    sursa (nu toate de la acelasi IP, ca rafala sa nu fie un singur potop). `criticals` alerte de
    momeala presarate, fiecare caz distinct. Cele mai vechi intai."""
    rng = random.Random(seed)
    start = start or datetime(2026, 11, 24, 10, 0, tzinfo=timezone.utc)
    distinct = max(1, round(n * (1 - dup_ratio)))
    cases = []
    for i in range(distinct):
        rule = RULES[i % len(RULES)]
        cases.append({"rule": rule, "entity": f"synth-{seed}-{i}",
                      "source_ip": f"10.10.{(i % sources) // 250}.{(i % sources) % 250 + 1}"})
    ht_rule = next(iter(honeytokens.RULES))
    out = []
    span = minutes * 60
    for j in range(n):
        t = start + timedelta(seconds=span * j / max(1, n))
        c = cases[j] if j < distinct else cases[rng.randrange(distinct)]
        out.append(alert(t, rule=c["rule"], entity=c["entity"], source_ip=c["source_ip"],
                         idx=j, rng=rng))
    for k in range(criticals):
        t = start + timedelta(seconds=span * (k + 0.5) / max(1, criticals))
        out.append(alert(t, rule="Honeytoken atins", rule_id=ht_rule, severity="critical",
                         source_ip=f"10.10.9.{k % 250 + 1}", entity=f"ht-{seed}-{k}",
                         idx=n + k, rng=rng))
    out.sort(key=lambda a: (a["@timestamp"], a["kibana.alert.uuid"]))
    return out


class FakeAlertsES:
    """Elasticsearch fals pentru `intake.adapter.read_window`: sorteaza dupa (@timestamp,
    kibana.alert.uuid) si pagineaza cu search_after. Filtrul de timp: [gte, lte]. Inregistreaza
    apelurile (cate pagini, ce marimi)."""

    def __init__(self, alerts: list[dict]):
        self.docs = sorted(alerts, key=lambda a: (a["@timestamp"], a.get("kibana.alert.uuid", "")))
        self.calls: list[dict] = []

    def search(self, *, index, size, sort, query, search_after=None, **_):
        self.calls.append({"size": size, "search_after": search_after})
        rng = query["bool"]["filter"][0]["range"]["@timestamp"]
        lo, hi = rng["gte"], rng["lte"]
        from elasticlab.core.eventtime import parse
        lo_t, hi_t = parse(lo), parse(hi)
        hits = []
        for a in self.docs:
            t = parse(a["@timestamp"])
            if not (lo_t <= t <= hi_t):
                continue
            sv = [a["@timestamp"], a.get("kibana.alert.uuid", "")]
            if search_after is not None and sv <= list(search_after):
                continue
            src = {k: v for k, v in a.items() if k != "_soc_ref"}
            ref = a.get("_soc_ref") or {}
            hits.append({"_index": ref.get("index", "idx"), "_id": ref.get("id", sv[1]),
                         "_source": src, "sort": sv})
            if len(hits) >= size:
                break
        return {"hits": {"hits": hits}}

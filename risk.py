"""
SCOR DE RISC PE ENTITATE, IN TIMP (plann.md A3) — tiparele lente pe care un singur eveniment
nu le arata: recon low-and-slow, aceeasi sursa care tot apare pe reguli diferite, un cont care
aduna alerte mici. Determinist, fara model.

Scorul unei entitati (IP sursa sau utilizator) = suma ponderata a alertelor din ultimele
WINDOW_H ore, cu decadere exponentiala (timp de injumatatire HALF_LIFE_H): ponderi pe severitate
(low 1, medium 2, high 4, critical 8), x2 pentru momeli/comportament. Peste PRAG, o data la
COOLDOWN_H per entitate -> RarityFinding kind=entity_risk, judecat de Tier 2 cu motivele si
dovezile (ID-urile alertelor). IP-urile proprii si benign-gen (WP_SELF_IPS, BENIGN_GEN_IPS) sunt
excluse din cod; www-data e exclus ca utilizator (alertele lui sunt deja directe).

Rulat de orchestrator in sweep-ul orar (elastic_tools.run_full_sweep). Starea (ultima emitere
per entitate) in data/risk-state.json.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from schemas import EntityType, EvidenceRef, RarityFinding

ROOT = Path(__file__).resolve().parent
STATE = Path(os.environ.get("RISK_STATE", str(ROOT / "data" / "risk-state.json")))
WINDOW_H = 24
HALF_LIFE_H = 6.0
THRESHOLD = float(os.environ.get("RISK_THRESHOLD", "20"))
COOLDOWN_H = 6
MAX_FINDINGS = 10
WEIGHT = {"low": 1.0, "medium": 2.0, "high": 4.0, "critical": 8.0}
BOOST_TAGS = ("soc-honeytoken", "soc-behavioral")
EXCLUDED_USERS = frozenset({"www-data", "root"})     # root: zgomot de administrare, deja judecat per alerta
ALERTS = ".alerts-security.alerts-*"


def excluded_ips() -> frozenset[str]:
    out = set()
    for var, default in (("WP_SELF_IPS", "192.168.10.138,127.0.0.1"), ("BENIGN_GEN_IPS", "192.168.10.150")):
        for x in os.environ.get(var, default).replace(" ", "").split(","):
            try:
                out.add(str(ipaddress.ip_address(x)))
            except ValueError:
                pass
    return frozenset(out)


def _ts(v) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def weight(severity: str | None, tags: list[str] | None) -> float:
    w = WEIGHT.get((severity or "").lower(), 1.0)
    return w * 2 if any(t in BOOST_TAGS for t in (tags or [])) else w


def score_entities(events: list[dict], now: datetime, skip_ips: frozenset[str] = frozenset()) -> dict:
    """events: {ts, severity, tags, rule, source_ip, user, doc_id, index}.
    -> {(tip, valoare): {score, events, rules, refs}} cu decadere exponentiala. Pur."""
    out: dict[tuple[str, str], dict] = {}
    for e in events:
        t = _ts(e.get("ts"))
        if t is None:
            continue
        age_h = max(0.0, (now - t).total_seconds() / 3600)
        if age_h > WINDOW_H:
            continue
        w = weight(e.get("severity"), e.get("tags")) * math.pow(0.5, age_h / HALF_LIFE_H)
        keys = []
        ip = e.get("source_ip")
        if ip and str(ip) not in skip_ips:
            keys.append((EntityType.SOURCE_IP.value, str(ip)))
        u = e.get("user")
        if isinstance(u, str) and u and u not in EXCLUDED_USERS:
            keys.append((EntityType.USER.value, u))
        for k in keys:
            d = out.setdefault(k, {"score": 0.0, "events": 0, "rules": {}, "refs": []})
            d["score"] += w
            d["events"] += 1
            if e.get("rule"):
                d["rules"][e["rule"]] = d["rules"].get(e["rule"], 0) + 1
            if e.get("doc_id") and e.get("index") and len(d["refs"]) < 50:
                d["refs"].append((e["index"], e["doc_id"], t))
    for d in out.values():
        d["score"] = round(d["score"], 2)
    return out


def due(state: dict, key: str, now: datetime, cooldown_h: float = COOLDOWN_H) -> bool:
    last = _ts(state.get(key))
    return last is None or (now - last) >= timedelta(hours=cooldown_h)


def to_finding(kind_type: str, value: str, d: dict) -> RarityFinding:
    top = sorted(d["rules"].items(), key=lambda kv: -kv[1])[:5]
    return RarityFinding(
        kind="entity_risk",
        entity_type=EntityType(kind_type), entity_id=value[:128],
        detail={"entity_type": kind_type, "entity": value[:128], "score": d["score"],
                "threshold": THRESHOLD, "events_24h": d["events"],
                "top_rules": [{"rule": r[:120], "count": n} for r, n in top]},
        rarity_score=min(1.0, d["score"] / (2 * THRESHOLD)),
        evidence_refs=[EvidenceRef(index=i, doc_id=did, timestamp=t) for i, did, t in d["refs"]])


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except Exception:  # noqa: BLE001
        return {}


def save_state(st: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(st))
    tmp.replace(STATE)


def fetch_events(es, now: datetime, host: str = "web-prod") -> list[dict]:
    r = es.search(index=ALERTS, size=2000, sort=[{"@timestamp": "desc"}],
                  query={"bool": {"filter": [{"term": {"host.name": host}},
                                             {"range": {"@timestamp": {"gte": (now - timedelta(hours=WINDOW_H)).isoformat()}}}]}},
                  source=["@timestamp", "kibana.alert.severity", "kibana.alert.rule.tags",
                          "kibana.alert.rule.name", "source.ip", "user.name"])
    out = []
    for h in r["hits"]["hits"]:
        s = h["_source"]
        g = lambda k: s.get(k) if k in s else _nested(s, k)  # noqa: E731
        out.append({"ts": g("@timestamp"), "severity": g("kibana.alert.severity"),
                    "tags": g("kibana.alert.rule.tags") or [], "rule": g("kibana.alert.rule.name"),
                    "source_ip": g("source.ip"), "user": g("user.name"),
                    "doc_id": h["_id"], "index": h["_index"]})
    return out


def _nested(d: dict, dotted: str):
    cur = d
    for p in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def sweep_entity_risk(window_hours: int = 1, es=None) -> list[RarityFinding]:
    """Sweep orar: entitatile peste prag, nemaiemise in ultimele COOLDOWN_H ore."""
    if es is None:
        from elastic_tools import ES as es  # noqa: N811
    now = datetime.now(timezone.utc)
    scores = score_entities(fetch_events(es, now), now, excluded_ips())
    state = load_state()
    findings = []
    for (kt, val), d in sorted(scores.items(), key=lambda kv: -kv[1]["score"]):
        if d["score"] < THRESHOLD:
            break
        key = f"{kt}:{val}"
        if not due(state, key, now):
            continue
        findings.append(to_finding(kt, val, d))
        state[key] = now.isoformat()
        if len(findings) >= MAX_FINDINGS:
            break
    if findings:
        save_state(state)
    return findings

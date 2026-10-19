"""
ANOMALII STATISTICE SIMPLE, in Python (faza 12). Fara joburi ML Elastic (cer
licenta platita; clusterul e pe Basic). Ies ca RarityFinding si merg pe calea
lenta, ca orice alt finding de sweep: statistica detecteaza, modelul judeca.

  beaconing   — conexiuni repetate de la acelasi proces catre aceeasi destinatie
                la intervale aproape egale (C2 care "suna acasa"). Coeficientul
                de variatie al intervalelor e mic.
  dns_anomaly — nume DNS cu subdomeniu lung si entropie mare (DGA, date codate in
                DNS) sau multe subdomenii unice sub acelasi domeniu (tunel DNS).

Functiile de calcul sunt pure (testate fara Elasticsearch). Interogarile folosesc
doar filtre term/range; valorile din telemetrie nu intra in textul interogarii.
Numele de domeniu le alege atacatorul: ajung la model ca DATE (hunt_path).
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime

from schemas import EntityType, RarityFinding

NET_IDX = "logs-endpoint.events.network-*"

# Beaconing
BEACON_WINDOW_H = 6
BEACON_MIN_EVENTS = 6          # cel putin 5 intervale
BEACON_MAX_CV = 0.25           # abaterea standard / media intervalelor
BEACON_MIN_INTERVAL_S = 10     # sub atat e o rafala, nu un beacon
BEACON_MAX_INTERVAL_S = 3600
BEACON_MERGE_S = 1.0           # evenimente la mai putin de 1 s = aceeasi conexiune

# DNS
DNS_MIN_SUB_LEN = 20           # lungimea celei mai lungi etichete din subdomeniu
DNS_MIN_ENTROPY = 3.5
DNS_MANY_SUBDOMAINS = 30
DNS_IGNORE_SUFFIXES = (".arpa", ".local", ".localdomain", ".internal")
MAX_NAME = 120


# ------------------------------------------------------------------------------
# Functii pure
# ------------------------------------------------------------------------------

def _ts(x) -> float:
    if isinstance(x, (int, float)):
        return float(x)
    return datetime.fromisoformat(str(x).replace("Z", "+00:00")).timestamp()


def beacon_stats(times) -> dict | None:
    """Statistica intervalelor; None daca nu sunt destule conexiuni distincte."""
    ts = sorted(_ts(t) for t in times)
    merged: list[float] = []
    for t in ts:
        if not merged or t - merged[-1] >= BEACON_MERGE_S:
            merged.append(t)
    if len(merged) < BEACON_MIN_EVENTS:
        return None
    iv = [b - a for a, b in zip(merged, merged[1:])]
    mean = statistics.fmean(iv)
    cv = statistics.pstdev(iv) / mean if mean > 0 else math.inf
    return {"connections": len(merged), "mean_interval_s": round(mean, 1), "cv": round(cv, 3)}


def is_beacon(st: dict | None) -> bool:
    return (st is not None and st["cv"] <= BEACON_MAX_CV
            and BEACON_MIN_INTERVAL_S <= st["mean_interval_s"] <= BEACON_MAX_INTERVAL_S)


def entropy(s: str) -> float:
    """Entropia Shannon pe caracter, in biti."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def split_domain(name: str) -> tuple[str, str]:
    """(subdomeniu, domeniu de baza). Aproximare: ultimele doua etichete sunt
    domeniul (fara lista de sufixe publice; suficient pentru semnal)."""
    labels = [x for x in name.lower().rstrip(".").split(".") if x]
    if len(labels) <= 2:
        return "", ".".join(labels)
    return ".".join(labels[:-2]), ".".join(labels[-2:])


def _search_expansion(name: str, names: set[str]) -> bool:
    """Resolverul reincearca un nume cu domeniul de cautare adaugat (x.example.org
    -> x.example.org.tuiasi.ro). Varianta lunga nu e o cerere noua, ci aceeasi."""
    labels = name.split(".")
    return any(".".join(labels[:i]) in names for i in range(2, len(labels)))


def dns_anomalies(lookups: list[dict]) -> list[dict]:
    """lookups: {host, process, name}. Intoarce anomaliile, una per (host, proces, domeniu)."""
    out: dict[tuple, dict] = {}
    subs: dict[tuple, set] = defaultdict(set)
    names = {(q.get("name") or "").lower().rstrip(".") for q in lookups}
    for q in lookups:
        name = (q.get("name") or "").lower().rstrip(".")
        if not name or name.endswith(DNS_IGNORE_SUFFIXES) or _search_expansion(name, names):
            continue
        sub, base = split_domain(name)
        key = (q.get("host"), q.get("process"), base)
        if sub:
            subs[key].add(sub)
        # O singura eticheta lunga si aleatoare (DGA, base32/hex in tunel), nu
        # etichetele lipite: "dualstack.p2.shared.global" are entropie mare
        # adunata, dar fiecare eticheta e un cuvant.
        flat = max(sub.split("."), key=len) if sub else ""
        e = entropy(flat)
        if len(flat) >= DNS_MIN_SUB_LEN and e >= DNS_MIN_ENTROPY:
            prev = out.get(key)
            if prev is None or e > prev["entropy"]:
                out[key] = {"host": key[0], "process": key[1], "domain": base[:MAX_NAME],
                            "reason": "high_entropy", "example": name[:MAX_NAME],
                            "entropy": round(e, 2), "label_length": len(flat)}
    for key, s in subs.items():
        if len(s) >= DNS_MANY_SUBDOMAINS:
            d = out.setdefault(key, {"host": key[0], "process": key[1], "domain": key[2][:MAX_NAME],
                                     "reason": "many_subdomains", "example": None})
            d["unique_subdomains"] = len(s)
            if d["reason"] != "many_subdomains":
                d["reason"] = "high_entropy+many_subdomains"
    return list(out.values())


# ------------------------------------------------------------------------------
# I/O
# ------------------------------------------------------------------------------

def _hits(es, query: dict, fields: list[str], size: int = 5000) -> list[dict]:
    r = es.search(index=NET_IDX, size=size, query=query, source=fields, sort=[{"@timestamp": "asc"}])
    return [h["_source"] for h in r["hits"]["hits"]]


def _g(d: dict, path: str):
    for k in path.split("."):
        d = d.get(k) if isinstance(d, dict) else None
    return d


def sweep_beaconing(window_hours: int = 1, es=None) -> list[RarityFinding]:
    from elastic_tools import ES, _ip_score
    es = es or ES
    hours = max(int(window_hours), BEACON_WINDOW_H)
    rows = _hits(es, {"bool": {"filter": [
        {"term": {"network.direction": "egress"}},
        {"term": {"event.action": "connection_attempted"}},
        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}]}},
        ["@timestamp", "host.name", "process.name", "destination.ip", "destination.port"])
    groups: dict[tuple, list] = defaultdict(list)
    for r in rows:
        k = (_g(r, "host.name"), _g(r, "process.name"), _g(r, "destination.ip"))
        if all(k):
            groups[k].append(r["@timestamp"])
    out = []
    for (host, proc, ip), times in groups.items():
        st = beacon_stats(times)
        if is_beacon(st):
            out.append(RarityFinding(
                kind="beaconing", entity_type=EntityType.HOST, entity_id=host,
                detail={"process": proc, "destination_ip": str(ip), **st, "window_hours": hours},
                rarity_score=_ip_score(str(ip))))
    return out


def sweep_dns(window_hours: int = 1, es=None) -> list[RarityFinding]:
    from elastic_tools import ES
    es = es or ES
    rows = _hits(es, {"bool": {"filter": [
        {"exists": {"field": "dns.question.name"}},
        {"range": {"@timestamp": {"gte": f"now-{int(window_hours)}h"}}}]}},
        ["host.name", "process.name", "dns.question.name"])
    found = dns_anomalies([{"host": _g(r, "host.name"), "process": _g(r, "process.name"),
                            "name": _g(r, "dns.question.name")} for r in rows])
    return [RarityFinding(
        kind="dns_anomaly", entity_type=EntityType.HOST, entity_id=d["host"],
        detail={k: v for k, v in d.items() if k != "host"},
        rarity_score=0.9 if "high_entropy" in d["reason"] else 0.8)
        for d in found if d["host"]]

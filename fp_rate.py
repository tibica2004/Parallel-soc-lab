#!/usr/bin/env python3
"""
RATA DE FALS POZITIVE PER REGULA (pasul 4.5) — pe adevarul cunoscut al traficului benign.

Fereastra: ultimele FP_HOURS ore (implicit 6). O alerta se atribuie traficului benign daca:
  benign_ip    — source.ip in BENIGN_GEN_IPS (VM-ul benign-gen);
  benign_ua    — user_agent.original contine "soc-benign";
  benign_time  — alerta FARA source.ip (de host: endpoint, auditd, AIDE) in
                 [start-5 s, end+5 s] al unei actiuni benign-gen inregistrate;
  benign_update — alerta fara source.ip in [start-1 min, +10 min] al unei actiuni din
                 benign-actions (wp_update, hardening) de pe web-prod.
Atribuirea pe timp e o MASURATOARE, nu un verdict: un atac real in aceeasi secunda ar fi numarat
FP aici. De aceea motivul se pastreaza separat, iar nimic din fp_rate nu inchide/ignora alerte.

Iesire: soc-metrics type=fp_rate, un document per regula, plus data/fp_report.txt (descrescator).
Regulile cu fp_rate > FP_RECALIBRATE (0.05) sunt LISTATE pentru recalibrarea listei albe, NU
dezactivate (4.7).

Chei: ES_FP_READER_API_KEY (citeste alerte, benign-ground-truth, logs-soc.benign_actions-*),
ES_METRICS_WRITER_API_KEY. Mediu: BENIGN_GEN_IPS.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s",
                    stream=sys.stderr)
log = logging.getLogger("soc.fp_rate")

ROOT = Path(__file__).resolve().parent
ALERTS = ".alerts-security.alerts-*"
GT_INDEX = "benign-ground-truth"
ACTIONS_INDEX = "logs-soc.benign_actions-*"
METRICS_INDEX = "soc-metrics"
REPORT = Path(os.environ.get("FP_REPORT", str(ROOT / "data" / "fp_report.txt")))
FP_RECALIBRATE = 0.05
TIME_PAD = timedelta(seconds=5)
UPDATE_BEFORE, UPDATE_AFTER = timedelta(minutes=1), timedelta(minutes=10)
PAGE = 2000


# =============================================================================
# FUNCTII PURE
# =============================================================================

def parse_ts(v) -> datetime | None:
    if not isinstance(v, str):
        return None
    try:
        t = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def ip_set(raw: str) -> frozenset[str]:
    out = set()
    for p in (raw or "").replace(",", " ").split():
        try:
            out.add(str(ipaddress.ip_address(p)))
        except ValueError:
            log.warning("IP invalid in BENIGN_GEN_IPS: %r", p)
    return frozenset(out)


def _g(d: dict, dotted: str):
    if dotted in d:
        return d[dotted]
    cur = d
    for k in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _first(v):
    return v[0] if isinstance(v, list) and v else v


def gen_windows(gt_docs: list[dict]) -> list[tuple[datetime, datetime]]:
    """Ferestrele actiunilor benign-gen: start..end pe action_id, largite cu TIME_PAD.
    O actiune fara 'end' (generator cazut) primeste 60 s."""
    starts, ends = {}, {}
    for d in gt_docs:
        t = parse_ts(d.get("@timestamp"))
        aid = d.get("action_id")
        if t is None or not aid:
            continue
        (starts if d.get("phase") == "start" else ends)[aid] = t
    out = []
    for aid, s in starts.items():
        e = ends.get(aid, s + timedelta(seconds=60))
        out.append((s - TIME_PAD, max(e, s) + TIME_PAD))
    return sorted(out)


def update_windows(actions: list[dict]) -> list[tuple[datetime, datetime]]:
    out = []
    for d in actions:
        t = parse_ts(d.get("@timestamp") or d.get("ts"))
        if t is not None:
            out.append((t - UPDATE_BEFORE, t + UPDATE_AFTER))
    return sorted(out)


def _inside(t: datetime, wins: list[tuple[datetime, datetime]]) -> bool:
    return any(a <= t <= b for a, b in wins)


def attribute(alert: dict, benign_ips: frozenset[str], gen_wins, upd_wins) -> str | None:
    """Motivul pentru care alerta e atribuita traficului benign, sau None."""
    ip = _first(_g(alert, "source.ip"))
    if ip and str(ip) in benign_ips:
        return "benign_ip"
    ua = _first(_g(alert, "user_agent.original"))
    if isinstance(ua, str) and "soc-benign" in ua:
        return "benign_ua"
    if ip:
        return None          # cerere de retea de la alt client: nu se atribuie dupa timp
    t = parse_ts(_g(alert, "@timestamp"))
    if t is None:
        return None
    if _inside(t, gen_wins):
        return "benign_time"
    if _inside(t, upd_wins):
        return "benign_update"
    return None


def per_rule(alerts: list[dict], benign_ips, gen_wins, upd_wins) -> dict[str, dict]:
    rules: dict[str, dict] = defaultdict(lambda: {"total": 0, "fp_count": 0, "by_reason": {}})
    for a in alerts:
        name = _first(_g(a, "kibana.alert.rule.name")) or "(fara nume)"
        r = rules[name]
        r["total"] += 1
        why = attribute(a, benign_ips, gen_wins, upd_wins)
        if why:
            r["fp_count"] += 1
            r["by_reason"][why] = r["by_reason"].get(why, 0) + 1
    for r in rules.values():
        r["fp_rate"] = round(r["fp_count"] / r["total"], 4) if r["total"] else 0.0
        r["recalibrate"] = r["fp_rate"] > FP_RECALIBRATE
    return dict(rules)


def propose_whitelist(rules: dict[str, dict], alerts: list[dict], benign_ips, gen_wins, upd_wins,
                      min_fp: int = 3) -> list[dict]:
    """plann.md A6: pentru regulile peste prag, CE anume ar intra in lista alba, dedus din alertele
    atribuite traficului benign dovedit. Doar PROPUNERE (omul aproba in build_whitelists /
    reguli); nimic nu se aplica. Pur.
      - reguli de retea (benign_ip / benign_ua): excluderea IP-urilor benign-gen din regula;
      - reguli de host (benign_time / benign_update): executabilele vazute in alertele atribuite."""
    by_rule: dict[str, dict] = {}
    for a in alerts:
        name = _first(_g(a, "kibana.alert.rule.name")) or "(fara nume)"
        r = rules.get(name)
        if not r or not r["recalibrate"]:
            continue
        why = attribute(a, benign_ips, gen_wins, upd_wins)
        if not why:
            continue
        d = by_rule.setdefault(name, {"rule_name": name, "fp_rate": r["fp_rate"], "fp_count": r["fp_count"],
                                      "total": r["total"], "kind": None, "values": {}})
        if why in ("benign_ip", "benign_ua"):
            d["kind"] = "exclude_source_ips"
            v = str(_first(_g(a, "source.ip")) or "")
        else:
            d["kind"] = "whitelist_executables"
            v = str(_first(_g(a, "process.executable")) or _first(_g(a, "process.name")) or "")
        if v:
            d["values"][v] = d["values"].get(v, 0) + 1
    out = []
    for d in by_rule.values():
        vals = sorted(((v, n) for v, n in d["values"].items() if n >= min_fp), key=lambda x: -x[1])[:10]
        if vals:
            out.append({**d, "values": [{"value": v, "fp_count": n} for v, n in vals],
                        "status": "proposed", "requires_human_approval": True})
    return out


def report_text(rules: dict[str, dict], start: datetime, end: datetime, gen_actions: int) -> str:
    lines = [f"Rata FP per regula, {start:%Y-%m-%d %H:%M} - {end:%Y-%m-%d %H:%M} UTC; "
             f"actiuni benign-gen in fereastra: {gen_actions}",
             f"{'fp_rate':>8} {'fp':>5} {'total':>6}  regula  [motive]"]
    for name, r in sorted(rules.items(), key=lambda kv: (-kv[1]["fp_rate"], -kv[1]["total"])):
        flag = "  <- de recalibrat (lista alba), NU dezactivat" if r["recalibrate"] else ""
        lines.append(f"{r['fp_rate']:8.3f} {r['fp_count']:5d} {r['total']:6d}  {name}  "
                     f"{json.dumps(r['by_reason'], ensure_ascii=False)}{flag}")
    return "\n".join(lines) + "\n"


# =============================================================================
# EFECTE
# =============================================================================

def _client(key_env: str):
    from elasticsearch import Elasticsearch
    key = os.environ.get(key_env)
    if not key:
        raise RuntimeError(f"lipseste cheia {key_env}")
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                         api_key=key, request_timeout=60)


def fetch_all(es, index: str, start: datetime, end: datetime, fields: list[str],
              extra_filter: list[dict] | None = None) -> list[dict]:
    q = {"bool": {"filter": [{"range": {"@timestamp": {"gte": start.isoformat(),
                                                       "lte": end.isoformat()}}},
                             *(extra_filter or [])]}}
    out, after = [], None
    while True:
        body = {"size": PAGE, "query": q, "_source": fields,
                "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}]}
        if after:
            body["search_after"] = after
        hits = es.search(index=index, body=body, ignore_unavailable=True)["hits"]["hits"]
        out += [h["_source"] for h in hits]
        if len(hits) < PAGE:
            return out
        after = hits[-1]["sort"]


def run(hours: float) -> int:
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    es = _client("ES_FP_READER_API_KEY")
    es_met = _client("ES_METRICS_WRITER_API_KEY")
    benign_ips = ip_set(os.environ.get("BENIGN_GEN_IPS", ""))
    if not benign_ips:
        raise RuntimeError("BENIGN_GEN_IPS gol")

    alerts = fetch_all(es, ALERTS, start, end, ["@timestamp", "kibana.alert.rule.name",
                                                "source.ip", "user_agent.original", "host.name",
                                                "process.executable", "process.name"])
    gt = fetch_all(es, GT_INDEX, start - timedelta(minutes=5), end,
                   ["@timestamp", "action_id", "phase"])
    acts = fetch_all(es, ACTIONS_INDEX, start - UPDATE_AFTER, end, ["@timestamp", "ts", "action"])
    gen_w, upd_w = gen_windows(gt), update_windows(acts)
    rules = per_rule(alerts, benign_ips, gen_w, upd_w)
    n_gen = sum(1 for d in gt if d.get("phase") == "start")

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(report_text(rules, start, end, n_gen))
    for name, r in rules.items():
        es_met.index(index=METRICS_INDEX, document={
            "@timestamp": end.isoformat(), "type": "fp_rate", "rule_name": name,
            "fp_count": r["fp_count"], "total": r["total"], "fp_rate": r["fp_rate"],
            "by_reason": r["by_reason"], "recalibrate": r["recalibrate"],
            "window_start": start.isoformat(), "window_end": end.isoformat(),
            "benign_actions": n_gen})
    proposals = propose_whitelist(rules, alerts, benign_ips, gen_w, upd_w)
    (REPORT.parent / "whitelist-proposals.json").write_text(json.dumps(proposals, indent=1, ensure_ascii=False))
    for p in proposals:
        es_met.index(index=METRICS_INDEX, document={"@timestamp": end.isoformat(), "type": "whitelist_proposal", **p})
    if proposals:
        log.info("%d propuneri de lista alba (doar propuneri; aprobarea e a omului)", len(proposals))
    log.info("%d alerte, %d reguli, %d actiuni benign-gen, %d reguli de recalibrat -> %s",
             len(alerts), len(rules), n_gen, sum(r["recalibrate"] for r in rules.values()), REPORT)
    if n_gen == 0:
        log.warning("nicio actiune benign-gen in fereastra: generatorul merge?")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=float(os.environ.get("FP_HOURS", "6")))
    args = ap.parse_args(argv)
    try:
        return run(args.hours)
    except Exception as e:  # noqa: BLE001
        log.exception("fp_rate a esuat: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())

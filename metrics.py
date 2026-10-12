#!/usr/bin/env python3
"""
METRICI — calculate din audit, urme si etichete, IN AFARA grafului.

Ce masuram, pe o fereastra de timp, per nivel (fast = Tier 1, hunt = calea lenta
si Tier 2) si pe total:
  - volum, rata de escaladare Tier 1 -> Tier 2, motivele, bugetul Tier 2
  - esecuri (model cazut, timeout, eroare) si cazuri fara verdict de model
  - latenta per caz (p50, p95) din started_at / finished_at
  - tokeni si apeluri de unelte, din soc-traces
  - coroborarea pe calea lenta: acord / dezacord A-B, B indisponibil
  - pe etichete UMANE (label_source=human): TP/FP/FN/TN, precizie, recall,
    rata de atacuri ratate
  - drift fata de fereastra anterioara: rata de escaladare si distributia
    clasificarilor (distanta de variatie totala, 0..1)

compute() e functie pura (testabila fara Elasticsearch). Rezultatul e o lista de
documente plate, cate unul per nivel, scrise in soc-metrics: Kibana doar le
afiseaza (ultima valoare, medie in timp), fara formule.

    source env.sh
    python3 metrics.py --zile 7            # tipareste
    python3 metrics.py --zile 7 --scrie    # si scrie instantaneul in soc-metrics
"""

from __future__ import annotations

import argparse
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

AUDIT_IDX = "soc-audit"
TRACES_IDX = "soc-traces"
VERDICTS_IDX = "verdicts-history"
METRICS_IDX = "soc-metrics"
MAX_DOCS = 10000
TIERS = ("fast", "hunt")
CLASSES = ("benign", "suspicious", "malicious", "undetermined")


def _ts(s) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


def _pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    k = (len(v) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(v) - 1)
    return round(v[lo] + (v[hi] - v[lo]) * (k - lo), 1)


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def _tvd(p: Counter, q: Counter) -> float | None:
    """Distanta de variatie totala intre doua distributii de clasificari (0 = identice)."""
    np_, nq = sum(p.values()), sum(q.values())
    if not np_ or not nq:
        return None
    return round(0.5 * sum(abs(p[c] / np_ - q[c] / nq) for c in CLASSES), 4)


def _tier_of(doc: dict) -> str | None:
    sp = (doc.get("verdict") or {}).get("source_path") or doc.get("source_path")
    return sp if sp in TIERS else None


def _in(doc: dict, start: datetime, end: datetime) -> bool:
    t = _ts(doc.get("@timestamp"))
    return t is not None and start <= t < end


def _audit_metrics(docs: list[dict]) -> dict:
    n = len(docs)
    decided = [d for d in docs if d.get("escalate") is not None]
    esc = [d for d in decided if d.get("escalate")]
    reasons = Counter(r for d in esc for r in (d.get("escalation_reasons") or []))
    failures = Counter(d.get("failure") for d in docs if d.get("failure"))
    tier2 = Counter(d.get("tier2") for d in docs if d.get("tier2"))
    lat = []
    for d in docs:
        a, b = _ts(d.get("started_at")), _ts(d.get("finished_at"))
        if a and b:
            lat.append((b - a).total_seconds() * 1000)
    cls = Counter((d.get("verdict") or {}).get("classification") for d in docs)
    corr = Counter((d.get("verdict") or {}).get("corroboration_status") for d in docs
                   if (d.get("verdict") or {}).get("source_path") == "hunt")
    no_model = sum(1 for d in docs if (d.get("verdict") or {}).get("model_id") == "none")
    out = {
        "cases": n,
        "escalation_decided": len(decided),
        "escalated": len(esc),
        "escalation_rate": _ratio(len(esc), len(decided)),
        "tier2_investigated": tier2.get("investigated", 0),
        "tier2_skipped_budget": tier2.get("skipped_budget", 0),
        "no_model": no_model,
        "no_model_rate": _ratio(no_model, n),
        "latency_ms_p50": _pct(lat, 0.5),
        "latency_ms_p95": _pct(lat, 0.95),
        "ab_agreement": corr.get("agreement", 0),
        "ab_disagreement": corr.get("disagreement", 0),
        "ab_secondary_unavailable": corr.get("secondary_unavailable", 0),
        "ab_budget_exhausted": corr.get("budget_exhausted", 0),
        "ab_agreement_rate": _ratio(corr.get("agreement", 0),
                                    corr.get("agreement", 0) + corr.get("disagreement", 0)),
    }
    for r, c in reasons.items():
        out[f"reason_{r}"] = c
    for f, c in failures.items():
        out[f"failure_{f}"] = c
    for c in CLASSES:
        out[f"class_{c}"] = cls.get(c, 0)
    return out


def _trace_metrics(docs: list[dict]) -> dict:
    tok = [(d.get("totals") or {}).get("tokens", 0) for d in docs]
    tools = [(d.get("totals") or {}).get("tool_calls", 0) for d in docs]
    errs = sum((d.get("totals") or {}).get("tool_errors", 0) for d in docs)
    return {
        "traced_cases": len(docs),
        "tokens_total": sum(tok),
        "tokens_per_case": round(sum(tok) / len(tok), 1) if tok else None,
        "tool_calls_per_case": round(sum(tools) / len(tools), 2) if tools else None,
        "tool_error_rate": _ratio(errs, sum(tools)),
    }


def _label_metrics(docs: list[dict]) -> dict:
    """Doar etichete puse de OM. Verdictele fara label_source=human nu conteaza:
    altfel sistemul si-ar masura propriile verdicte ca adevar."""
    human = [d for d in docs if d.get("label_source") == "human" and d.get("label_outcome")]
    o = Counter(d["label_outcome"] for d in human)
    tp, fp, fn, tn = (o.get(k, 0) for k in ("TP", "FP", "FN", "TN"))
    return {
        "labeled": len(human), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": _ratio(tp, tp + fp),
        "recall": _ratio(tp, tp + fn),
        "missed_attack_rate": _ratio(fn, tp + fn),
        "false_positive_rate": _ratio(fp, fp + tn),
    }


def compute(audits: list[dict], traces: list[dict], verdicts: list[dict],
            now: datetime, days: float) -> list[dict]:
    """Un document per nivel (fast, hunt) si unul total, pentru fereastra
    [now - days, now). Drift-ul compara cu fereastra [now - 2*days, now - days)."""
    end, start, prev = now, now - timedelta(days=days), now - timedelta(days=2 * days)
    out = []
    for tier in TIERS + ("all",):
        pick = (lambda d: True) if tier == "all" else (lambda d, t=tier: _tier_of(d) == t)
        cur_a = [d for d in audits if pick(d) and _in(d, start, end)]
        old_a = [d for d in audits if pick(d) and _in(d, prev, start)]
        doc = {"@timestamp": now.isoformat(), "window_days": days, "tier": tier}
        doc.update(_audit_metrics(cur_a))
        doc.update(_trace_metrics([d for d in traces if pick(d) and _in(d, start, end)]))
        doc.update(_label_metrics([d for d in verdicts if pick(d) and _in(d, start, end)]))
        old = _audit_metrics(old_a)
        doc["prev_escalation_rate"] = old["escalation_rate"]
        doc["drift_escalation_rate"] = (round(doc["escalation_rate"] - old["escalation_rate"], 4)
                                        if doc["escalation_rate"] is not None
                                        and old["escalation_rate"] is not None else None)
        doc["drift_classes_tvd"] = _tvd(Counter((d.get("verdict") or {}).get("classification") for d in cur_a),
                                        Counter((d.get("verdict") or {}).get("classification") for d in old_a))
        out.append(doc)
    return out


# --------------------------------------------------------------------------
# Elasticsearch: citire (cheia de writer citeste soc-audit; cea read-only nu)
# --------------------------------------------------------------------------


def _client():
    from elasticsearch import Elasticsearch
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                         api_key=os.environ["ES_WRITER_API_KEY"], request_timeout=60)


def _fetch(es, index: str, since: datetime, fields: list[str]) -> list[dict]:
    try:
        r = es.search(index=index, size=MAX_DOCS, source=fields, sort=[{"@timestamp": "asc"}],
                      query={"range": {"@timestamp": {"gte": since.isoformat()}}})
    except Exception as e:
        print(f"[metrici] {index} indisponibil: {type(e).__name__}", file=sys.stderr)
        return []
    hits = r["hits"]["hits"]
    if len(hits) >= MAX_DOCS:
        print(f"[metrici] {index}: limita de {MAX_DOCS} documente atinsa, fereastra trunchiata",
              file=sys.stderr)
    return [h["_source"] for h in hits]


def collect(es, now: datetime, days: float) -> list[dict]:
    since = now - timedelta(days=2 * days)
    audits = _fetch(es, AUDIT_IDX, since, ["@timestamp", "escalate", "escalation_reasons", "failure",
                                           "tier2", "started_at", "finished_at", "verdict.source_path",
                                           "verdict.classification", "verdict.corroboration_status",
                                           "verdict.model_id"])
    traces = _fetch(es, TRACES_IDX, since, ["@timestamp", "source_path", "totals"])
    verdicts = _fetch(es, VERDICTS_IDX, since, ["@timestamp", "source_path", "label_source", "label_outcome"])
    return compute(audits, traces, verdicts, now, days)


def write_snapshot(es, docs: list[dict]) -> None:
    for d in docs:
        es.index(index=METRICS_IDX, document=d)


def compute_and_write(es, now: datetime, days: float = 1) -> list[dict]:
    """Folosita de orchestrator: calculeaza fereastra si scrie instantaneul."""
    docs = collect(es, now, days)
    write_snapshot(es, docs)
    return docs


RATE_KEYS = {"escalation_rate", "drift_escalation_rate", "drift_classes_tvd", "no_model_rate",
             "tool_error_rate", "ab_agreement_rate", "precision", "recall", "missed_attack_rate",
             "false_positive_rate"}


def _fmt(k: str, v) -> str:
    if v is None:
        return "—"
    return f"{v:.1%}" if k in RATE_KEYS else str(v)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zile", type=float, default=7)
    ap.add_argument("--scrie", action="store_true", help="scrie instantaneul in soc-metrics")
    args = ap.parse_args()
    es = _client()
    docs = collect(es, datetime.now(timezone.utc), args.zile)
    keys = ["cases", "escalated", "escalation_rate", "drift_escalation_rate", "drift_classes_tvd",
            "tier2_investigated", "tier2_skipped_budget", "no_model", "latency_ms_p50", "latency_ms_p95",
            "tokens_per_case", "tool_calls_per_case", "tool_error_rate", "ab_agreement_rate",
            "labeled", "TP", "FP", "FN", "TN", "precision", "recall", "missed_attack_rate"]
    print(f"Metrici pe ultimele {args.zile:g} zile\n")
    print(f"{'':24s}" + "".join(f"{d['tier']:>12s}" for d in docs))
    for k in keys:
        print(f"{k:24s}" + "".join(f"{_fmt(k, d.get(k)):>12s}" for d in docs))
    if args.scrie:
        write_snapshot(es, docs)
        print(f"\nInstantaneu scris in {METRICS_IDX} ({len(docs)} documente).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
STUDIUL DE ABLATIE — Tier 1, configuratiile A-D pe ACEEASI alerta.

Pentru fiecare scenariu: telemetria se genereaza O SINGURA DATA pe web-prod,
alerta reala se preia o data, apoi pe ea ruleaza, independent, fiecare
configuratie (fast_path.CONFIGS):
  A = fapte + enrich      B = A + RAG      C = A + unelte      D = A + RAG + unelte
Ordinea configuratiilor se roteste de la un scenariu la altul (latenta nu
favorizeaza sistematic una). Cu --treceri 2, fiecare configuratie ruleaza de
doua ori pe aceeasi alerta: diferentele masoara variatia modelului.

Istoricul etichetat (past_verdicts, RAG din verdicts-history) e OPRIT implicit:
etichetele puse pe alertele produse de scenarii nu au voie sa se intoarca in
evaluarea acelorasi scenarii. --cu-istoric il porneste (pentru comparatie).

Alertele preluate se salveaza (results/ablatie-alerte-*.json); --alerte <fisier>
reia aceleasi alerte fara generare noua.

Metrici per configuratie: TP/FP/FN/TN, recall, rata FP, rata de escaladare
(should_escalate), latenta p50/p95, tokeni, apeluri de unelte, rezistenta la
injectie (scenariile cu `injection: true` clasate corect), pivoturi respinse
de unelte, instabilitate intre treceri.

    source env.sh
    SCENARIOS=scenarios_ablation.yml python3 -u ablation.py --treceri 2 \\
        | tee results/ablatie-$(date +%F-%H%M).txt
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import time
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_NAMES = ("A", "B", "C", "D")
WAIT_S = 360   # ca harness-ul pe calea rapida: indexare + intervalul regulii EQL


def _pct(values: list[float], p: float) -> float | None:
    if not values:
        return None
    v = sorted(values)
    k = (len(v) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(v) - 1)
    return round(v[lo] + (v[hi] - v[lo]) * (k - lo), 1)


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def rotation(configs: list[str], i: int) -> list[str]:
    k = i % len(configs)
    return configs[k:] + configs[:k]


def summarize(rows: list[dict]) -> dict[str, dict]:
    """Functie pura. rows: {scenario, config, pass, gt, injection, outcome,
    classification, escalate, latency_ms, tokens, tool_calls, rejected, error}."""
    out = {}
    for cfg in sorted({r["config"] for r in rows}):
        rs = [r for r in rows if r["config"] == cfg]
        o = defaultdict(int)
        for r in rs:
            o[r["outcome"]] += 1
        tp, fp, fn, tn = (o[k] for k in ("TP", "FP", "FN", "TN"))
        inj = [r for r in rs if r.get("injection")]
        by_case = defaultdict(set)
        for r in rs:
            by_case[r["scenario"]].add((r["outcome"], r["classification"]))
        multi = [s for s in by_case if sum(1 for r in rs if r["scenario"] == s) > 1]
        lat = [r["latency_ms"] for r in rs if r.get("latency_ms") is not None]
        tok = [r.get("tokens") or 0 for r in rs]
        out[cfg] = {
            "runs": len(rs), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "recall": _ratio(tp, tp + fn),
            "false_positive_rate": _ratio(fp, fp + tn),
            "escalation_rate": _ratio(sum(1 for r in rs if r.get("escalate")), len(rs)),
            "latency_ms_p50": _pct(lat, 0.5), "latency_ms_p95": _pct(lat, 0.95),
            "tokens_per_run": round(sum(tok) / len(tok), 1) if tok else None,
            "tool_calls_per_run": round(sum(r.get("tool_calls") or 0 for r in rs) / len(rs), 2) if rs else None,
            "rejected_pivots": sum(r.get("rejected") or 0 for r in rs),
            "errors": sum(1 for r in rs if r.get("error")),
            "injection_runs": len(inj),
            "injection_resisted": sum(1 for r in inj if r["outcome"] in ("TP", "TN")),
            "unstable_scenarios": sum(1 for s in multi if len(by_case[s]) > 1),
            "multi_pass_scenarios": len(multi),
        }
    return out


def _error_row(name, cfg, p, sc, err, dt) -> dict:
    """Esecul unei rulari se noteaza ca escaladare (principiul 8), cu eroarea."""
    gt = sc["ground_truth"]
    return {"scenario": name, "config": cfg, "pass": p, "gt": gt, "injection": bool(sc.get("injection")),
            "outcome": "TP" if gt == "attack" else "FP", "classification": "undetermined",
            "confidence": 0, "action": "escalate_human", "escalate": True, "reasons": ["tier1_failure"],
            "latency_ms": dt, "tokens": 0, "tool_calls": 0, "rejected": 0, "l1_status": None,
            "error": type(err).__name__}


def run_one(alert: dict, cfg_name: str, sc: dict, p: int, graphs: dict) -> dict:
    import tracing
    from escalation import should_escalate
    from harness import score_verdict
    name = sc["name"]
    t0 = time.monotonic()
    try:
        with tracing.case() as tr:
            out = graphs[cfg_name].invoke({"alert": copy.deepcopy(alert)}, config={"recursion_limit": 25})
        dt = int((time.monotonic() - t0) * 1000)
    except Exception as e:
        return _error_row(name, cfg_name, p, sc, e, int((time.monotonic() - t0) * 1000))
    v = out["verdict"]
    esc = should_escalate(v, floor_applied=bool(out.get("floor_applied")),
                          pair_in_baseline=(out.get("context") or {}).get("pair_in_baseline"))
    tot = tr.totals()
    l1 = out.get("l1") or {}
    return {"scenario": name, "config": cfg_name, "pass": p, "gt": sc["ground_truth"],
            "injection": bool(sc.get("injection")), "outcome": score_verdict(v, sc["ground_truth"]),
            "classification": v.classification.value, "confidence": v.confidence,
            "action": v.proposed_action.value, "escalate": esc.escalate,
            "reasons": [r.value for r in esc.reasons], "latency_ms": dt,
            "tokens": tot.get("tokens", 0), "tool_calls": l1.get("tool_calls", 0),
            "rejected": l1.get("rejected", 0), "l1_status": l1.get("status"), "error": None}


RATE_KEYS = {"recall", "false_positive_rate", "escalation_rate"}


def print_summary(summary: dict[str, dict]) -> None:
    keys = ["runs", "TP", "FP", "FN", "TN", "recall", "false_positive_rate", "escalation_rate",
            "latency_ms_p50", "latency_ms_p95", "tokens_per_run", "tool_calls_per_run",
            "rejected_pivots", "injection_resisted", "injection_runs", "unstable_scenarios",
            "multi_pass_scenarios", "errors"]
    cfgs = list(summary)
    print(f"\n{'':22s}" + "".join(f"{c:>10s}" for c in cfgs))
    for k in keys:
        cells = []
        for c in cfgs:
            v = summary[c].get(k)
            cells.append("—" if v is None else (f"{v:.0%}" if k in RATE_KEYS else str(v)))
        print(f"{k:22s}" + "".join(f"{x:>10s}" for x in cells))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--configuratii", default=",".join(CONFIG_NAMES))
    ap.add_argument("--treceri", type=int, default=1)
    ap.add_argument("--alerte", help="fisier JSON cu alerte salvate anterior (fara generare)")
    ap.add_argument("--cu-istoric", action="store_true", help="porneste istoricul etichetat")
    ap.add_argument("--web-prod-host", default="tiberiu@172.20.99.240")
    ap.add_argument("--doar", help="ruleaza doar scenariul cu acest nume")
    args = ap.parse_args()

    import yaml
    from fast_path import CONFIGS, build_fast_path
    from harness import _fetch_alert, run_web_prod

    cfg_names = [c.strip() for c in args.configuratii.split(",") if c.strip()]
    for c in cfg_names:
        if c not in CONFIGS:
            raise SystemExit(f"configuratie necunoscuta: {c}")
    graphs = {c: build_fast_path(CONFIGS[c] if args.cu_istoric else CONFIGS[c].without_history())
              for c in cfg_names}

    path = Path(os.environ.get("SCENARIOS", "scenarios_ablation.yml"))
    scenarios = yaml.safe_load(path.read_text(encoding="utf-8"))["scenarios"]
    if args.doar:
        scenarios = [s for s in scenarios if s["name"] == args.doar]
    saved = json.loads(Path(args.alerte).read_text(encoding="utf-8")) if args.alerte else {}

    print(f"=== Ablatie Tier 1: {len(scenarios)} scenarii x {cfg_names} x {args.treceri} treceri"
          f" | istoric {'pornit' if args.cu_istoric else 'oprit'} ===\n", flush=True)
    rows, alerts = [], {}
    for i, sc in enumerate(scenarios):
        name = sc["name"]
        print(f"[{i + 1}/{len(scenarios)}] {name}  (adevar: {sc['ground_truth']}"
              f"{', injectie' if sc.get('injection') else ''})", flush=True)
        alert = saved.get(name)
        if alert is None:
            if sc.get("generate"):
                print(f"    generez telemetrie (astept {WAIT_S}s)...", flush=True)
                run_web_prod(sc["generate"], args.web_prod_host, wait=WAIT_S)
            alert = _fetch_alert(sc["rule_name"])
        if alert is None:
            print("    EROARE: nicio alerta; scenariul e sarit", flush=True)
            continue
        alerts[name] = alert
        for p in range(1, args.treceri + 1):
            for c in rotation(cfg_names, i):
                r = run_one(alert, c, sc, p, graphs)
                rows.append(r)
                print(f"    {c} t{p}: {r['classification']}/{r['confidence']}/{r['action']} "
                      f"[{r['outcome']}] esc={r['escalate']} {r['latency_ms'] / 1000:.0f}s "
                      f"tok={r['tokens']} unelte={r['tool_calls']}"
                      + (f" respinse={r['rejected']}" if r["rejected"] else "")
                      + (f" L1={r['l1_status']}" if r["l1_status"] not in (None, "ok") else "")
                      + (f" EROARE {r['error']}" if r["error"] else ""), flush=True)

    summary = summarize(rows)
    print_summary(summary)
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    (ROOT / "results").mkdir(exist_ok=True)
    if alerts and not args.alerte:
        ap_path = ROOT / "results" / f"ablatie-alerte-{stamp}.json"
        ap_path.write_text(json.dumps(alerts, ensure_ascii=False, default=str), encoding="utf-8")
        print(f"\nAlerte salvate: {ap_path.relative_to(ROOT)} (reluare cu --alerte)")
    print("\nJSON:", json.dumps({"run_id": str(uuid.uuid4()), "rows": rows, "summary": summary},
                               ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

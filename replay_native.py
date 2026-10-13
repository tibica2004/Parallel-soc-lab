#!/usr/bin/env python3
"""
RELUARE PE ALERTELE NATIVE DEFEND deja existente in ES (faza 10).

Nu genereaza nimic pe web-prod: ia ultimele N alerte native per regula si le
trece prin calea rapida (configuratia din FAST_CONFIG, implicit base) si prin
should_escalate. Masoara doar ce face Tier 1 cu ele; adevarul de referinta nu
e in alerta, deci scorarea (attack/benign) o face omul din lista afisata.

    python3 -u replay_native.py --per-regula 5 | tee results/nativ-$(date +%F-%H%M).txt
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter

import defend_native
from elastic_tools import ES
from escalation import should_escalate
from fast_path import build_fast_path, config_from_env

ALERTS_IDX = ".alerts-security.alerts-*"


def native_alerts(per_rule: int) -> list[dict]:
    r = ES.search(index=ALERTS_IDX, size=0,
                  query={"term": {"event.dataset": defend_native.NATIVE_DATASET}},
                  aggs={"r": {"terms": {"field": "kibana.alert.rule.name", "size": 50},
                              "aggs": {"last": {"top_hits": {"size": per_rule,
                                                             "sort": [{"@timestamp": "desc"}]}}}}})
    return [h["_source"] for b in r["aggregations"]["r"]["buckets"] for h in b["last"]["hits"]["hits"]]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-regula", type=int, default=5)
    args = ap.parse_args()
    cfg = config_from_env()
    graph = build_fast_path(cfg)
    alerts = native_alerts(args.per_regula)
    print(f"=== Reluare alerte native Defend: {len(alerts)} alerte | configuratia {cfg.name} ===\n")
    stats, rows = Counter(), []
    for i, a in enumerate(alerts, 1):
        nd = defend_native.detection(a)
        rule = a.get("kibana.alert.rule.name") or ""
        t0 = time.monotonic()
        try:
            out = graph.invoke({"alert": a}, config={"recursion_limit": 25})
        except Exception as e:
            print(f"[{i}] {rule}\n    EROARE: {e}")
            stats["errors"] += 1
            continue
        v, ctx = out["verdict"], out.get("context") or {}
        esc = should_escalate(v, floor_applied=bool(out.get("floor_applied")),
                              pair_in_baseline=ctx.get("pair_in_baseline"),
                              native_detection=bool(ctx.get("native_detection")))
        ex = ctx.get("execution") or {}
        dt = time.monotonic() - t0
        print(f"[{i}] {rule}  ({a.get('@timestamp', '')[:19]})")
        print(f"    defend: {nd.kind.value}/{nd.mode.value} risk={nd.risk_score} attck={','.join(nd.techniques[:4])}")
        print(f"    fapte: user={ex.get('user')} parinte={ex.get('parent')} proces={ex.get('process')} "
              f"web_svc={ctx.get('ran_by_web_service_account')} admin={ctx.get('ran_by_known_admin')}")
        print(f"    -> {v.classification.value} / {v.confidence} / {v.proposed_action.value}  "
              f"{'escaladat (' + ', '.join(r.value for r in esc.reasons) + ')' if esc.escalate else 'INCHIS'}  [{dt:.0f}s]")
        stats[v.classification.value] += 1
        stats["escalated" if esc.escalate else "closed"] += 1
        stats["floor"] += bool(out.get("floor_applied"))
        rows.append({"rule": rule, "ts": a.get("@timestamp"), "classification": v.classification.value,
                     "confidence": v.confidence, "escalate": esc.escalate,
                     "reasons": [r.value for r in esc.reasons], "latency_s": round(dt, 1)})
    print(f"\nREZUMAT: {dict(stats)}")
    print("JSON: " + json.dumps(rows, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

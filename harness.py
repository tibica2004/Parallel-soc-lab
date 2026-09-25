#!/usr/bin/env python3
"""Harness de evaluare: ruleaza scenarii etichetate, scoate metrici."""
from __future__ import annotations
import argparse, json, os, subprocess, sys, time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import yaml
from elasticsearch import Elasticsearch

ES = Elasticsearch(
    os.environ.get("ES_URL", "http://localhost:9200"),
    api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"],
    request_timeout=30,
)
SCENARIOS = Path(os.environ.get("SCENARIOS", "scenarios.yml"))
ALERT_CLASSES = {"malicious", "suspicious"}
NON_CLOSE = {"escalate_human","block_ip_ttl","freeze_process","quarantine_file","isolate_host","kill_process"}


def run_web_prod(cmd, host):
    if not cmd: return
    subprocess.run(["ssh", host, cmd], check=False, capture_output=True, timeout=40)
    time.sleep(45)


def score(verdict, gt):
    flagged = (verdict.classification.value in ALERT_CLASSES
               or verdict.proposed_action.value in NON_CLOSE)
    if gt == "attack": return "TP" if flagged else "FN"
    return "FP" if flagged else "TN"


def run_fast(sc):
    from fast_path import build_fast_path
    g = build_fast_path()
    a = sc["alert"]
    return g.invoke({"alert": a, "rule_id": a.get("kibana.alert.rule.uuid","test")},
                    config={"recursion_limit":25})["verdict"]


def run_hunt(sc):
    from hunt_path import build_hunt_path
    from schemas import RarityFinding, EntityType
    d = sc["finding"]
    f = RarityFinding(kind=d.get("kind","new_parent_child"), entity_type=EntityType.HOST,
                      entity_id=d["host"], detail=d["detail"],
                      rarity_score=d.get("rarity_score",1.0), evidence_refs=[])
    return build_hunt_path().invoke({"finding": f}, config={"recursion_limit":80})["verdict"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["fast","hunt"])
    ap.add_argument("--exclude-validation", action="store_true")
    ap.add_argument("--web-prod-host", default=os.environ.get("WEB_PROD_HOST", ""))
    args = ap.parse_args()

    import urllib.request
    base = os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1")
    try:
        urllib.request.urlopen(base.rstrip("/") + "/models", timeout=5)
    except Exception as e:
        print(f"Modelul nu raspunde la {base}: {e}. Porneste tunelul si reincearca.")
        return 1

    if not SCENARIOS.exists():
        print(f"Lipseste {SCENARIOS}"); return 1
    scenarios = yaml.safe_load(SCENARIOS.read_text())["scenarios"]
    if args.only: scenarios = [s for s in scenarios if s["path"]==args.only]
    if args.exclude_validation: scenarios = [s for s in scenarios if not s.get("validation")]

    print(f"=== Harness: {len(scenarios)} scenarii | critic: {'OPRIT' if os.environ.get('DISABLE_CRITIC') == '1' else 'ACTIV'} ===\n")
    conf = defaultdict(int); by_band = defaultdict(lambda:{"correct":0,"total":0}); missed=[]

    for i, sc in enumerate(scenarios,1):
        name = sc.get("name",f"sc-{i}"); gt = sc["ground_truth"]
        print(f"[{i}/{len(scenarios)}] {name}  (adevar: {gt})")
        if sc.get("generate"):
            print(f"    generez telemetrie...")
            run_web_prod(sc["generate"], args.web_prod_host)
        t0 = datetime.now()
        try:
            v = run_fast(sc) if sc["path"]=="fast" else run_hunt(sc)
        except Exception as e:
            print(f"    EROARE: {e}"); continue
        dt = (datetime.now()-t0).total_seconds()
        o = score(v, gt); conf[o]+=1
        band = (v.confidence//10)*10; by_band[band]["total"]+=1
        if o in ("TP","TN"): by_band[band]["correct"]+=1
        if o=="FN": missed.append(name)
        flag = {"TP":"OK","TN":"OK","FN":"!!! ATAC RATAT","FP":"fals pozitiv"}[o]
        print(f"    -> {v.classification.value}/{v.confidence}/{v.proposed_action.value}  [{o} {flag}] critic_ok={v.critic_agreed}  [{dt:.0f}s]")

    tp,fn,tn,fp = (conf[k] for k in ("TP","FN","TN","FP"))
    attacks=tp+fn; benigns=tn+fp
    print(f"\n{'='*50}\nMATRICE DE CONFUZIE")
    print(f"  TP (atac semnalat):    {tp}")
    print(f"  FN (ATAC RATAT):       {fn}   <- eroarea scumpa")
    print(f"  TN (benign inchis):    {tn}")
    print(f"  FP (benign escaladat): {fp}")
    if attacks:
        print(f"\n  RECALL: {tp/attacks:.0%} ({tp}/{attacks})")
        print(f"  RATA ATACURI RATATE: {fn/attacks:.0%}  <- conteaza")
    if tp+fp: print(f"  PRECIZIE: {tp/(tp+fp):.0%}")
    if benigns: print(f"  RATA FALS POZITIVE: {fp/benigns:.0%}")
    print(f"\nCALIBRARE (precizie pe banda):")
    for b in sorted(by_band):
        x=by_band[b]; acc=x["correct"]/x["total"] if x["total"] else 0
        print(f"  {b:3d}-{b+9}: {acc:.0%} ({x['correct']}/{x['total']})")
    if missed:
        print(f"\n!!! ATACURI RATATE: {missed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

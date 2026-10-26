#!/usr/bin/env python3
"""
HARNESS DE EVALUARE.

Diferenta fata de scripturile de test: astea rulau O investigatie si-ti aratau
rezultatul. Harness-ul ruleaza N scenarii ETICHETATE si scoate un scor.

Transforma "am rulat o data si a iesit suspicious" in "din 20 de scenarii,
sistemul a avut dreptate in 16, a ratat 2 atacuri, a escaladat inutil 2 benigne".

Scenariile stau in scenarios.yml. Fiecare are:
  - un finding (ce intra pe calea lenta) SAU o alerta (ce intra pe calea rapida)
  - o eticheta: ground_truth = attack | benign
  - optional: telemetrie de generat inainte (comanda pe web-prod)

METRICA CARE CONTEAZA pentru un sistem de securitate: rata de ATACURI RATATE
(fals negative). Un atac clasat benign cu incredere mare e eroarea scumpa.
O urmarim separat de precizia generala.

DISCIPLINA: un scenariu adaugat DUPA ce ai vazut sistemul gresind pe el merge
in setul de validare (validation: true), tinut deoparte. Altfel optimizezi
sistemul pe examen, nu pe materie.

    export ES_API_KEY=... ES_URL=... LLM_BASE_URL=...
    python3 harness.py                    # ruleaza tot
    python3 harness.py --only fast        # doar calea rapida
    python3 harness.py --exclude-validation
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml
from elasticsearch import Elasticsearch

ES = Elasticsearch(
    os.environ.get("ES_URL", "http://localhost:9200"),
    api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"],
    request_timeout=30,
)

SCENARIOS = Path(os.environ.get("SCENARIOS", "scenarios.yml"))

# Clasificarile care conteaza ca "sistemul a semnalat pericol"
ALERT_CLASSES = {"malicious", "suspicious"}
# Actiuni care inseamna "nu a inchis, a escaladat/actionat"
NON_CLOSE_ACTIONS = {"escalate_human", "block_ip_ttl", "freeze_process",
                     "quarantine_file", "isolate_host", "kill_process"}


def run_web_prod(cmd: str, host: str, wait: int = 45) -> None:
    """Genereaza telemetrie pe web-prod prin SSH inainte de scenariu."""
    if not cmd:
        return
    subprocess.run(["ssh", host, cmd], check=False, capture_output=True, timeout=30)
    time.sleep(wait)  # indexare; pentru fast, si intervalul regulii EQL


def score_verdict(verdict, ground_truth: str) -> str:
    """
    Clasifica rezultatul in 4 categorii de confuzie:
      TP  - atac, sistemul l-a semnalat (malicious/suspicious sau a escaladat)
      FN  - atac, sistemul l-a INCHIS ca benign  <- eroarea scumpa
      TN  - benign, sistemul l-a inchis corect
      FP  - benign, sistemul l-a escaladat/semnalat inutil
    """
    flagged = (verdict.classification.value in ALERT_CLASSES
               or verdict.proposed_action.value in NON_CLOSE_ACTIONS)
    if ground_truth == "attack":
        return "TP" if flagged else "FN"
    else:
        return "FP" if flagged else "TN"


def _fetch_alert(rule_name: str, since_min: int = 15, since: datetime | None = None):
    """Cea mai recenta alerta REALA de la regula data. rule_name e keyword,
    deci potrivire exacta. Cu `since` (momentul generarii scenariului), doar
    alertele aparute dupa el: altfel un scenariu poate evalua alerta lasata de
    scenariul anterior."""
    from elasticsearch import Elasticsearch
    es = Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                       api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"])
    r = es.search(index=".alerts-security.alerts-*", size=1, sort=[{"@timestamp": "desc"}],
                  query={"bool": {"filter": [
                      {"term": {"kibana.alert.rule.name": rule_name}},
                      {"range": {"@timestamp": {"gte": since.isoformat() if since else f"now-{since_min}m"}}},
                  ]}})
    hits = r["hits"]["hits"]
    return hits[0]["_source"] if hits else None


def run_fast(scenario: dict, since: datetime | None = None):
    """Ruleaza un scenariu prin calea rapida, pe ALERTA REALA produsa de regula.
    Scenariul trebuie sa dea `rule_name` (regula care se declanseaza)."""
    from fast_path import build_fast_path
    rule = scenario.get("rule_name")
    if not rule:
        raise ValueError(f"scenariul '{scenario.get('name')}' nu are rule_name")
    alert = _fetch_alert(rule, since=since)
    if alert is None:
        raise RuntimeError(f"nicio alerta '{rule}' dupa generarea scenariului "
                           f"(regula nu s-a declansat inca sau nu exista)")
    graph = build_fast_path()
    return graph.invoke({"alert": alert}, config={"recursion_limit": 25})["verdict"]


def run_chain(scenario: dict, since: datetime | None = None):
    """Lantul complet pe alerta REALA: Tier 1 -> should_escalate -> (daca escaladeaza)
    Case fara verdictul Tier 1 -> Tier 2. Se noteaza verdictul FINAL: al Tier 2
    daca a existat, altfel al Tier 1. Exact ce ar face orchestratorul (fara buget)."""
    import uuid
    from case_adapter import from_alert
    from escalation import should_escalate
    from fast_path import build_fast_path
    from hunt_path import build_hunt_path
    rule = scenario.get("rule_name")
    if not rule:
        raise ValueError(f"scenariul '{scenario.get('name')}' nu are rule_name")
    alert = _fetch_alert(rule, since=since)
    if alert is None:
        raise RuntimeError(f"nicio alerta '{rule}' dupa generarea scenariului")
    out = build_fast_path().invoke({"alert": alert}, config={"recursion_limit": 25})
    v1 = out["verdict"]
    esc = should_escalate(v1, floor_applied=bool(out.get("floor_applied")),
                          pair_in_baseline=(out.get("context") or {}).get("pair_in_baseline"),
                          native_detection=bool((out.get("context") or {}).get("native_detection")))
    print(f"    Tier 1: {v1.classification.value} / {v1.confidence} / {v1.proposed_action.value}"
          f"  -> {'escaladat (' + ', '.join(r.value for r in esc.reasons) + ')' if esc.escalate else 'inchis'}")
    if not esc.escalate:
        return v1
    case = from_alert(alert, esc, str(uuid.uuid4()), facts=out.get("context"))
    v2 = build_hunt_path().invoke({"case": case}, config={"recursion_limit": 80})["verdict"]
    print(f"    Tier 2: {v2.classification.value} / {v2.confidence} / {v2.proposed_action.value}")
    return v2


def run_hunt(scenario: dict):
    """Ruleaza un scenariu prin calea lenta."""
    from hunt_path import build_hunt_path
    from schemas import RarityFinding, EntityType
    d = scenario["finding"]
    finding = RarityFinding(
        kind=d.get("kind", "new_parent_child"),
        entity_type=EntityType.HOST,
        entity_id=d["host"], detail=d["detail"],
        rarity_score=d.get("rarity_score", 1.0), evidence_refs=[],
    )
    graph = build_hunt_path()
    res = graph.invoke({"finding": finding}, config={"recursion_limit": 80})
    return res["verdict"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", choices=["fast", "hunt"], help="doar o cale")
    ap.add_argument("--exclude-validation", action="store_true",
                    help="sari peste scenariile din setul de validare")
    ap.add_argument("--web-prod-host", default=os.environ.get("WEB_PROD_HOST", "tiberiu@172.20.99.240"))
    ap.add_argument("--chain", action="store_true",
                    help="scenariile fast trec prin lantul complet Tier 1 -> Tier 2")
    args = ap.parse_args()

    if not SCENARIOS.exists():
        print(f"Lipseste {SCENARIOS}. Vezi scenarios.yml.example.")
        return 1

    scenarios = yaml.safe_load(SCENARIOS.read_text(encoding="utf-8"))["scenarios"]
    if args.only:
        scenarios = [s for s in scenarios if s["path"] == args.only]
    if args.exclude_validation:
        scenarios = [s for s in scenarios if not s.get("validation")]

    print(f"=== Harness: {len(scenarios)} scenarii{' | LANT Tier 1 -> Tier 2' if args.chain else ''} ===\n")

    confusion = defaultdict(int)
    by_band = defaultdict(lambda: {"correct": 0, "total": 0})
    results = []
    missed_attacks = []

    for i, sc in enumerate(scenarios, 1):
        name = sc.get("name", f"scenariu-{i}")
        gt = sc["ground_truth"]
        print(f"[{i}/{len(scenarios)}] {name}  (adevar: {gt})")

        # Genereaza telemetrie daca scenariul o cere
        since = datetime.now(timezone.utc) if sc.get("generate") else None
        if sc.get("generate"):
            wait = 360 if sc["path"] == "fast" else 45
            print(f"    generez telemetrie (astept {wait}s)...")
            run_web_prod(sc["generate"], args.web_prod_host, wait=wait)

        t0 = datetime.now()
        try:
            if sc["path"] == "fast":
                verdict = run_chain(sc, since) if args.chain else run_fast(sc, since)
            else:
                verdict = run_hunt(sc)
        except Exception as e:
            print(f"    EROARE: {e}")
            continue
        dt = (datetime.now() - t0).total_seconds()

        outcome = score_verdict(verdict, gt)
        confusion[outcome] += 1

        # Calibrare: precizia pe banda de incredere
        band = (verdict.confidence // 10) * 10
        by_band[band]["total"] += 1
        if outcome in ("TP", "TN"):
            by_band[band]["correct"] += 1

        if outcome == "FN":
            missed_attacks.append(name)

        flag = {"TP": "OK", "TN": "OK", "FN": "!!! ATAC RATAT", "FP": "fals pozitiv"}[outcome]
        print(f"    -> {verdict.classification.value} / {verdict.confidence} / "
              f"{verdict.proposed_action.value}  [{outcome} {flag}]  [{dt:.0f}s]")
        results.append((name, gt, verdict.classification.value, verdict.confidence, outcome))

    # --- Raport ---
    tp, fn, tn, fp = (confusion[k] for k in ("TP", "FN", "TN", "FP"))
    total = tp + fn + tn + fp
    attacks = tp + fn
    benigns = tn + fp

    print(f"\n{'='*50}")
    print("MATRICE DE CONFUZIE")
    print(f"  TP (atac semnalat):     {tp}")
    print(f"  FN (ATAC RATAT):        {fn}   <- eroarea scumpa")
    print(f"  TN (benign inchis):     {tn}")
    print(f"  FP (benign escaladat):  {fp}")

    if attacks:
        recall = tp / attacks
        print(f"\n  RECALL (atacuri prinse):  {recall:.0%}  ({tp}/{attacks})")
        print(f"  RATA ATACURI RATATE:      {fn/attacks:.0%}  <- metrica care conteaza")
    if tp + fp:
        precision = tp / (tp + fp)
        print(f"  PRECIZIE:                 {precision:.0%}")
    if benigns:
        print(f"  RATA FALS POZITIVE:       {fp/benigns:.0%}  ({fp}/{benigns})")

    print(f"\nCALIBRARE (precizie pe banda de incredere):")
    for band in sorted(by_band):
        b = by_band[band]
        acc = b["correct"] / b["total"] if b["total"] else 0
        print(f"  {band:3d}-{band+9}:  {acc:.0%}  ({b['correct']}/{b['total']})")
    print("  -> pragul pentru actiuni automate = prima banda cu precizie >= 95%")

    if missed_attacks:
        print(f"\n!!! ATACURI RATATE ({len(missed_attacks)}):")
        for m in missed_attacks:
            print(f"     - {m}")
        print("  Astea sunt cazurile de studiat. Adauga-le in setul de validare.")

    return 0


if __name__ == "__main__":
    sys.exit(main())

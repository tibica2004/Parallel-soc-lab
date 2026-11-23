#!/usr/bin/env python3
"""
REGRESIE SI DETERMINISM (pasul 8.3) — Tier 1 pe un set fix de alerte, fara sa scrie nimic.

  python regression.py export        # setul de aur: verdictele cu eticheta UMANA -> data/golden/
  python regression.py run           # Tier 1 pe setul de aur -> P/R/F1, matrice, schimbari fata de baseline
  python regression.py determinism --n 40   # 2 rulari pe ultimele N alerte (nu cere etichete)

Setul de aur: verdicts-history cu label_source=human; alerta se citeste dupa EvidenceRef (nu
se copiaza in repo: data/ e in .gitignore). Etichetele sunt binare (interfata: attack/benign),
deci pragul din task (25 malicious/25 suspicious/25 benign) devine >= 50 attack si >= 50 benign.
Scorul e acelasi ca in interfata de etichetare (labeling.outcome: flagged = suspicious/malicious/
undetermined sau actiune != none). Nimic nu se scrie in verdicts-history (rulare offline).

Raport: data/regression/<ts>.md + .json; soc-metrics type=regression / determinism; baseline:
data/regression/baseline_<prompt_set>_<model>.json (prima rulare pe un set de prompturi il creeaza).
GPU: ruleaza doar cand harness-ul si OpenClaw nu ruleaza.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from elasticlab.paths import REPO_ROOT

ROOT = REPO_ROOT
GOLDEN = ROOT / "data" / "golden" / "golden_v1.ndjson"
OUT = ROOT / "data" / "regression"
MIN_PER_CLASS = 50
DETERMINISM_MIN_PCT = 98.0


# =============================================================================
# FUNCTII PURE
# =============================================================================

WILSON_Z = 1.959964   # 95%


def wilson(k: int, n: int, z: float = WILSON_Z) -> tuple[float, float] | None:
    """Intervalul Wilson (95%) pentru proportia k/n. None cand n = 0 (nimic de estimat).
    Ramane in [0, 1] si la k = 0 sau k = n, unde intervalul normal ar degenera. Pur."""
    if n <= 0:
        return None
    if not 0 <= k <= n:
        raise ValueError(f"k={k} in afara [0, {n}]")
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / den
    return (round(max(0.0, mid - half), 4), round(min(1.0, mid + half), 4))


def metrics(rows: list[dict]) -> dict:
    """rows: {ground_truth, outcome(TP/FP/FN/TN)}. Precizie/recall/F1 pe clasa attack, cu
    intervale Wilson 95% pentru precizie, recall si rata de fals pozitive. Pur."""
    c = {k: sum(1 for r in rows if r["outcome"] == k) for k in ("TP", "FP", "FN", "TN")}
    p = c["TP"] / (c["TP"] + c["FP"]) if c["TP"] + c["FP"] else None
    r = c["TP"] / (c["TP"] + c["FN"]) if c["TP"] + c["FN"] else None
    f1 = 2 * p * r / (p + r) if p and r else None
    rnd = lambda x: None if x is None else round(x, 4)
    ci = lambda k, n: None if (w := wilson(k, n)) is None else list(w)
    return {**c, "n": len(rows), "precision_attack": rnd(p), "recall_attack": rnd(r),
            "f1_attack": rnd(f1),
            "fpr_benign": rnd(c["FP"] / (c["FP"] + c["TN"])) if c["FP"] + c["TN"] else None,
            "precision_attack_ci95": ci(c["TP"], c["TP"] + c["FP"]),
            "recall_attack_ci95": ci(c["TP"], c["TP"] + c["FN"]),
            "fpr_benign_ci95": ci(c["FP"], c["FP"] + c["TN"])}


def fmt_ci(value: float | None, ci: list[float] | None) -> str:
    """'0.75 [0.41, 0.93]' pentru raport; '—' cand nu exista valoare. Pur."""
    if value is None:
        return "—"
    return f"{value} [{ci[0]}, {ci[1]}]" if ci else str(value)


def changed(baseline: dict[str, dict], now: dict[str, dict]) -> list[dict]:
    """Alertele al caror verdict (clasificare, flagged) difera de baseline. Pur."""
    out = []
    for k, v in now.items():
        b = baseline.get(k)
        if b and (b["classification"], b["flagged"]) != (v["classification"], v["flagged"]):
            out.append({"alert": k, "old": b["classification"], "new": v["classification"],
                        "old_flagged": b["flagged"], "new_flagged": v["flagged"]})
    return sorted(out, key=lambda x: x["alert"])


def determinism(a: dict[str, dict], b: dict[str, dict]) -> dict:
    """Doua rulari pe aceleasi alerte: % identic si schimbarile grave (atac <-> benign). Pur."""
    keys = sorted(set(a) & set(b))
    diffs = [k for k in keys if (a[k]["classification"], a[k]["flagged"])
             != (b[k]["classification"], b[k]["flagged"])]
    severe = [k for k in diffs if {a[k]["classification"], b[k]["classification"]} == {"malicious", "benign"}]
    pct = round(100 * (len(keys) - len(diffs)) / len(keys), 1) if keys else 0.0
    return {"n": len(keys), "identical_pct": pct, "diffs": diffs, "severe": severe,
            "passed": pct >= DETERMINISM_MIN_PCT and not severe}


def balanced(items: list[dict]) -> dict:
    n = {g: sum(1 for i in items if i["ground_truth"] == g) for g in ("attack", "benign")}
    return {**n, "ok": all(v >= MIN_PER_CLASS for v in n.values())}


# =============================================================================
# EFECTE
# =============================================================================

def _es(var: str = "ES_READER_API_KEY"):
    from elasticsearch import Elasticsearch
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                         api_key=os.environ[var], request_timeout=60)


def _alert(es, ref: dict) -> dict | None:
    try:
        return es.get(index=ref["index"], id=ref["doc_id"])["_source"]
    except Exception:  # noqa: BLE001 — alerta stearsa (retentie): sarita, raportata
        return None


def triage_one(fast, alert: dict) -> dict:
    from labeling import is_flagged
    out = fast.invoke({"alert": alert}, config={"recursion_limit": 25})
    v = out["verdict"]
    return {"classification": v.classification.value,
            "flagged": is_flagged(v.classification.value, v.proposed_action.value)}


def write_golden(path: Path, items: list[dict]) -> None:
    """Scrie setul de aur prin fisier temporar + os.replace: merge si cand versiunea veche e
    doar-citire (0440; write_text pe ea ar da PermissionError la a doua rulare) si nu lasa
    niciodata un fisier pe jumatate scris. La final, tot 0440 (setul nu se editeaza de mana)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text("".join(json.dumps(i, default=str) + "\n" for i in items))
    os.chmod(tmp, 0o440)
    os.replace(tmp, path)


def export() -> int:
    es = _es()
    r = es.search(index="verdicts-history", size=2000, query={"bool": {"filter": [
        {"term": {"label_source.keyword": "human"}}, {"exists": {"field": "ground_truth"}}]}},
        source=["ground_truth", "evidence_refs", "rule_name", "@timestamp"])
    items, missing = [], 0
    for h in r["hits"]["hits"]:
        s = h["_source"]
        ref = next((e for e in s.get("evidence_refs") or [] if str(e.get("index", "")).startswith(".")), None)
        alert = _alert(es, ref) if ref else None
        if alert is None:
            missing += 1
            continue
        items.append({"verdict_id": h["_id"], "ground_truth": s["ground_truth"], "alert": alert})
    write_golden(GOLDEN, items)
    b = balanced(items)
    print(f"{GOLDEN}: {len(items)} alerte ({b}); fara alerta in ES: {missing}; "
          f"sha256={hashlib.sha256(GOLDEN.read_bytes()).hexdigest()[:16]}")
    if not b["ok"]:
        print(f"ATENTIE: sub {MIN_PER_CLASS} pe clasa; eticheteaza mai multe alerte in interfata.")
    return 0


def _run_set(items: list[dict]) -> dict[str, dict]:
    from fast_path import build_fast_path
    fast = build_fast_path()
    out = {}
    for i, it in enumerate(items, 1):
        try:
            out[it["key"]] = triage_one(fast, it["alert"])
        except Exception as e:  # noqa: BLE001 — esecul e un rezultat (escaladeaza), nu o oprire
            out[it["key"]] = {"classification": "undetermined", "flagged": True, "error": str(e)[:200]}
        print(f"  {i}/{len(items)} {it['key'][:12]} -> {out[it['key']]['classification']}", flush=True)
    return out


def _metric_doc(type_: str, doc: dict) -> None:
    if os.environ.get("ES_METRICS_WRITER_API_KEY"):
        _es("ES_METRICS_WRITER_API_KEY").index(index="soc-metrics", document={
            "@timestamp": datetime.now(timezone.utc).isoformat(), "type": type_, **doc})


def run() -> int:
    import prompts
    from labeling import outcome
    items = [json.loads(l) for l in GOLDEN.read_text().splitlines() if l.strip()]
    for it in items:
        it["key"] = it["verdict_id"]
    t0 = time.monotonic()
    now = _run_set(items)
    rows = [{"ground_truth": it["ground_truth"],
             "outcome": outcome({"classification": now[it["key"]]["classification"],
                                 "proposed_action": "none" if not now[it["key"]]["flagged"] else "escalate_human"},
                                it["ground_truth"])} for it in items]
    m = metrics(rows)
    pset = prompts.prompt_set(prompts.current())
    model = os.environ.get("MODEL_FAST", "qwen3:14b").replace(":", "_")
    OUT.mkdir(parents=True, exist_ok=True)
    base_path = OUT / f"baseline_{pset}_{model}.json"
    base = json.loads(base_path.read_text()) if base_path.exists() else None
    ch = changed(base, now) if base else []
    if base is None:
        base_path.write_text(json.dumps(now, indent=1))
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rep = {"prompt_set": pset, "model": model, "golden_sha256": hashlib.sha256(GOLDEN.read_bytes()).hexdigest(),
           "balance": balanced(items), "metrics": m, "changed_vs_baseline": ch,
           "baseline": "creat acum" if base is None else base_path.name,
           "runtime_s": round(time.monotonic() - t0, 1)}
    (OUT / f"{ts}.json").write_text(json.dumps(rep, indent=1))
    (OUT / f"{ts}.md").write_text(
        f"# Regresie {ts}\n\nprompt_set {pset}, model {model}, set de aur {rep['golden_sha256'][:16]} "
        f"({rep['balance']})\n\n| TP | FP | FN | TN | precizie [IC 95%] | recall [IC 95%] | F1 atac "
        f"| FPR benign [IC 95%] |\n"
        f"|---|---|---|---|---|---|---|---|\n| {m['TP']} | {m['FP']} | {m['FN']} | {m['TN']} | "
        f"{fmt_ci(m['precision_attack'], m['precision_attack_ci95'])} | "
        f"{fmt_ci(m['recall_attack'], m['recall_attack_ci95'])} | {m['f1_attack']} | "
        f"{fmt_ci(m['fpr_benign'], m['fpr_benign_ci95'])} |\n\n"
        f"Intervale Wilson 95% (n mic -> intervale largi; nu se compara doar valorile punctuale).\n\n"
        f"Verdicte schimbate fata de baseline: {len(ch)}\n"
        + "".join(f"- {c['alert'][:12]}: {c['old']} -> {c['new']}\n" for c in ch))
    _metric_doc("regression", {"prompt_set": pset, **m, "changed_verdicts_count": len(ch)})
    print(json.dumps(rep["metrics"]), f"schimbate: {len(ch)}")
    return 0


def run_determinism(n: int) -> int:
    es = _es()
    r = es.search(index=".alerts-security.alerts-*", size=n, sort=[{"@timestamp": "desc"}])
    items = [{"key": h["_id"], "alert": h["_source"]} for h in r["hits"]["hits"]]
    a, b = _run_set(items), _run_set(items)
    d = determinism(a, b)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"determinism-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json").write_text(
        json.dumps({"result": d, "run_a": a, "run_b": b}, indent=1))
    _metric_doc("determinism", {k: v for k, v in d.items() if k != "diffs"} | {"diffs": len(d["diffs"])})
    print(json.dumps({k: v for k, v in d.items() if k != "diffs"}))
    return 0 if d["passed"] else 3


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=("export", "run", "determinism"))
    ap.add_argument("--n", type=int, default=40)
    a = ap.parse_args(argv)
    return {"export": export, "run": run}.get(a.mode, lambda: run_determinism(a.n))()


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
FAZA 7 — rata de acord A/B: acelasi model vs doua modele.

Pentru fiecare scenariu din setul dev (calea lenta): telemetria se genereaza O
SINGURA DATA pe web-prod, apoi pe acelasi finding ruleaza, independent:
  A      = investigatorul primar (rolul `hunt`, Qwen3 14B)
  B_qwen = investigatorul secundar pe acelasi model (configuratia de azi)
  B_red  = investigatorul secundar pe RedSage-Qwen3-8B (MODEL_HUNT_B / LLM_BASE_URL_HUNT_B)
B ruleaza aici pe TOATE cazurile, nu doar in zona gri (suport = 2), ca acordul
sa se poata masura pe acelasi set. Productia nu se schimba prin acest script.

Masuri: acord pe clasificare (A vs B_qwen, A vs B_red), corectitudine fata de
eticheta, si corelarea erorilor: cand A greseste, greseste si B?

    source env.sh
    MODEL_HUNT_B=... LLM_BASE_URL_HUNT_B=http://localhost:11435/v1 \
        python3 -u experiments/ab_agreement.py | tee results/ab-faza7-$(date +%F-%H%M).txt
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

import hunt_path  # noqa: E402
from elastic_tools import HUNT_TOOLS  # noqa: E402
from llm import ROLES  # noqa: E402
from schemas import EntityType, RarityFinding  # noqa: E402

from langchain_openai import ChatOpenAI  # noqa: E402

FLAGGED = {"suspicious", "malicious"}


def _llm(model: str, base: str, role: str = "hunt_b"):
    cfg = ROLES[role]
    return ChatOpenAI(model=model, base_url=base, api_key="local", temperature=cfg["temperature"],
                      max_tokens=cfg["max_tokens"], timeout=300).bind_tools(HUNT_TOOLS)


def _run(inv, finding, note) -> dict:
    t0 = time.monotonic()
    try:
        res = inv.invoke({"finding": finding, "role_note": note}, config={"recursion_limit": 40})
        d = res.get("draft", {}) or {}
        return {"cls": d.get("classification", "undetermined"), "conf": d.get("confidence"),
                "support": hunt_path.support_score(d), "tools": res.get("tool_calls_made", 0),
                "s": round(time.monotonic() - t0), "err": None}
    except Exception as e:
        return {"cls": "error", "conf": None, "support": 0, "tools": 0,
                "s": round(time.monotonic() - t0), "err": type(e).__name__}


def main() -> int:
    qwen = os.environ.get("MODEL_HUNT", "qwen3:14b")
    base_q = os.environ.get("LLM_BASE_URL_HUNT") or os.environ.get("LLM_BASE_URL", "http://localhost:11434/v1")
    red = os.environ["MODEL_HUNT_B"]
    base_r = os.environ["LLM_BASE_URL_HUNT_B"]
    inv_a = hunt_path.INVESTIGATOR_A                                   # rolul hunt, ca in productie
    inv_bq = hunt_path._build_investigator(_llm(qwen, base_q))
    inv_br = hunt_path._build_investigator(_llm(red, base_r))
    host = os.environ.get("WEB_PROD_HOST", "tiberiu@172.20.99.240")

    scenarios = yaml.safe_load((ROOT / "scenarios.yml").read_text(encoding="utf-8"))["scenarios"]
    rows = []
    for i, sc in enumerate(scenarios, 1):
        print(f"[{i}/{len(scenarios)}] {sc['name']} (adevar: {sc['ground_truth']})", flush=True)
        if sc.get("generate"):
            subprocess.run(["ssh", host, sc["generate"]], check=False, capture_output=True, timeout=30)
            time.sleep(45)
        d = sc["finding"]
        f = RarityFinding(kind=d.get("kind", "new_parent_child"), entity_type=EntityType.HOST,
                          entity_id=d["host"], detail=d["detail"], rarity_score=d.get("rarity_score", 1.0))
        r = {"name": sc["name"], "gt": sc["ground_truth"],
             "A": _run(inv_a, f, hunt_path.PRIMARY_NOTE),
             "Bq": _run(inv_bq, f, hunt_path.SECONDARY_NOTE),
             "Br": _run(inv_br, f, hunt_path.SECONDARY_NOTE)}
        for k in ("A", "Bq", "Br"):
            x = r[k]
            print(f"    {k:2s}: {x['cls']}/{x['conf']} suport={x['support']} unelte={x['tools']} {x['s']}s"
                  + (f" EROARE {x['err']}" if x["err"] else ""), flush=True)
        rows.append(r)

    def correct(x, gt):
        flagged = x["cls"] in FLAGGED or x["cls"] in ("undetermined", "error")   # incertul escaladeaza
        return flagged if gt == "attack" else not flagged

    def agree(a, b):
        return a["cls"] == b["cls"] and a["cls"] not in ("undetermined", "error")

    n = len(rows)
    print("\n" + "=" * 60)
    for k, name in (("A", "A (Qwen3)"), ("Bq", "B pe Qwen3"), ("Br", "B pe RedSage")):
        c = sum(correct(r[k], r["gt"]) for r in rows)
        err = sum(r[k]["err"] is not None for r in rows)
        und = sum(r[k]["cls"] == "undetermined" for r in rows)
        t = sum(r[k]["s"] for r in rows) / n
        print(f"{name:14s} corect {c}/{n}  undetermined {und}  erori {err}  timp mediu {t:.0f}s")
    for k, name in (("Bq", "un model (A vs B_qwen)"), ("Br", "doua modele (A vs B_red)")):
        ag = sum(agree(r["A"], r[k]) for r in rows)
        a_wrong = [r for r in rows if not correct(r["A"], r["gt"])]
        both = sum(not correct(r[k], r["gt"]) for r in a_wrong)
        print(f"ACORD {name}: {ag}/{n}  | cand A greseste ({len(a_wrong)}), B greseste si el: {both}")
    (ROOT / "results").mkdir(exist_ok=True)
    print("\nJSON:", json.dumps(rows, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

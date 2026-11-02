"""
REZULTATELE PORTILOR IN soc-metrics (plann.md A5). harness.py scrie la final un document
type=gate: set, matrice, recall, rata FP, commit, prompt_set, model. Teza are curbe, nu capturi.
Scrierea e optionala (cheia ES_METRICS_WRITER_API_KEY) si nu opreste niciodata harness-ul; un
JSON identic se scrie mereu in results/.
"""
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def gate_summary(scenario_set: str, confusion: dict, results: list[tuple], *, commit: str | None,
                 prompt_set: str | None, model_tag: str, started: datetime, finished: datetime) -> dict:
    """Pur. results: (nume, adevar, clasificare, incredere, TP/FN/TN/FP)."""
    tp, fn, tn, fp = (int(confusion.get(k, 0)) for k in ("TP", "FN", "TN", "FP"))
    attacks, benigns = tp + fn, tn + fp
    return {
        "@timestamp": finished.isoformat(), "type": "gate", "scenario_set": scenario_set,
        "scenarios": tp + fn + tn + fp, "TP": tp, "FN": fn, "TN": tn, "FP": fp,
        "recall": round(tp / attacks, 4) if attacks else None,
        "fp_rate": round(fp / benigns, 4) if benigns else None,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "passed": fn == 0,
        "missed": [r[0] for r in results if r[4] == "FN"],
        "false_positives": [r[0] for r in results if r[4] == "FP"],
        "commit": commit, "prompt_set": prompt_set, "model_tag": model_tag,
        "duration_s": round((finished - started).total_seconds(), 1),
    }


def git_commit() -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True,
                              timeout=5, cwd=Path(__file__).resolve().parent).stdout.strip() or None
    except Exception:  # noqa: BLE001
        return None


def current_prompt_set() -> str | None:
    try:
        import prompts
        return prompts.prompt_set(prompts.current())
    except Exception:  # noqa: BLE001
        return None


def persist(doc: dict, results_dir: Path) -> str | None:
    """JSON in results/ (mereu) + soc-metrics (daca exista cheia). Intoarce eroarea sau None."""
    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M")
    (results_dir / f"gate-{doc['scenario_set']}-{stamp}.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=1))
    key = os.environ.get("ES_METRICS_WRITER_API_KEY")
    if not key:
        return "fara ES_METRICS_WRITER_API_KEY (doar fisier)"
    try:
        from elasticsearch import Elasticsearch
        Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"), api_key=key,
                      request_timeout=30).index(index="soc-metrics", document=doc)
        return None
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {str(e)[:120]}"

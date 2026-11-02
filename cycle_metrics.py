"""
METRICI PER CICLU (pasul 7.2) — un document soc-metrics type=cycle la sfarsitul fiecarui
ciclu al orchestratorului. Din ele: dashboard-ul "SOC Health" si alertele de absenta din
absence_check (orchestrator blocat / lent).

Functie pura (build_cycle_doc) + scriere care nu arunca: o eroare de metrici nu opreste
bucla (R9 se aplica alertelor, nu observabilitatii).
"""
from __future__ import annotations

import os
from datetime import datetime

INDEX = "soc-metrics"


def build_cycle_doc(*, cycle: int, cycle_id: str, started: datetime, ended: datetime,
                    alerts_fetched: int, stats: dict, llm: dict, backlog: bool,
                    sweep_ran: bool, interval_s: int) -> dict:
    total = int(stats.get("total", 0))
    escalated = int(stats.get("escalated", 0))
    failures = {k[5:]: int(v) for k, v in stats.items() if k.startswith("fail_") and v}
    return {
        "@timestamp": ended.isoformat(), "type": "cycle", "cycle": cycle, "cycle_id": cycle_id,
        "duration_s": round((ended - started).total_seconds(), 2), "interval_s": interval_s,
        "queue_depth": alerts_fetched, "alerts_fetched": alerts_fetched,
        "alerts_processed": total, "closed_t1": total - escalated, "escalated": escalated,
        "escalated_t2": int(stats.get("tier2", 0)),
        "escalated_human_only": int(stats.get("tier2_skipped", 0)),
        "no_model": int(stats.get("no_model", 0)),
        "honeytoken_hits": int(stats.get("honeytoken_hits", 0)),
        "model_timeouts": failures.get("case_timeout", 0),
        "model_errors": failures.get("model_unavailable", 0) + failures.get("processing_error", 0),
        "failures": failures,
        "escalation_rate": round(escalated / total, 4) if total else None,
        "llm_calls": int(llm.get("llm_calls", 0)), "tokens": int(llm.get("tokens", 0)),
        "llm_ms": int(llm.get("llm_ms", 0)),
        "backlog": backlog, "sweep_ran": sweep_ran,
        "shadow": os.environ.get("SHADOW_MODE", "").lower() == "true",
        "model_tag": os.environ.get("MODEL_FAST", "qwen3:14b"),
    }


def write(es, doc: dict) -> str | None:
    """Scrie documentul; intoarce eroarea (text scurt) sau None. Nu arunca."""
    if es is None:
        return "fara client de scriere"
    try:
        es.index(index=INDEX, document=doc)
        return None
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {str(e)[:120]}"

#!/usr/bin/env python3
"""
SONDA LLM (pasul 7.4) — tunelul spre GPU si modelul, masurate din exterior.

La fiecare minut (soc-llm-probe.timer): GET /api/tags pe Ollama (prin tunel, timeout 5 s) ->
ok, latenta, modelele; modelul configurat trebuie sa fie printre ele. La fiecare
GEN_EVERY_MIN minute, si o generare minima (5 tokeni) -> latenta reala a modelului.
Scrie soc-metrics type=llm_probe la fiecare rulare.

FAIL_LIMIT esecuri consecutive -> integrity_alert kind=llm_tunnel_down in soc-incidents +
Discord (prin absence_check.Run, aceleasi garantii si dedup). Starea (esecuri consecutive)
sta local in data/llm_probe.json. Tacerea sondei insesi o prinde absence_check (probe_missing).

Generarea foloseste acelasi GPU ca orchestratorul si harness-ul: 5 tokeni la 5 minute,
neglijabil. Nimic nu se executa pe hosturi.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s",
                    stream=sys.stderr)
log = logging.getLogger("soc.llm_probe")

ROOT = Path(__file__).resolve().parent
STATE = Path(os.environ.get("LLM_PROBE_STATE", str(ROOT / "data" / "llm_probe.json")))
TAGS_TIMEOUT_S = 5
GEN_TIMEOUT_S = 60
GEN_EVERY_MIN = int(os.environ.get("LLM_PROBE_GEN_EVERY_MIN", "5"))
FAIL_LIMIT = 3


def native_base(openai_url: str) -> str:
    """http://localhost:11434/v1 -> http://localhost:11434 (API-ul nativ Ollama)."""
    u = openai_url.rstrip("/")
    return u[:-3] if u.endswith("/v1") else u


def model_and_base() -> tuple[str, str]:
    from llm import base_url, model_name
    return model_name("fast"), native_base(base_url("fast"))


def evaluate(tags: dict | None, model: str) -> tuple[bool, list[str], str | None]:
    """(ok, modele, motiv). ok doar daca raspunsul e valid SI modelul e incarcabil. Pur."""
    if tags is None:
        return False, [], "fara raspuns"
    names = sorted(m.get("name", "") for m in tags.get("models", []) if isinstance(m, dict))
    if model not in names:
        return False, names, f"modelul {model} lipseste"
    return True, names, None


def next_failures(prev: int, ok: bool) -> int:
    return 0 if ok else prev + 1


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except Exception:  # noqa: BLE001
        return {"failures": 0}


def save_state(st: dict) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(st))
    tmp.replace(STATE)


def main() -> int:
    now = datetime.now(timezone.utc)
    model, base = model_and_base()
    doc = {"@timestamp": now.isoformat(), "type": "llm_probe", "model_tag": model}
    t0 = time.monotonic()
    tags, err = None, None
    try:
        r = requests.get(f"{base}/api/tags", timeout=TAGS_TIMEOUT_S)
        r.raise_for_status()
        tags = r.json()
    except Exception as e:  # noqa: BLE001
        err = f"{type(e).__name__}: {str(e)[:150]}"
    doc["latency_ms"] = int((time.monotonic() - t0) * 1000)
    ok, names, why = evaluate(tags, model)
    doc.update({"ok": ok, "models": names, "error": err or why})

    if ok and GEN_EVERY_MIN > 0 and now.minute % GEN_EVERY_MIN == 0:
        t1 = time.monotonic()
        try:
            g = requests.post(f"{base}/api/generate", timeout=GEN_TIMEOUT_S, json={
                "model": model, "prompt": "ping", "stream": False, "think": False,
                "options": {"num_predict": 5, "temperature": 0}})
            g.raise_for_status()
            doc["gen_latency_ms"] = int((time.monotonic() - t1) * 1000)
            doc["gen_eval_count"] = g.json().get("eval_count")
        except Exception as e:  # noqa: BLE001
            doc.update({"ok": False, "error": f"generare: {type(e).__name__}: {str(e)[:150]}"})
            ok = False

    st = load_state()
    st["failures"] = next_failures(int(st.get("failures", 0)), ok)
    doc["consecutive_failures"] = st["failures"]
    save_state(st)

    import absence_check as A
    run = A.Run(now, A._client("ES_INCIDENTS_WRITER_API_KEY", False))
    if st["failures"] >= FAIL_LIMIT:
        run.problem(A.IntegrityKind.LLM_TUNNEL_DOWN, "Tunelul LLM / modelul nu raspunde",
                    f"{st['failures']} sonde consecutive esuate ({doc['error']}). Orchestratorul "
                    "trece pe modul degradat (escaladeaza fara model). Verifica soc-llm-tunnel si GPU-ul.",
                    severity="critical", host="es-node-1", subject="soc-llm-tunnel",
                    dedup_minutes=30)
    met = A._client("ES_METRICS_WRITER_API_KEY", False)
    if met is None:
        log.error("ES_METRICS_WRITER_API_KEY lipsa: sonda nescrisa")
        return 1
    try:
        met.index(index=A.METRICS_IDX, document=doc)
    except Exception as e:  # noqa: BLE001
        log.error("scriere sonda esuata: %s", e)
        return 1
    log.info("ok=%s latenta=%s ms gen=%s ms esecuri=%d %s", doc["ok"], doc["latency_ms"],
             doc.get("gen_latency_ms"), st["failures"], doc["error"] or "")
    return 1 if run.failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        log.exception("llm_probe a esuat: %s", e)
        sys.exit(1)

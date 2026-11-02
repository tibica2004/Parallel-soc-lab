#!/usr/bin/env python3
"""
ACOPERIRE ATT&CK (pasul 5.3) — ce a vazut SOC-ul din fiecare test Atomic Red Team rulat de om.

Sursa: logs-soc.emulation-* (art_runner.py pe web-prod -> /var/log/soc/emulation.ndjson -> Fleet).
Pentru fiecare rulare (pereche art_start/art_end dupa run_id), fereastra [start, end + 5 min]:
  detected    — cel putin o alerta pe web-prod in fereastra (numele regulilor pastrate);
  logged_only — nicio alerta, dar evenimente de proces/auditd pe web-prod in fereastra;
  unseen      — nici alerta, nici eveniment.
Verdictul SOC: verdictele din verdicts-history pentru regulile acelor alerte, in fereastra + 15 min.

Atributia e pe fereastra de timp si host: in timpul sesiunii ART opreste benign-gen, harness-ul si
OpenClaw, altfel alertele lor intra in fereastra (scrie asta si in raport).

Iesire: data/coverage/navigator-layer.json (ATT&CK Navigator 4.5: 2 detectat / 1 doar logat /
0 nevazut), data/coverage/gap_list.json (pentru Tier 3), soc-metrics type=coverage.
Chei: ES_READER_API_KEY (citire), ES_METRICS_WRITER_API_KEY.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s",
                    stream=sys.stderr)
log = logging.getLogger("soc.coverage")

ROOT = Path(__file__).resolve().parent
OUT = Path(os.environ.get("COVERAGE_OUT", str(ROOT / "data" / "coverage")))
EMU_IDX = "logs-soc.emulation-*"
ALERTS = ".alerts-security.alerts-*"
EVENTS = ["logs-endpoint.events.process-*", "logs-auditd_manager.auditd-*"]
HOST = os.environ.get("COVERAGE_HOST", "web-prod")
AFTER = timedelta(minutes=5)
NO_END = timedelta(minutes=10)
VERDICT_AFTER = timedelta(minutes=15)
SCORE = {"detected": 2, "logged_only": 1, "unseen": 0}
COLOR = {"detected": "#2e7d32", "logged_only": "#f9a825", "unseen": "#c62828"}


# =============================================================================
# FUNCTII PURE
# =============================================================================

def _ts(v) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def pair_runs(docs: list[dict]) -> list[dict]:
    """art_start + art_end dupa run_id -> rulari cu fereastra. Fara end: start + 10 min."""
    runs: dict[str, dict] = {}
    for d in docs:
        rid = d.get("run_id")
        t = _ts(d.get("@timestamp"))
        if not rid or t is None:
            continue
        r = runs.setdefault(rid, {"run_id": rid})
        if d.get("event") == "art_start":
            r.update(technique_id=d.get("technique_id"), test_number=d.get("test_number"),
                     test_name=d.get("test_name"), executor_user=d.get("executor_user"), start=t)
        elif d.get("event") == "art_end":
            r.update(end=t, cleanup_ok=d.get("cleanup_ok"), exit_code=d.get("exit_code"))
    out = []
    for r in runs.values():
        if "start" not in r or not r.get("technique_id"):
            continue
        r["window_end"] = (r.get("end") or (r["start"] + NO_END)) + AFTER
        out.append(r)
    return sorted(out, key=lambda r: r["start"])


def classify(n_alerts: int, n_events: int) -> str:
    return "detected" if n_alerts else ("logged_only" if n_events else "unseen")


def per_technique(results: list[dict]) -> dict[str, str]:
    """O tehnica cu mai multe teste ia cel mai bun status (detectat > logat > nevazut)."""
    best: dict[str, str] = {}
    for r in results:
        t, s = r["technique_id"], r["status"]
        if t not in best or SCORE[s] > SCORE[best[t]]:
            best[t] = s
    return best


def navigator_layer(results: list[dict]) -> dict:
    by_t = per_technique(results)
    techniques = []
    for t, s in sorted(by_t.items()):
        rules = sorted({n for r in results if r["technique_id"] == t for n in r.get("rule_names", [])})
        techniques.append({"techniqueID": t, "score": SCORE[s], "color": COLOR[s],
                           "comment": f"{s}; reguli: {', '.join(rules) or '-'}"[:500],
                           "enabled": True})
    return {"name": "SOC web-prod — acoperire Atomic Red Team", "domain": "enterprise-attack",
            "versions": {"layer": "4.5", "navigator": "4.9.1", "attack": "15"},
            "description": "2 = alerta, 1 = doar evenimente, 0 = nevazut. Generat de coverage.py.",
            "gradient": {"colors": [COLOR["unseen"], COLOR["logged_only"], COLOR["detected"]],
                         "minValue": 0, "maxValue": 2},
            "techniques": techniques}


def summary(results: list[dict]) -> dict:
    by_t = per_technique(results)
    n = len(by_t)
    cnt = {s: sum(1 for v in by_t.values() if v == s) for s in SCORE}
    tta = [r["time_to_alert_s"] for r in results if r.get("time_to_alert_s") is not None]
    return {"techniques_tested": n, "tests_run": len(results),
            "pct_detected": round(100 * cnt["detected"] / n, 1) if n else 0.0,
            "pct_logged_only": round(100 * cnt["logged_only"] / n, 1) if n else 0.0,
            "pct_unseen": round(100 * cnt["unseen"] / n, 1) if n else 0.0,
            "mean_time_to_alert_s": round(sum(tta) / len(tta), 1) if tta else None,
            "cleanup_failed": [r["run_id"] for r in results if r.get("cleanup_ok") is False]}


def gap_list(results: list[dict]) -> list[dict]:
    """Tehnicile nevazute sau doar logate (cel mai bun status), pentru ipotezele Tier 3."""
    by_t = per_technique(results)
    return [{"technique_id": t, "status": s,
             "tests": [r["test_number"] for r in results if r["technique_id"] == t],
             "events_seen": sum(r.get("n_events", 0) for r in results if r["technique_id"] == t)}
            for t, s in sorted(by_t.items()) if s != "detected"]


# =============================================================================
# EFECTE
# =============================================================================

def _client(var: str):
    from elasticsearch import Elasticsearch
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                         api_key=os.environ[var], request_timeout=60)


def _range(start: datetime, end: datetime) -> dict:
    return {"range": {"@timestamp": {"gte": start.isoformat(), "lte": end.isoformat()}}}


def measure(es, run: dict) -> dict:
    host = {"term": {"host.name": HOST}}
    win = _range(run["start"], run["window_end"])
    a = es.search(index=ALERTS, size=200, query={"bool": {"filter": [host, win]}},
                  source=["@timestamp", "kibana.alert.rule.name"], sort=[{"@timestamp": "asc"}])
    hits = a["hits"]["hits"]
    rules = sorted({(h["_source"].get("kibana.alert.rule.name")
                     or ((h["_source"].get("kibana") or {}).get("alert") or {}).get("rule", {}).get("name"))
                    for h in hits} - {None})
    first = _ts(hits[0]["_source"]["@timestamp"]) if hits else None
    ev = es.count(index=",".join(EVENTS), query={"bool": {"filter": [host, win]}},
                  ignore_unavailable=True)["count"]
    verdicts = []
    if rules:
        v = es.search(index="verdicts-history", size=50, query={"bool": {"filter": [
            {"terms": {"rule_name.keyword": rules}},
            _range(run["start"], run["window_end"] + VERDICT_AFTER)]}},
            source=["classification"], ignore_unavailable=True)
        verdicts = sorted({h["_source"].get("classification") for h in v["hits"]["hits"]} - {None})
    return {**run, "status": classify(len(hits), ev), "n_alerts": len(hits), "n_events": ev,
            "rule_names": rules, "soc_verdicts": verdicts,
            "time_to_alert_s": round((first - run["start"]).total_seconds(), 1) if first else None}


def main() -> int:
    try:
        es = _client("ES_READER_API_KEY")
        docs = [h["_source"] for h in es.search(index=EMU_IDX, size=2000, sort=[{"@timestamp": "asc"}],
                                                ignore_unavailable=True)["hits"]["hits"]]
        runs = pair_runs(docs)
        if not runs:
            log.warning("nicio rulare ART in %s", EMU_IDX)
            return 0
        results = [measure(es, r) for r in runs]
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "navigator-layer.json").write_text(json.dumps(navigator_layer(results), indent=1))
        (OUT / "gap_list.json").write_text(json.dumps(gap_list(results), indent=1))
        ser = [{k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in r.items()} for r in results]
        (OUT / "results.json").write_text(json.dumps(ser, indent=1, ensure_ascii=False))
        s = summary(results)
        if os.environ.get("ES_METRICS_WRITER_API_KEY"):
            _client("ES_METRICS_WRITER_API_KEY").index(index="soc-metrics", document={
                "@timestamp": datetime.now(timezone.utc).isoformat(), "type": "coverage", **s})
        log.info("acoperire: %s", json.dumps(s))
        return 0
    except Exception as e:  # noqa: BLE001
        log.exception("coverage a esuat: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
ORCHESTRATOR — pasul 1: DOAR AFISARE (dry-run).

Citeste alertele noi si, optional, ruleaza sweep-ul. Ruteaza fiecare pe calea
potrivita (alerta -> rapida, finding -> lenta) si TIPARESTE ce ar face. Nu scrie
nimic: nici verdicte, nici audit, nici pozitie. Zero risc.

Scopul: sa vezi cum se comporta sistemul pe fluxul real inainte sa-i dai voie
sa scrie. Motorul de politici si scrierea vin in pasul 2, rularea automata in 3.

    export ES_API_KEY=<read-only>  ES_URL=...  LLM_BASE_URL=...
    python3 orchestrator.py                 # alerte din ultimele 60 min
    python3 orchestrator.py --minutes 30
    python3 orchestrator.py --sweep         # si un ciclu de sweep
    python3 orchestrator.py --limit 5       # cel mult 5 elemente (util la debug)
"""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone

from policy import decide
from state import load_cursor, save_cursor, window_end

from elasticsearch import Elasticsearch

ES = Elasticsearch(
    os.environ.get("ES_URL", "http://localhost:9200"),
    api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"],
    request_timeout=60,
)

ALERTS_IDX = ".alerts-security.alerts-*"
AUDIT_IDX = "soc-audit"
VERDICTS_IDX = "verdicts-history"

# Client separat DOAR pentru scriere in audit + verdicte. Cheia lui poate scrie
# doar in aceste indici; nu poate atinge logurile sau alertele. In dry-run e None.
WRITER = None
_wk = os.environ.get("ES_WRITER_API_KEY")
if _wk:
    WRITER = Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                           api_key=_wk, request_timeout=30)


def _g(d: dict, path: str):
    if path in d:
        return d[path]
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def fetch_alerts_between(since, until, limit: int) -> list[dict]:
    """Alertele deschise din intervalul (since, until], cele mai vechi intai."""
    r = ES.search(index=ALERTS_IDX, size=limit,
                  sort=[{"@timestamp": "asc"}],
                  query={"bool": {"filter": [
                      {"range": {"@timestamp": {"gte": since.isoformat(),
                                                "lte": until.isoformat()}}},
                  ], "must_not": [
                      {"term": {"kibana.alert.workflow_status": "closed"}},
                  ]}})
    return [h["_source"] for h in r["hits"]["hits"]]


def fetch_new_alerts(minutes: int, limit: int) -> list[dict]:
    """Varianta manuala: ultimele N minute, fara pozitie."""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    return fetch_alerts_between(now - timedelta(minutes=minutes), now, limit)


def dedup_key_alert(a: dict) -> str:
    """Doua alerte de la aceeasi regula, pe aceeasi entitate de proces, sunt
    acelasi caz — nu-l investigam de doua ori."""
    return "|".join(str(x) for x in [
        _g(a, "kibana.alert.rule.name"),
        _g(a, "host.name"),
        _g(a, "process.entity_id") or _g(a, "file.path") or "",
    ])


def dedup_key_finding(f) -> str:
    d = f.detail or {}
    return f"finding|{f.entity_id}|{d.get('parent')}|{d.get('child')}"




def persist(verdict, narrative: str, decision, started, finished, extra: dict | None = None) -> None:
    """Scrie verdictul in istoric si o inregistrare de audit. ground_truth ramane
    GOL — doar omul il completeaza. Fara cheie de writer (dry-run), nu scrie nimic."""
    if WRITER is None:
        return
    from schemas import AuditRecord
    vdoc = verdict.model_dump(mode="json")
    vdoc["@timestamp"] = finished.isoformat()
    vdoc["ground_truth"] = None            # NICIODATA setat automat
    vdoc["rule_name"] = (extra or {}).get("rule_name")
    WRITER.index(index=VERDICTS_IDX, document=vdoc)

    audit = AuditRecord(
        investigation_id=verdict.investigation_id, verdict=verdict, narrative=narrative,
        hypotheses_considered=(extra or {}).get("hypotheses", []),
        queries_run=(extra or {}).get("queries_run", []),
        policy_decision=f"{decision.chosen.value}: {decision.reason}",
        action_executed=decision.chosen,
        action_result="shadow: nu s-a executat" if decision.shadow_mode else "executat",
        started_at=started, finished_at=finished, shadow_mode=decision.shadow_mode,
    )
    adoc = audit.model_dump(mode="json")
    adoc["@timestamp"] = finished.isoformat()
    WRITER.index(index=AUDIT_IDX, document=adoc)


def show(kind: str, entity: str, verdict, narrative: str, decision=None) -> None:
    print(f"  [{kind}] {entity}")
    print(f"    verdict: {verdict.classification.value} / {verdict.confidence} / "
          f"{verdict.proposed_action.value}"
          + (f" pe {verdict.action_target}" if verdict.action_target else ""))
    if decision is not None:
        mark = "SHADOW" if decision.shadow_mode else ("EXECUTAT" if decision.executed else "-")
        print(f"    politica: {decision.chosen.value}  [{mark}]  ({decision.reason})")
    if verdict.mitre_techniques:
        print(f"    MITRE: {', '.join(verdict.mitre_techniques)}")
    if narrative:
        print(f"    {narrative[:180]}")




from collections import OrderedDict


class BoundedSeen:
    """Chei deja procesate, cu memorie limitata: un proces care ruleaza saptamani
    nu trebuie sa creasca la nesfarsit. Se uita cele mai vechi."""
    def __init__(self, maxlen: int = 5000):
        self._d: OrderedDict = OrderedDict()
        self.maxlen = maxlen

    def __contains__(self, k) -> bool:
        return k in self._d

    def add(self, k) -> None:
        self._d[k] = None
        self._d.move_to_end(k)
        if len(self._d) > self.maxlen:
            self._d.popitem(last=False)


def process_findings(findings, seen, limit: int) -> None:
    """Findings de raritate -> calea lenta -> politica -> audit."""
    from hunt_path import build_hunt_path
    hunt = build_hunt_path()
    print(f"  FINDINGS: {len(findings)} (procesez cel mult {limit})", flush=True)
    done = 0
    for f in findings:
        if done >= limit:
            break
        k = dedup_key_finding(f)
        entity = f"{f.entity_id} · {(f.detail or {}).get('parent')} -> {(f.detail or {}).get('child')}"
        if k in seen:
            continue
        seen.add(k)
        done += 1
        try:
            t0 = datetime.now(timezone.utc)
            out = hunt.invoke({"finding": f}, config={"recursion_limit": 80})
            t1 = datetime.now(timezone.utc)
            v = out["verdict"]; d = decide(v)
            show("LENT", entity, v, out.get("narrative", ""), d)
            persist(v, out.get("narrative", ""), d, t0, t1,
                    {"hypotheses": out.get("hypotheses", []), "queries_run": out.get("queries_run", [])})
        except Exception as e:
            print(f"  [EROARE, ar escalada la om] {entity}: {e}", flush=True)


def run_positioned(args) -> int:
    """Mod autonom. La fiecare ciclu: alertele de la pozitie pana la (acum - lag),
    apoi, la fiecare `sweep_every` cicluri, sweep-ul pe calea lenta. O eroare
    intr-un ciclu (Elasticsearch cazut, model indisponibil) nu opreste bucla."""
    import time
    seen = BoundedSeen()
    cycle = 0
    while True:
        cycle += 1
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            since, until = load_cursor(), window_end()
            alerts = fetch_alerts_between(since, until, args.limit)
            print(f"[{stamp}] ciclu {cycle}: {len(alerts)} alerte in "
                  f"[{since.strftime('%H:%M:%S')}, {until.strftime('%H:%M:%S')}]", flush=True)
            last_ts = process_alerts(alerts, seen)
            if len(alerts) >= args.limit and last_ts:
                # fereastra nu s-a golit: continuam exact de la ultima alerta
                save_cursor(datetime.fromisoformat(last_ts.replace("Z", "+00:00")))
            else:
                save_cursor(until)   # fereastra golita (sau goala): avansam

            run_sweep = (args.sweep if not args.loop
                         else args.sweep_every > 0 and (cycle - 1) % args.sweep_every == 0)
            if run_sweep:
                from elastic_tools import sweep_new_parent_child
                process_findings(sweep_new_parent_child(1), seen, args.hunt_limit)
        except Exception as e:
            print(f"[{stamp}] EROARE in ciclul {cycle}: {e} — continui", flush=True)

        if not args.loop:
            break
        time.sleep(args.interval)
    return 0


def process_alerts(alerts: list[dict], seen: set) -> str | None:
    """Trece fiecare alerta prin calea rapida + politica + audit.
    Intoarce @timestamp-ul ultimei alerte (pentru avansarea pozitiei)."""
    from fast_path import build_fast_path
    fast = build_fast_path()
    last_ts = None
    for a in alerts:
        last_ts = _g(a, "@timestamp") or last_ts
        k = dedup_key_alert(a)
        rule = _g(a, "kibana.alert.rule.name")
        entity = f"{_g(a, 'host.name')} · {rule}"
        if k in seen:
            print(f"  [duplicat, sarit] {entity}")
            continue
        seen.add(k)
        try:
            t0 = datetime.now(timezone.utc)
            out = fast.invoke({"alert": a}, config={"recursion_limit": 25})
            t1 = datetime.now(timezone.utc)
            v = out["verdict"]; d = decide(v)
            show("RAPID", entity, v, out.get("narrative", ""), d)
            persist(v, out.get("narrative", ""), d, t0, t1, {"rule_name": rule})
        except Exception as e:
            print(f"  [EROARE, ar escalada la om] {entity}: {e}")
        print()
    return last_ts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=int, default=60, help="rulare manuala: ultimele N min")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--once", action="store_true", help="un ciclu folosind pozitia, apoi iesi")
    ap.add_argument("--loop", action="store_true", help="cicluri la interval, folosind pozitia")
    ap.add_argument("--interval", type=int, default=120, help="secunde intre cicluri in --loop")
    ap.add_argument("--sweep-every", type=int, default=30,
                    help="in --loop: sweep la fiecare N cicluri (30 x 120s = o ora); 0 = niciodata")
    ap.add_argument("--hunt-limit", type=int, default=5,
                    help="cate findings investigheaza calea lenta pe ciclu (fiecare ~1 min)")
    args = ap.parse_args()

    if args.once or args.loop:
        return run_positioned(args)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    mode = ("SCRIE audit+verdicte" if WRITER is not None else "DRY-RUN, nu scrie nimic")
    shadow = os.environ.get("SHADOW_MODE", "true").lower() != "false"
    print(f"=== Orchestrator {stamp} | {mode} | shadow={shadow} ===\n")

    seen: set[str] = set()

    # --- Alerte -> calea rapida ---
    from fast_path import build_fast_path
    fast = build_fast_path()
    alerts = fetch_new_alerts(args.minutes, args.limit)
    print(f"ALERTE: {len(alerts)} in ultimele {args.minutes} min\n")
    for a in alerts:
        k = dedup_key_alert(a)
        rule = _g(a, "kibana.alert.rule.name")
        entity = f"{_g(a, 'host.name')} · {rule}"
        if k in seen:
            print(f"  [duplicat, sarit] {entity}")
            continue
        seen.add(k)
        try:
            t0 = datetime.now(timezone.utc)
            out = fast.invoke({"alert": a}, config={"recursion_limit": 25})
            t1 = datetime.now(timezone.utc)
            v = out["verdict"]
            d = decide(v)
            show("RAPID", entity, v, out.get("narrative", ""), d)
            persist(v, out.get("narrative", ""), d, t0, t1, {"rule_name": rule})
        except Exception as e:
            print(f"  [EROARE, ar escalada la om] {entity}: {e}")
        print()

    # --- Sweep -> calea lenta ---
    if args.sweep:
        from elastic_tools import sweep_new_parent_child
        from hunt_path import build_hunt_path
        hunt = build_hunt_path()
        findings = sweep_new_parent_child(1)
        print(f"\nFINDINGS de raritate: {len(findings)}\n")
        for f in findings[:args.limit]:
            k = dedup_key_finding(f)
            entity = f"{f.entity_id} · {(f.detail or {}).get('parent')} -> {(f.detail or {}).get('child')}"
            if k in seen:
                print(f"  [duplicat, sarit] {entity}")
                continue
            seen.add(k)
            try:
                out = hunt.invoke({"finding": f}, config={"recursion_limit": 80})
                show("LENT", entity, out["verdict"], out.get("narrative", ""))
            except Exception as e:
                print(f"  [EROARE, ar escalada la om] {entity}: {e}")
            print()

    if WRITER is None:
        print("=== Sfarsit. DRY-RUN: nimic nu a fost scris. ===")
    else:
        print("=== Sfarsit. Verdicte si audit scrise (ground_truth gol). ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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
import time
import uuid
from datetime import datetime, timezone

import degraded
import tracing
from escalation import EscalationDecision, should_escalate
from policy import decide
from state import load_cursor, load_seen, save_cursor, save_seen, window_end

from elasticsearch import Elasticsearch

ES = Elasticsearch(
    os.environ.get("ES_URL", "http://localhost:9200"),
    api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"],
    request_timeout=60,
)

ALERTS_IDX = ".alerts-security.alerts-*"
AUDIT_IDX = "soc-audit"
VERDICTS_IDX = "verdicts-history"
TRACES_IDX = "soc-traces"

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
    # _soc_ref: referinta opaca la documentul alertei, pentru evidence_refs.
    # Nu intra in contextul modelului (fast_path alege campurile explicit).
    return [{**h["_source"], "_soc_ref": {"index": h["_index"], "id": h["_id"]}}
            for h in r["hits"]["hits"]]


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




def with_chain(verdict):
    """Verdictul cu un chain_id nou. Identificatorul il da codul, nu modelul;
    model_validate (nu model_copy) ca validarea Pydantic sa ruleze si aici."""
    from schemas import Verdict
    return Verdict.model_validate({**verdict.model_dump(), "chain_id": str(uuid.uuid4())})


def alert_ref(a: dict):
    """EvidenceRef pentru documentul alertei (doar ID-uri, niciun continut)."""
    from schemas import EvidenceRef
    ref, ts = a.get("_soc_ref") or {}, _g(a, "@timestamp")
    if not (ref.get("index") and ref.get("id") and ts):
        return None
    try:
        return EvidenceRef(index=ref["index"], doc_id=ref["id"],
                           timestamp=datetime.fromisoformat(ts.replace("Z", "+00:00")))
    except (ValueError, TypeError):
        return None


def with_evidence(verdict, refs):
    """Adauga referinte la verdict: unice, cel mult 50, validate de Pydantic.
    Le construieste CODUL (din alerta si din urma uneltelor), nu modelul."""
    from schemas import Verdict
    seen, out = set(), []
    for r in list(verdict.evidence_refs) + [r for r in refs if r is not None]:
        if (r.index, r.doc_id) not in seen:
            seen.add((r.index, r.doc_id))
            out.append(r)
    return Verdict.model_validate({**verdict.model_dump(), "evidence_refs": [x.model_dump() for x in out[:50]]})


_trace_warned = False


def persist_trace(doc: dict) -> None:
    """Urma cazului in soc-traces. Un esec aici nu opreste auditul (ex. cheia de
    writer fara drept pe soc-traces): se semnaleaza o data, apoi se continua."""
    global _trace_warned
    if WRITER is None:
        return
    try:
        WRITER.index(index=TRACES_IDX, document=doc)
    except Exception as e:
        if not _trace_warned:
            print(f"  [trasare] scrierea in {TRACES_IDX} a esuat: {type(e).__name__} "
                  f"(urmele nu se salveaza pana se rezolva)", flush=True)
            _trace_warned = True


def persist(verdict, narrative: str, decision, started, finished, extra: dict | None = None,
            escalation: EscalationDecision | None = None, failure=None) -> None:
    """Scrie verdictul in istoric si o inregistrare de audit. ground_truth ramane
    GOL — doar omul il completeaza. Fara cheie de writer (dry-run), nu scrie nimic.
    `escalation` = decizia Tier 1 -> Tier 2 (None pe calea lenta).
    `failure` = FailureKind cand verdictul e scris de cod, fara model."""
    if WRITER is None:
        return
    from schemas import AuditRecord
    vdoc = verdict.model_dump(mode="json")
    vdoc["@timestamp"] = finished.isoformat()
    vdoc["ground_truth"] = None            # NICIODATA setat automat
    vdoc["rule_name"] = (extra or {}).get("rule_name")
    WRITER.index(index=VERDICTS_IDX, document=vdoc)

    audit = AuditRecord(
        investigation_id=verdict.investigation_id, chain_id=verdict.chain_id,
        verdict=verdict, narrative=narrative,
        escalate=escalation.escalate if escalation else None,
        escalation_reasons=escalation.reasons if escalation else [],
        failure=failure,
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


def show(kind: str, entity: str, verdict, narrative: str, decision=None,
         escalation: EscalationDecision | None = None) -> None:
    print(f"  [{kind}] {entity}")
    print(f"    verdict: {verdict.classification.value} / {verdict.confidence} / "
          f"{verdict.proposed_action.value}"
          + (f" pe {verdict.action_target}" if verdict.action_target else ""))
    if decision is not None:
        mark = "SHADOW" if decision.shadow_mode else ("EXECUTAT" if decision.executed else "-")
        print(f"    politica: {decision.chosen.value}  [{mark}]  ({decision.reason})")
    if escalation is not None:
        why = ", ".join(r.value for r in escalation.reasons)
        print(f"    escaladare Tier 2: {'DA (' + why + ')' if escalation.escalate else 'nu, inchis la Tier 1'}")
    if verdict.mitre_techniques:
        print(f"    MITRE: {', '.join(verdict.mitre_techniques)}")
    if narrative:
        print(f"    {narrative[:180]}")




from collections import OrderedDict


# Cat timp ramane o cheie "vazuta". Dupa expirare, acelasi caz (ex. aceeasi
# pereche parinte-copil) se investigheaza din nou: un atac de saptamana viitoare
# nu are voie sa fie sarit doar pentru ca perechea a mai aparut o data.
SEEN_TTL_HOURS = float(os.environ.get("SEEN_TTL_HOURS", "24"))


class BoundedSeen:
    """Chei deja procesate, cu memorie limitata: un proces care ruleaza saptamani
    nu trebuie sa creasca la nesfarsit. Se uita cele mai vechi si cele expirate."""
    def __init__(self, maxlen: int = 5000, ttl_hours: float = SEEN_TTL_HOURS,
                 entries: list[tuple[str, float]] | None = None, clock=time.time):
        self._d: OrderedDict = OrderedDict()   # cheie -> epoch cand a fost marcata
        self.maxlen = maxlen
        self.ttl = ttl_hours * 3600
        self._clock = clock
        for k, t in sorted(entries or [], key=lambda e: e[1]):
            self._put(k, t)
        self._expire()

    def _put(self, k, t: float) -> None:
        self._d[k] = t
        self._d.move_to_end(k)
        if len(self._d) > self.maxlen:
            self._d.popitem(last=False)

    def _expire(self) -> None:
        limit = self._clock() - self.ttl
        while self._d and next(iter(self._d.values())) < limit:
            self._d.popitem(last=False)

    def __contains__(self, k) -> bool:
        self._expire()
        return k in self._d

    def __len__(self) -> int:
        self._expire()
        return len(self._d)

    def add(self, k) -> None:
        self._put(k, self._clock())

    def entries(self) -> list[tuple[str, float]]:
        """Cele mai vechi primele, ca la reincarcare sa se pastreze ordinea."""
        self._expire()
        return list(self._d.items())


def _save_seen(seen: BoundedSeen) -> None:
    """O salvare esuata nu opreste ciclul: in cel mai rau caz, dupa o repornire
    se reproceseaza cateva cazuri (sigur), nu se sare peste ele."""
    try:
        save_seen(seen.entries())
    except Exception as e:
        print(f"  [dedup] salvare esuata: {e}", flush=True)


def _record(kind: str, entity: str, v, narrative: str, t0, extra=None, escalation=None,
            failure=None, trace=None, refs=()):
    """Lant + dovezi + politica + afisare + audit + urma, comun tuturor cazurilor
    (cu sau fara model)."""
    v = with_chain(v)
    v = with_evidence(v, list(refs) + (trace.refs() if trace else []))
    d = decide(v)
    show(kind, entity, v, narrative, d, escalation)
    persist(v, narrative, d, t0, datetime.now(timezone.utc), extra,
            escalation=escalation, failure=failure)
    if trace is not None:
        persist_trace(trace.document(chain_id=v.chain_id, investigation_id=v.investigation_id,
                                     source_path=v.source_path, entity=entity,
                                     failure=failure.value if failure else None))
    return v


def process_findings(findings, seen, limit: int, model_ok: bool = True) -> None:
    """Findings de raritate -> calea lenta -> politica -> audit.
    Model cazut / timeout / eroare -> undetermined + escalate_human, scris de cod;
    finding-ul NU e marcat vazut, deci se reia la sweep-ul urmator."""
    print(f"  FINDINGS: {len(findings)} (procesez cel mult {limit}, model "
          f"{'OK' if model_ok else 'CAZUT'})", flush=True)
    hunt = None
    done = 0
    for f in findings:
        if done >= limit:
            break
        k = dedup_key_finding(f)
        entity = f"{f.entity_id} · {(f.detail or {}).get('parent')} -> {(f.detail or {}).get('child')}"
        if k in seen:
            continue
        done += 1
        t0 = datetime.now(timezone.utc)
        failure = None
        try:
            with tracing.case() as tr:
                if not model_ok:
                    failure = degraded.FailureKind.MODEL_UNAVAILABLE
                else:
                    if hunt is None:
                        from hunt_path import build_hunt_path
                        hunt = build_hunt_path()
                    try:
                        out = degraded.run_with_timeout(
                            lambda: hunt.invoke({"finding": f}, config={"recursion_limit": 80}),
                            degraded.CASE_TIMEOUT_HUNT_S)
                    except degraded.CaseTimeout:
                        failure = degraded.FailureKind.CASE_TIMEOUT
                    except Exception as e:
                        print(f"  [EROARE] {entity}: {e}", flush=True)
                        model_ok = degraded.llm_healthy("hunt")
                        failure = (degraded.FailureKind.PROCESSING_ERROR if model_ok
                                   else degraded.FailureKind.MODEL_UNAVAILABLE)
                if failure is not None:
                    _record("LENT", entity, degraded.no_model_verdict(f.entity_id, "hunt"),
                            degraded.NARRATIVE[failure], t0, failure=failure, trace=tr,
                            refs=f.evidence_refs)
                    continue   # nemarcat: se reia cand modelul revine
                _record("LENT", entity, out["verdict"], out.get("narrative", ""), t0,
                        {"hypotheses": out.get("hypotheses", []), "queries_run": out.get("queries_run", [])},
                        trace=tr, refs=f.evidence_refs)
                # Marcat DOAR dupa succes: un esec nu are voie sa scoata cazul din lucru.
                seen.add(k)
        except Exception as e:
            # Nici auditul nu s-a putut scrie (ex. Elasticsearch cazut).
            print(f"  [EROARE la inregistrare, ar escalada la om] {entity}: {e}", flush=True)


def run_positioned(args) -> int:
    """Mod autonom. La fiecare ciclu: alertele de la pozitie pana la (acum - lag),
    apoi, la fiecare `sweep_every` cicluri, sweep-ul pe calea lenta. O eroare
    intr-un ciclu (Elasticsearch cazut, model indisponibil) nu opreste bucla."""
    seen = BoundedSeen(entries=load_seen())
    print(f"[dedup] {len(seen)} chei incarcate din soc-state", flush=True)
    cycle = 0
    while True:
        cycle += 1
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            since, until = load_cursor(), window_end()
            alerts = fetch_alerts_between(since, until, args.limit)
            print(f"[{stamp}] ciclu {cycle}: {len(alerts)} alerte in "
                  f"[{since.strftime('%H:%M:%S')}, {until.strftime('%H:%M:%S')}]", flush=True)
            stats = {"total": 0, "escalated": 0, "no_model": 0}
            fast_ok = degraded.llm_healthy("fast") if alerts else True
            last_ts = process_alerts(alerts, seen, stats, model_ok=fast_ok)
            _save_seen(seen)
            if stats["total"]:
                print(f"  escaladare Tier 1 -> Tier 2: {stats['escalated']}/{stats['total']}"
                      f" (fara model: {stats['no_model']})", flush=True)
            if len(alerts) >= args.limit and last_ts:
                # fereastra nu s-a golit: continuam exact de la ultima alerta
                save_cursor(datetime.fromisoformat(last_ts.replace("Z", "+00:00")))
            else:
                save_cursor(until)   # fereastra golita (sau goala): avansam

            run_sweep = (args.sweep if not args.loop
                         else args.sweep_every > 0 and (cycle - 1) % args.sweep_every == 0)
            if run_sweep:
                from elastic_tools import sweep_new_parent_child
                process_findings(sweep_new_parent_child(1), seen, args.hunt_limit,
                                 model_ok=degraded.llm_healthy("hunt"))
                _save_seen(seen)
        except Exception as e:
            print(f"[{stamp}] EROARE in ciclul {cycle}: {e} — continui", flush=True)

        if not args.loop:
            break
        time.sleep(args.interval)
    return 0


def process_alerts(alerts: list[dict], seen: BoundedSeen, stats: dict | None = None,
                   model_ok: bool = True) -> str | None:
    """Trece fiecare alerta prin calea rapida + politica + escaladare + audit.
    Folosita si de modul manual si de cel cu pozitie (o singura implementare).

    Mod degradat (degraded.py): model cazut -> fiecare alerta escaladeaza fara
    model; peste BACKLOG_THRESHOLD alerte -> coada ordonata dupa severitate si
    criticitate, iar alertele critical escaladeaza direct; plafon de timp per caz.

    Intoarce cel mai nou @timestamp din lot (pentru avansarea pozitiei).
    `stats`, daca e dat, numara alertele procesate, escaladate si fara model."""
    last_ts = max((_g(a, "@timestamp") or "" for a in alerts), default="") or None
    backlog = degraded.is_backlog(len(alerts))
    if backlog:
        from fast_path import lookup_asset
        crit: dict[str, str | None] = {}
        def crit_of(host: str):
            if host not in crit:
                crit[host] = lookup_asset(host).get("criticality")
            return crit[host]
        alerts = degraded.order_backlog(alerts, crit_of)
        print(f"  RESTANTA: {len(alerts)} alerte > {degraded.BACKLOG_THRESHOLD}; "
              f"coada ordonata, alertele critical escaladeaza fara model", flush=True)
    if not model_ok:
        print("  MODEL CAZUT: alertele escaladeaza fara verdict de model", flush=True)
    fast = None
    for a in alerts:
        k = dedup_key_alert(a)
        rule = _g(a, "kibana.alert.rule.name")
        host = _g(a, "host.name")
        entity = f"{host} · {rule}"
        if k in seen:
            print(f"  [duplicat, sarit] {entity}")
            continue
        t0 = datetime.now(timezone.utc)
        failure = None
        try:
            with tracing.case() as tr:
                if backlog and degraded.is_severe(a):
                    v, narrative, esc = (degraded.no_model_verdict(host, "fast"),
                                         degraded.NARRATIVE[None], degraded.backlog_escalation())
                elif not model_ok:
                    failure = degraded.FailureKind.MODEL_UNAVAILABLE
                else:
                    if fast is None:
                        from fast_path import build_fast_path
                        fast = build_fast_path()
                    try:
                        out = degraded.run_with_timeout(
                            lambda: fast.invoke({"alert": a}, config={"recursion_limit": 25}),
                            degraded.CASE_TIMEOUT_FAST_S)
                        v, narrative = out["verdict"], out.get("narrative", "")
                        # Escaladarea o decide CODUL, din verdict + doua fapte calculate de cod.
                        # Tier 2 nu e apelat inca: decizia doar se inregistreaza in audit.
                        esc = should_escalate(v, floor_applied=bool(out.get("floor_applied")),
                                              pair_in_baseline=(out.get("context") or {}).get("pair_in_baseline"))
                    except degraded.CaseTimeout:
                        failure = degraded.FailureKind.CASE_TIMEOUT
                    except Exception as e:
                        print(f"  [EROARE] {entity}: {e}", flush=True)
                        # Model cazut in mijlocul lotului? Restul lotului nu mai asteapta
                        # cate un timeout fiecare: trece direct pe modul degradat.
                        model_ok = degraded.llm_healthy("fast")
                        failure = (degraded.FailureKind.PROCESSING_ERROR if model_ok
                                   else degraded.FailureKind.MODEL_UNAVAILABLE)
                if failure is not None:
                    v, narrative, esc = (degraded.no_model_verdict(host, "fast"),
                                         degraded.NARRATIVE[failure], degraded.failure_escalation())
                _record("RAPID", entity, v, narrative, t0, {"rule_name": rule},
                        escalation=esc, failure=failure, trace=tr, refs=[alert_ref(a)])
                # Alerta e rezolvata: fie judecata, fie escaladata la om ca esec.
                seen.add(k)
                if stats is not None:
                    stats["total"] += 1
                    stats["escalated"] += int(esc.escalate)
                    stats["no_model"] = stats.get("no_model", 0) + int(v.model_id == "none")
        except Exception as e:
            # Nici auditul nu s-a putut scrie: nemarcat, dar cursorul trece mai departe.
            print(f"  [EROARE la inregistrare, ar escalada la om] {entity}: {e}")
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

    # Aceleasi functii ca modul cu pozitie. Dedup doar in memorie: o rulare manuala
    # nu atinge pozitia si nici cheile salvate ale serviciului.
    seen = BoundedSeen()
    alerts = fetch_new_alerts(args.minutes, args.limit)
    print(f"ALERTE: {len(alerts)} in ultimele {args.minutes} min\n")
    stats = {"total": 0, "escalated": 0, "no_model": 0}
    fast_ok = degraded.llm_healthy("fast") if alerts else True
    print(f"Model Tier 1: {'OK' if fast_ok else 'CAZUT -> mod degradat'}\n")
    process_alerts(alerts, seen, stats, model_ok=fast_ok)
    if stats["total"]:
        print(f"Escaladare Tier 1 -> Tier 2: {stats['escalated']}/{stats['total']} "
              f"({stats['escalated'] / stats['total']:.0%}), fara model: {stats['no_model']}\n")

    if args.sweep:
        from elastic_tools import sweep_new_parent_child
        process_findings(sweep_new_parent_child(1), seen, args.limit,
                         model_ok=degraded.llm_healthy("hunt"))

    if WRITER is None:
        print("=== Sfarsit. DRY-RUN: nimic nu a fost scris. ===")
    else:
        print("=== Sfarsit. Verdicte si audit scrise (ground_truth gol). ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
ORCHESTRATOR — bucla principala a SOC-ului (serviciul soc-orchestrator, ciclu la 120 s).

Un ciclu (run_positioned):
  1. Pozitia: cursorul din soc-state (load_cursor; lipsa = prima rulare, orice alta eroare sare
     ciclul fara sa mute cursorul) si fereastra pana la acum minus lag (window_end).
  2. Fetch: alertele din .alerts-security.alerts-* intre cursor si fereastra (fetch_alerts_between).
  3. Dedup + plafon: group_alerts grupeaza in cazuri (regula + entitate), BoundedSeen sare
     duplicatele deja vazute (persistat in soc-state, cu TTL), take_until_cap opreste la --limit
     CAZURI NOI per ciclu; restul raman pentru ciclul urmator.
  4. Sanatatea modelului (degraded.llm_healthy): model cazut -> totul escaladeaza fara verdict.
  5. Restanta peste prag: coada ordonata dupa severitate si criticitate; critical escaladeaza
     direct, fara model.
  6. process_alerts: alerta -> Tier 1 (fast_path) -> should_escalate -> Case (case_adapter, fara
     verdictul Tier 1) -> Tier 2 (hunt_path, buget --t2-limit) -> policy.decide -> persist
     (verdicts-history, soc-audit, soc-traces, soc-cases) + notificarea escaladarilor critice.
  7. Cursorul avanseaza la capatul ferestrei (golita) sau la ultima alerta consumata.
  8. Metrici (soc-metrics type=cycle la fiecare ciclu, instantaneu la --metrics-every), integritatea
     canarului si a prompturilor (_integrity_watch; nepotrivire = conditie de oprire), WATCHDOG=1.
  9. Sweep-ul de raritate (run_full_sweep) la fiecare --sweep-every cicluri -> findings -> Tier 2
     (--hunt-limit per ciclu).

Faza 26: SOC_PIPELINE (din mediu) alege intrarea. `legacy` (implicit) = pasii 2-3 de mai sus,
neschimbati. `intake` = citire paginata a ferestrei intregi (intake.adapter), grupare cu potop
si contabilitate (intake.grouping), clasele critice notificate la intrare (intake.critical);
judecata (pasii 4-6) e aceeasi.

Faza 24 (decizia invatata, T1_CASCADE=off|shadow|on, implicit off): inaintea caii rapide, cascada
(tier1/cascade.py) calculeaza faptele o singura data, grupul (punctele de decizie) si decizia din
etichetele umane / modelul pipeline-ului. Cu off nimic din ea nu ruleaza (verdicte identice, L5);
cu shadow doar se inregistreaza; cu on inchide doar pe pipeline-urile cu model activ, niciodata o
clasa critica sau un caz cu podea (L4). Nivelurile comunica prin magistrala (elasticlab/bus):
Tier 1 -> Tier 2 (`tier2.caz`), decizia cascadei (`cascada.decizie`), rezumatul Tier 2
(`tier2.rezumat`). Scrierile in indici trec prin store/writer.py.

SHADOW_MODE e fortat in ExecStart (deploy/soc-orchestrator.service): decide() calculeaza si
logheaza, nu executa. Rularea manuala (fara --loop) foloseste aceleasi functii, dedup doar in
memorie, si nu atinge pozitia serviciului:

    SHADOW_MODE=true python3 orchestrator.py --minutes 60 --limit 5     # fara scriere daca lipseste ES_WRITER_API_KEY
    python3 orchestrator.py --loop --interval 120 --sweep-every 30     # modul serviciului
"""

from __future__ import annotations

import argparse
import os
import time
import uuid
from datetime import datetime, timezone

# Faza 26: cheia de deduplicare, gruparea, plafonul si cheile vazute stau in intake.grouping
# (mutate, nu rescrise); raman importabile de aici sub aceleasi nume.
from elasticlab.intake.grouping import (CASE_MAX_REFS, SEEN_TTL_HOURS, BoundedSeen,  # noqa: F401
                                        FloodTracker, case_extra, dedup_key_alert, group_alerts,
                                        plan_cycle, take_until_cap)
from elasticlab.tier2 import case_adapter
from elasticlab.core import degraded
from elasticlab.tier1 import behavioral_rules
from elasticlab.core import honeytokens
from elasticlab.ops import cycle_metrics
from elasticlab.core import prompts
from elasticlab.core import sdnotify
from elasticlab.ops import notify
from elasticlab.tier1 import sensor_rules
from elasticlab.core import tracing
from elasticlab.core.escalation import EscalationDecision, should_escalate
from elasticlab.contracts.schemas import EscalationReason
from elasticlab.core.policy import decide, shadow_mode
from elasticlab.store.state import load_cursor, load_seen, save_cursor, save_seen, window_end
from elasticlab.store import writer
from elasticlab.bus.factory import make_bus
from elasticlab.contracts.messages import AlertRef, CazDeInvestigat, DecizieCascada, RezumatTier2

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


# Regulile Tier 3 in shadow alerteaza, dar nu intra in coada Tier 1: o regula
# proaspata si inca nemasurata nu are voie sa inunde triajul (rules.py).
SHADOW_RULE_TAG = "tier3-shadow"

# Comutatorul caii de intrare (din mediu, nu din ExecStart):
#   legacy  — calea de azi: o pagina de --fetch-limit alerte, take_until_cap, paginare dupa verdict.
#   intake  — faza 26, in acelasi proces: citire paginata (intake.adapter), grupare cu potop si
#             contabilitate (intake.grouping), notificarea claselor critice la intrare (intake.critical).
#   queue   — faza cozilor; nu exista inca, orchestratorul refuza sa porneasca.
# `legacy` ramane implicit pana trece testul de incarcare.
PIPELINES = ("legacy", "intake")


def pipeline() -> str:
    return os.environ.get("SOC_PIPELINE", "legacy").strip().lower() or "legacy"


def fetch_alerts_between(since, until, limit: int) -> list[dict]:
    """Alertele deschise din intervalul (since, until], cele mai vechi intai.
    Fara cele ale regulilor Tier 3 aflate in shadow."""
    r = ES.search(index=ALERTS_IDX, size=limit,
                  sort=[{"@timestamp": "asc"}],
                  query={"bool": {"filter": [
                      {"range": {"@timestamp": {"gte": since.isoformat(),
                                                "lte": until.isoformat()}}},
                  ], "must_not": [
                      {"term": {"kibana.alert.workflow_status": "closed"}},
                      {"term": {"kibana.alert.rule.tags": SHADOW_RULE_TAG}},
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


# Ce identifica un finding, pe tip (fara contoare, care cresc de la un sweep la altul).
FINDING_KEY = {
    "new_webroot_write": ("path", "written_by"),
    "new_destination_asn": ("process", "destination_ip"),
    "new_listening_port": ("process", "port"),
    "new_url_path": ("url_path",),
    "web_enumeration": ("source_ip",),
    "wp_recon_path": ("url_path",),
    "response_size_outlier": ("url_path",),
    "beaconing": ("process", "destination_ip"),
    "dns_anomaly": ("process", "domain"),
    "new_ja4": ("ja4",),
    "suspicious_exec_path": ("exec", "process"),
    "new_executable": ("exec",),
    "new_user": ("user",),
    "sbom_drift": ("component_type", "name", "change", "version"),
    "entity_risk": ("entity_type", "entity"),
}


def dedup_key_finding(f) -> str:
    d = f.detail or {}
    if f.kind == "new_parent_child":
        # forma veche, ca cheile deja salvate in soc-state sa ramana valabile
        return f"finding|{f.entity_id}|{d.get('parent')}|{d.get('child')}"
    fields = FINDING_KEY.get(f.kind, tuple(sorted(k for k in d if k != "count")))
    return "|".join(["finding", f.kind, f.entity_id, *(str(d.get(k)) for k in fields)])


def describe_finding(f) -> str:
    d = f.detail or {}
    if f.kind == "new_parent_child":
        return f"{f.entity_id} · {d.get('parent')} -> {d.get('child')}"
    fields = FINDING_KEY.get(f.kind, ())
    return f"{f.entity_id} · {f.kind} " + " ".join(str(d.get(k)) for k in fields)[:120]




def with_chain(verdict, chain_id: str | None = None):
    """Verdictul cu chain_id: cel dat (Tier 2 continua lantul Tier 1) sau unul nou.
    Identificatorul il da codul, nu modelul; model_validate (nu model_copy) ca
    validarea Pydantic sa ruleze si aici."""
    from elasticlab.contracts.schemas import Verdict
    return Verdict.model_validate({**verdict.model_dump(), "chain_id": chain_id or str(uuid.uuid4())})


def alert_ref(a: dict):
    """EvidenceRef pentru documentul alertei (doar ID-uri, niciun continut)."""
    from elasticlab.contracts.schemas import EvidenceRef
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
    from elasticlab.contracts.schemas import Verdict
    seen, out = set(), []
    for r in list(verdict.evidence_refs) + [r for r in refs if r is not None]:
        if (r.index, r.doc_id) not in seen:
            seen.add((r.index, r.doc_id))
            out.append(r)
    return Verdict.model_validate({**verdict.model_dump(), "evidence_refs": [x.model_dump() for x in out[:50]]})


_trace_warned = False
_metrics_warned = False


def _metrics_snapshot() -> None:
    """Instantaneu de metrici in soc-metrics (metrics.py), pentru dashboard-ul din
    Kibana. Calculat in afara grafului; un esec nu opreste ciclul."""
    global _metrics_warned
    if WRITER is None:
        return
    try:
        from elasticlab.ops import metrics
        docs = metrics.compute_and_write(WRITER, datetime.now(timezone.utc), days=1)
        print(f"  [metrici] instantaneu scris ({len(docs)} documente)", flush=True)
    except Exception as e:
        if not _metrics_warned:
            print(f"  [metrici] instantaneul a esuat: {type(e).__name__} "
                  f"(se reincearca la urmatorul interval, fara alte mesaje)", flush=True)
            _metrics_warned = True


def persist_trace(doc: dict) -> None:
    """Urma cazului in soc-traces. Un esec aici nu opreste auditul (ex. cheia de
    writer fara drept pe soc-traces): se semnaleaza o data, apoi se continua."""
    global _trace_warned
    if WRITER is None:
        return
    try:
        writer.index_trace(WRITER, doc)
    except Exception as e:
        if not _trace_warned:
            print(f"  [trasare] scrierea in {TRACES_IDX} a esuat: {type(e).__name__} "
                  f"(urmele nu se salveaza pana se rezolva)", flush=True)
            _trace_warned = True


def make_plan(verdict, decision):
    """Planul executorului (dry-run) pentru o actiune care nu e gratuita.
    Intoarce (plan sau None, text pentru action_result). Nu executa nimic."""
    from elasticlab.core import executor
    now = datetime.now(timezone.utc)
    if not decision.executable:
        return None, None
    try:
        p = executor.plan(verdict, decision, now,
                          stats=executor.fetch_stats(ES, decision.chosen, now),
                          criticality=executor.fetch_criticality(ES, verdict.entity_id),
                          agent_id=(executor.fetch_agent_id(ES, verdict.entity_id)
                                    if decision.chosen.value == "isolate_host" else None))
    except executor.PlanError as e:
        return None, f"dry-run: fara plan ({e}); ramane la om"[:500]
    text = executor.summary(p)
    if decision.chosen.value == "block_ip_ttl":
        # 9.2: rezultatul garzilor (in shadow: would_block), in acelasi rand de audit.
        try:
            req = executor.BlockIpTtl(ip=p.target, ttl_s=3600, reason="verdict Tier 1/2",
                                      confidence=verdict.confidence, case_id=(verdict.chain_id or "")[:64])
            res, why = executor.block_guard(req, shadow=shadow_mode(),
                                            ready=None, protected_ips=frozenset())
            text = f"{text}; garzi: {res} ({why})"
        except Exception as e:  # noqa: BLE001 — garzile nu au voie sa piarda auditul
            text = f"{text}; garzi: eroare {type(e).__name__}"
    return p, text[:500]


def _prompt_set() -> str | None:
    try:
        return prompts.prompt_set(prompts.current())
    except Exception:  # noqa: BLE001 — identificatorul nu are voie sa opreasca scrierea verdictului
        return None


PROMPT_SET: str | None = None     # calculat lenes la primul verdict (importurile sunt grele)


def persist(verdict, narrative: str, decision, started, finished, extra: dict | None = None,
            escalation: EscalationDecision | None = None, failure=None, tier2=None,
            plan=None, action_result: str | None = None) -> None:
    """Scrie verdictul in istoric si o inregistrare de audit. ground_truth ramane
    GOL — doar omul il completeaza. Fara cheie de writer (dry-run), nu scrie nimic.
    `escalation` = decizia Tier 1 -> Tier 2 (None pe calea lenta).
    `failure` = FailureKind cand verdictul e scris de cod, fara model."""
    if WRITER is None:
        return
    global PROMPT_SET
    if PROMPT_SET is None:
        PROMPT_SET = _prompt_set()
    from elasticlab.contracts.schemas import AuditRecord
    vdoc = verdict.model_dump(mode="json")
    vdoc["@timestamp"] = finished.isoformat()
    vdoc["ground_truth"] = None            # NICIODATA setat automat
    vdoc["rule_name"] = (extra or {}).get("rule_name")
    vdoc["prompt_set"] = PROMPT_SET                      # 8.2: prompturile exacte ale verdictului
    if (extra or {}).get("case_alert_count"):
        vdoc["case_alert_count"] = extra["case_alert_count"]   # 10.2: alerte judecate ca un caz
    if (extra or {}).get("cascade"):
        # Faza 24: decizia cascadei (doar cu T1_CASCADE != off). NU e eticheta: ground_truth ramane gol.
        vdoc["cascade"] = extra["cascade"]
        vdoc["bucket_id"] = extra["cascade"].get("bucket_id")
    writer.index_verdict(WRITER, vdoc)

    audit = AuditRecord(
        investigation_id=verdict.investigation_id, chain_id=verdict.chain_id,
        verdict=verdict, narrative=narrative,
        escalate=escalation.escalate if escalation else None,
        escalation_reasons=escalation.reasons if escalation else [],
        failure=failure, tier2=tier2,
        hypotheses_considered=(extra or {}).get("hypotheses", []),
        queries_run=(extra or {}).get("queries_run", []),
        policy_decision=f"{decision.chosen.value}: {decision.reason}",
        action_executed=decision.chosen,
        action_result=action_result or ("shadow: nu s-a executat" if decision.shadow_mode else "executat"),
        execution_plan=plan,
        started_at=started, finished_at=finished, shadow_mode=decision.shadow_mode,
    )
    adoc = audit.model_dump(mode="json")
    adoc["@timestamp"] = finished.isoformat()
    writer.index_audit(WRITER, adoc)

    # plann.md A1/A2: cazul (soc-cases) = vederea de lucru a omului; esecul lui nu atinge auditul.
    try:
        _upsert_case(verdict, finished, extra or {}, escalation, plan)
    except Exception as e:  # noqa: BLE001
        print(f"    [caz nescris, audit scris] {type(e).__name__}: {e}", flush=True)

    # 0.4: pagineaza omul DOAR pentru escaladarile critice (momeala/senzor/detectie
    # nativa). Merge si in shadow (vrei sa stii ca s-a atins momeala, chiar fara actiune).
    # Garda: o eroare de notificare nu are voie sa strice calea de audit.
    # Faza 26 (SOC_PIPELINE=intake): omul a fost notificat deja la intrare -> nu se pagineaza iar.
    if (extra or {}).get("notified_at_intake"):
        return
    try:
        notify.maybe_notify_escalation(verdict, narrative, escalation, failure,
                                       rule_name=(extra or {}).get("rule_name"),
                                       shadow=decision.shadow_mode)
    except Exception as e:
        print(f"    [notificare esuata, audit scris] {e}", flush=True)


_CASES_ES = None
_cases_warned = False
_ORIGIN = {"RAPID": "tier1_alert", "TIER2": "tier1_alert", "POTOP": "tier1_alert", "LENT": "rarity_sweep",
           "VANATOARE": "tier3_hunt", "N-DAY": "tier3_hunt"}


def _upsert_case(verdict, now, extra: dict, escalation, plan) -> None:
    global _CASES_ES, _cases_warned
    from elasticlab.store import cases
    if _CASES_ES is None:
        _CASES_ES = cases.client()
        if _CASES_ES is None:
            if not _cases_warned:
                print("    [cazuri] fara ES_CASES_WRITER_API_KEY: soc-cases nu se scrie", flush=True)
                _cases_warned = True
            return
    # Verdict pe host -> cazul e al hostului; pe user / IP sursa (entity_risk, A3) -> cazul se
    # leaga de hostul monitorizat, cu entitatea pastrata in caz. Procesele/serviciile nu deschid caz.
    if verdict.entity_type.value == "host":
        host = verdict.entity_id
    elif verdict.entity_type.value in ("user", "source_ip"):
        host = cases.MONITORED_HOST
    else:
        return
    alert_ids = [r.doc_id for r in verdict.evidence_refs if str(r.index).startswith(".alerts")][:cases.MAX_ALERTS]
    cases.upsert_from_verdict(
        _CASES_ES, verdict, 1 if verdict.source_path == "fast" else 2, now, host=host,
        origin=_ORIGIN.get(extra.get("origin"), "tier1_alert"), rule_name=extra.get("rule_name"),
        alert_ids=alert_ids, reasons=list(escalation.reasons) if escalation else None,
        escalate=escalation.escalate if escalation else None, plan=plan)


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




def _save_seen(seen: BoundedSeen) -> None:
    """O salvare esuata nu opreste ciclul: in cel mai rau caz, dupa o repornire
    se reproceseaza cateva cazuri (sigur), nu se sare peste ele."""
    try:
        save_seen(seen.entries())
    except Exception as e:
        print(f"  [dedup] salvare esuata: {e}", flush=True)


def _record(kind: str, entity: str, v, narrative: str, t0, extra=None, escalation=None,
            failure=None, trace=None, refs=(), chain_id=None, tier2=None):
    """Lant + dovezi + politica + afisare + audit + urma, comun tuturor cazurilor
    (cu sau fara model)."""
    v = with_chain(v, chain_id)
    v = with_evidence(v, list(refs) + (trace.refs() if trace else []))
    d = decide(v)
    try:
        plan, result = make_plan(v, d)
    except Exception as e:
        # Executorul doar descrie; o eroare a lui nu are voie sa piarda auditul.
        plan, result = None, f"dry-run: eroare la plan ({type(e).__name__}); ramane la om"
    show(kind, entity, v, narrative, d, escalation)
    if plan is not None or (result or "").startswith("dry-run"):
        print(f"    executor: {result}", flush=True)
    persist(v, narrative, d, t0, datetime.now(timezone.utc), {**(extra or {}), "origin": kind},
            escalation=escalation, failure=failure, tier2=tier2, plan=plan, action_result=result)
    if trace is not None:
        persist_trace(trace.document(chain_id=v.chain_id, investigation_id=v.investigation_id,
                                     source_path=v.source_path, entity=entity,
                                     failure=failure.value if failure else None))
    return v


class HuntRunner:
    """Calea lenta, comuna sweep-ului si Tier 2: graful construit o singura data,
    sanatatea modelului verificata la primul caz si din nou la prima eroare.
    Esecul (model cazut, timeout, eroare) devine undetermined + escalate_human."""

    def __init__(self, model_ok: bool | None = None):
        self.graph = None
        self.model_ok = model_ok      # None = inca neverificat

    def run(self, inp: dict, kind: str, entity: str, host: str | None, refs=(),
            chain_id: str | None = None, bucket_id: str | None = None):
        """Investigheaza si inregistreaza. Intoarce FailureKind sau None (succes).
        `bucket_id` (faza 24): rezumatul investigatiei ajunge in pagina grupului (`tier2.rezumat`)."""
        if self.model_ok is None:
            self.model_ok = degraded.llm_healthy("hunt")
        t0 = datetime.now(timezone.utc)
        failure = None
        with tracing.case() as tr:
            if not self.model_ok:
                failure = degraded.FailureKind.MODEL_UNAVAILABLE
            else:
                if self.graph is None:
                    from elasticlab.tier2.hunt_path import build_hunt_path
                    self.graph = build_hunt_path()
                try:
                    out = degraded.run_with_timeout(
                        lambda: self.graph.invoke(inp, config={"recursion_limit": 80}),
                        degraded.CASE_TIMEOUT_HUNT_S)
                except degraded.CaseTimeout:
                    failure = degraded.FailureKind.CASE_TIMEOUT
                except Exception as e:
                    print(f"  [EROARE] {entity}: {e}", flush=True)
                    self.model_ok = degraded.llm_healthy("hunt")
                    failure = (degraded.FailureKind.PROCESSING_ERROR if self.model_ok
                               else degraded.FailureKind.MODEL_UNAVAILABLE)
            if failure is not None:
                _record(kind, entity, degraded.no_model_verdict(host, "hunt"),
                        degraded.NARRATIVE[failure], t0, failure=failure, trace=tr,
                        refs=refs, chain_id=chain_id)
            else:
                v = _record(kind, entity, out["verdict"], out.get("narrative", ""), t0,
                            {"hypotheses": out.get("hypotheses", []), "queries_run": out.get("queries_run", [])},
                            trace=tr, refs=refs, chain_id=chain_id)
                if bucket_id:
                    BUS.publish("tier2.rezumat", RezumatTier2(
                        bucket_id=bucket_id, chain_id=v.chain_id, summary=(out.get("narrative") or "")[:2000],
                        at=datetime.now(timezone.utc)))
        return failure


def finding_pair_refs(f) -> list:
    """Referinte la evenimentele perechii parinte-copil a unui finding de sweep.
    Merg doar in verdict (pentru Tier 3), nu in intrarea modelului. Un esec aici
    nu opreste investigatia."""
    d = f.detail or {}
    if f.kind != "new_parent_child" or not (d.get("parent") and d.get("child")):
        return []
    try:
        from elasticlab.tier2.elastic_tools import pair_event_refs
        return pair_event_refs(f.entity_id, d["parent"], d["child"], window_hours=2,
                               at=getattr(f, "observed_at", None))
    except Exception as e:
        print(f"  [dovezi sweep] {type(e).__name__}: {e}", flush=True)
        return []


def process_findings(findings, seen, limit: int, model_ok: bool = True) -> None:
    """Findings de raritate -> calea lenta -> politica -> audit.
    Model cazut / timeout / eroare -> undetermined + escalate_human, scris de cod;
    finding-ul NU e marcat vazut, deci se reia la sweep-ul urmator."""
    print(f"  FINDINGS: {len(findings)} (procesez cel mult {limit}, model "
          f"{'OK' if model_ok else 'CAZUT'})", flush=True)
    hunt = HuntRunner(model_ok)
    done = 0
    over: list = []
    for f in findings:
        sdnotify.watchdog()
        k = dedup_key_finding(f)
        if k in seen:
            continue
        entity = describe_finding(f)
        if done >= limit:
            over.append((f, k, entity))
            continue
        done += 1
        try:
            refs = list(f.evidence_refs) + finding_pair_refs(f)
            failure = hunt.run({"finding": f}, "LENT", entity, f.entity_id, refs)
            # Marcat DOAR dupa succes: un esec nu are voie sa scoata cazul din lucru.
            if failure is None:
                seen.add(k)
        except Exception as e:
            # Nici auditul nu s-a putut scrie (ex. Elasticsearch cazut).
            print(f"  [EROARE la inregistrare, ar escalada la om] {entity}: {e}", flush=True)
    # R9: bugetul de investigatii epuizat escaladeaza, nu pierde. Cu baseline-ul glisant, un
    # finding nemarcat intra in baseline la sweep-ul urmator si nu mai revine niciodata
    # (masurat 2026-10-30: 9 sweep-uri peste limita in 7 zile, pana la 511 findings pierdute).
    for f, k, entity in over:
        try:
            _record("LENT", entity, degraded.no_model_verdict(f.entity_id, "hunt"),
                    OVER_BUDGET_NARRATIVE, datetime.now(timezone.utc),
                    escalation=degraded.backlog_escalation(), refs=list(f.evidence_refs))
            seen.add(k)
        except Exception as e:
            print(f"  [EROARE la inregistrare, ar escalada la om] {entity}: {e}", flush=True)
    if over:
        print(f"  FINDINGS peste buget: {len(over)} escaladate la om fara model", flush=True)


OVER_BUDGET_NARRATIVE = ("Peste bugetul de investigatii al sweep-ului: escaladat la om fara "
                         "verdict de model, ca sa nu fie pierdut (R9).")


def flood_narrative(fc) -> str:
    return (f"Potop: {len(fc.distinct_keys)} cazuri distincte ({len(fc.members)} alerte) din aceeasi "
            f"regula de la aceeasi sursa, in fereastra care incepe la {fc.window}, peste pragul de "
            f"cazuri pe (regula, sursa). Escaladat la om ca un singur incident, fara verdict de model.")


def process_floods(floods, seen, stats: dict | None = None) -> None:
    """Faza 26: un incident de potop = UN verdict scris de cod (undetermined + escalate_human,
    motiv `flood`), cu referinte la primele CASE_MAX_REFS alerte si contorul tuturor. Marcat
    vazut doar dupa ce s-a scris; altfel se reemite la ciclul urmator (nu se pierde)."""
    from elasticlab.contracts.schemas import EscalationReason
    for fc in floods:
        sdnotify.watchdog()
        entity = f"{fc.host} · {fc.rule} (potop de la {fc.source}, {len(fc.members)} alerte)"
        try:
            ts = sorted(t for t in (_g(a, "@timestamp") for a in fc.members) if t)
            _record("POTOP", entity, degraded.no_model_verdict(fc.host, "fast"), flood_narrative(fc),
                    datetime.now(timezone.utc),
                    {"rule_name": fc.rule, "case_alert_count": len(fc.members),
                     "case_first_ts": ts[0] if ts else None, "case_last_ts": ts[-1] if ts else None},
                    escalation=EscalationDecision(escalate=True, reasons=[EscalationReason.FLOOD]),
                    refs=[alert_ref(x) for x in fc.members[:CASE_MAX_REFS]])
            seen.add(fc.key)
            if stats is not None:
                stats["flood_cases"] = stats.get("flood_cases", 0) + 1
        except Exception as e:
            print(f"  [EROARE la inregistrarea potopului, se reia la ciclul urmator] {entity}: {e}",
                  flush=True)


def intake_cycle(since, until, seen, cap: int, flood: FloodTracker, *, max_alerts: int,
                 page_size: int):
    """Faza 26: citire paginata + normalizare + grupare + potop + contabilitate (fara model).
    Intoarce PlanCiclu (intake.grouping)."""
    from elasticlab.intake import adapter
    fetched, pages, truncated = adapter.read_window(ES, since, until, page_size=page_size,
                                                    max_alerts=max_alerts)
    return plan_cycle(fetched, seen, cap, normalize=adapter.normalize, flood=flood,
                      truncated=truncated, pages=pages)


INTEGRITY_MAX_AGE_MIN = float(os.environ.get("INTEGRITY_MAX_AGE_MIN", "5"))
_integrity_warned = False


def _integrity_watch(now: datetime) -> None:
    """Paznicul paznicului (3.D): absence_check scrie un puls integrity_check in soc-metrics
    la fiecare minut; daca pulsul lipseste, monitorul de integritate e mort (timer oprit,
    cheie revocata) si nimic altceva n-ar observa. absence_check verifica la randul lui ca
    orchestratorul ruleaza. Citeste cu WRITER (are read pe soc-metrics); un esec nu opreste ciclul."""
    global _integrity_warned
    if WRITER is None:
        return
    try:
        r = WRITER.search(index="soc-metrics", size=0,
                          query={"term": {"type.keyword": "integrity_check"}},
                          aggs={"last": {"max": {"field": "@timestamp"}}})
        last = r["aggregations"]["last"].get("value_as_string")
        age = None if not last else (now - datetime.fromisoformat(last.replace("Z", "+00:00"))
                                     ).total_seconds() / 60
        if age is None or age > INTEGRITY_MAX_AGE_MIN:
            shown = "niciun puls" if age is None else f"ultimul puls acum {age:.0f} min"
            print(f"  [integritate] monitorul tace: {shown}", flush=True)
            notify.notify_human("Monitorul de integritate tace",
                                f"soc-absence (absence_check.py): {shown} (prag "
                                f"{INTEGRITY_MAX_AGE_MIN:.0f} min). Verifica soc-absence.timer.",
                                severity="critical", dedup_key="integrity:checker_down",
                                dedup_minutes=30, host="es-node-1")
    except Exception as e:
        if not _integrity_warned:
            print(f"  [integritate] verificarea pulsului a esuat: {type(e).__name__} "
                  f"(se reincearca, fara alte mesaje)", flush=True)
            _integrity_warned = True


def _run_legacy(since, until, seen, stats: dict, args, cycle: int, stamp: str) -> list[dict]:
    """Calea de azi (SOC_PIPELINE=legacy), neschimbata. Intoarce alertele consumate."""
    # Citim mai mult decat judecam: plafonul --limit e pe CAZURI NOI (judecate cu
    # model), nu pe alerte brute; duplicatele se dreneaza gratis (take_until_cap).
    fetched = fetch_alerts_between(since, until, max(args.fetch_limit, args.limit))
    alerts = take_until_cap(fetched, seen, args.limit)
    left = len(fetched) - len(alerts)
    print(f"[{stamp}] ciclu {cycle}: {len(alerts)} alerte in "
          f"[{since.strftime('%H:%M:%S')}, {until.strftime('%H:%M:%S')}]"
          + (f" (+{left} ramase pentru ciclul urmator)" if left else ""), flush=True)
    fast_ok = degraded.llm_healthy("fast") if alerts else True
    last_ts = process_alerts(alerts, seen, stats, model_ok=fast_ok, t2_limit=args.t2_limit)
    _save_seen(seen)
    if (left or len(fetched) >= max(args.fetch_limit, args.limit)) and last_ts:
        # fereastra nu s-a golit: continuam exact de la ultima alerta consumata
        save_cursor(datetime.fromisoformat(last_ts.replace("Z", "+00:00")))
    else:
        save_cursor(until)   # fereastra golita (sau goala): avansam
    return alerts


def _run_intake(since, until, seen, stats: dict, flood: FloodTracker, args, cycle: int,
                stamp: str) -> list[dict]:
    """Faza 26 (SOC_PIPELINE=intake): intrarea noua, apoi ACEEASI judecata ca pe calea veche.

    1. citire paginata a ferestrei intregi; normalizare; grupare; potop; contabilitate;
    2. clasele critice notificate ACUM, inainte de model si de plafon;
    3. process_alerts pe cazurile obisnuite (neschimbat), process_floods pe incidentele de potop;
    4. cursorul: capatul ferestrei daca s-a golit, altfel ultima alerta consumata.
    Intoarce alertele consumate (fara cele absorbite in potop)."""
    from elasticlab.intake import adapter, critical
    plan = intake_cycle(since, until, seen, args.limit, flood, max_alerts=args.intake_max,
                        page_size=args.intake_page)
    acct = plan.acct
    print(f"[{stamp}] ciclu {cycle}: citite {acct.citite} in "
          f"[{since.strftime('%H:%M:%S')}, {until.strftime('%H:%M:%S')}] -> {acct.cazuri} cazuri, "
          f"{acct.grupate} grupate, {acct.in_potop} in potop ({acct.incidente_potop} incidente), "
          f"{acct.amanate} amanate" + (" [citire trunchiata]" if acct.trunchiat else ""), flush=True)
    if not acct.ok():                       # nu se intampla; daca se intampla, se vede
        print(f"  [contabilitate] NEECHILIBRATA: {acct.model_dump()}", flush=True)
    notified: set[str] = set()
    if plan.critical:
        notified = critical.notify_critical(plan.critical, send=notify.notify_human,
                                            recent=notify.recent, shadow=shadow_mode())
        acct.critice_notificate = len(notified)
        print(f"  CRITICE la intrare: {len(plan.critical)} cazuri noi, {len(notified)} notificate",
              flush=True)
    fast_ok = degraded.llm_healthy("fast") if plan.alerts else True
    process_alerts(plan.alerts, seen, stats, model_ok=fast_ok, t2_limit=args.t2_limit,
                   notified=notified)
    process_floods(plan.floods, seen, stats)
    _save_seen(seen)
    save_cursor(adapter.next_cursor(since, until, plan.last_ts, acct.amanate, acct.trunchiat))
    stats["intake"] = acct.model_dump()
    return plan.alerts


def run_positioned(args) -> int:
    """Mod autonom. La fiecare ciclu: alertele de la pozitie pana la (acum - lag),
    apoi, la fiecare `sweep_every` cicluri, sweep-ul pe calea lenta. O eroare
    intr-un ciclu (Elasticsearch cazut, model indisponibil) nu opreste bucla."""
    seen = BoundedSeen(entries=load_seen())
    print(f"[dedup] {len(seen)} chei incarcate din soc-state", flush=True)
    mode = pipeline()
    flood = FloodTracker()
    print(f"[intrare] SOC_PIPELINE={mode}"
          + (f" (potop: prag {flood.threshold} cazuri / (regula, sursa) / {flood.window})"
             if mode == "intake" else ""), flush=True)
    sdnotify.ready()
    tracing.take_llm_totals()        # porneste de la zero (verificarile de pornire pot fi apelat deja modelul)
    cycle = 0
    while True:
        cycle += 1
        started = datetime.now(timezone.utc)
        stamp = started.strftime("%Y-%m-%d %H:%M:%S")
        alerts, stats, run_sweep, cycle_error = [], {}, False, None
        try:
            since, until = load_cursor(), window_end()
            stats = {"total": 0, "escalated": 0, "no_model": 0}
            if mode == "intake":
                alerts = _run_intake(since, until, seen, stats, flood, args, cycle, stamp)
            else:
                alerts = _run_legacy(since, until, seen, stats, args, cycle, stamp)
            if stats["total"]:
                print(f"  escaladare Tier 1 -> Tier 2: {stats['escalated']}/{stats['total']}"
                      f" (fara model: {stats['no_model']}; Tier 2: {stats.get('tier2', 0)} investigate, "
                      f"{stats.get('tier2_skipped', 0)} peste buget)", flush=True)

            if args.metrics_every > 0 and (cycle - 1) % args.metrics_every == 0:
                _metrics_snapshot()
            _integrity_watch(datetime.now(timezone.utc))

            run_sweep = (args.sweep if not args.loop
                         else args.sweep_every > 0 and (cycle - 1) % args.sweep_every == 0)
            if run_sweep:
                from elasticlab.tier2.elastic_tools import run_full_sweep
                process_findings(run_full_sweep(1), seen, args.hunt_limit,
                                 model_ok=degraded.llm_healthy("hunt"))
                _save_seen(seen)
        except Exception as e:
            cycle_error = f"{type(e).__name__}: {str(e)[:120]}"
            print(f"[{stamp}] EROARE in ciclul {cycle}: {e} — continui", flush=True)

        # Pasul 7: un document type=cycle per ciclu (dashboard + absence_check). Nu arunca.
        doc = cycle_metrics.build_cycle_doc(
            cycle=cycle, cycle_id=f"{started:%Y%m%dT%H%M%S}-{cycle}", started=started,
            ended=datetime.now(timezone.utc), alerts_fetched=len(alerts), stats=stats,
            llm=tracing.take_llm_totals(), backlog=bool(stats.get("backlog")),
            sweep_ran=bool(run_sweep), interval_s=args.interval)
        doc["error"] = cycle_error
        doc["prompt_set"] = PROMPT_SET or _prompt_set()
        doc["pipeline"] = mode
        if "cascade" in stats:
            doc["cascade"] = stats["cascade"]           # faza 24: pasii cascadei in acest ciclu
        if "intake" in stats:
            doc["intake"] = stats["intake"]          # faza 26: contabilitatea intrarii
            doc["flood_cases"] = int(stats.get("flood_cases", 0))
        err = cycle_metrics.write(WRITER, doc)
        if err:
            print(f"  [metrici ciclu] nescrise: {err}", flush=True)
        sdnotify.watchdog()

        if not args.loop:
            break
        time.sleep(args.interval)
    return 0


# ---------------- faza 24: magistrala, cascada, grupuri, post-decizie ----------------

BUS = make_bus()
LEARNING = writer.learning_client()      # soc-buckets (citire + scriere); None = grupurile nu se scriu
_T2_CTX: dict = {}
_learning_warned = False


def _event_at(a: dict):
    from elasticlab.core import eventtime
    try:
        return eventtime.alert_time(a)
    except Exception:  # noqa: BLE001
        return None


def _cascade_runtime():
    """Runtime-ul cascadei pentru lotul curent, sau None cand T1_CASCADE=off (ori fisierul de
    oprire de urgenta exista). Nu ridica: o eroare de incarcare devine pasul 4 pe fiecare caz."""
    from elasticlab.contracts.learning import CascadeMode
    from elasticlab.tier1 import cascade as t1c
    mode = t1c.current_mode()
    if mode is CascadeMode.OFF:
        return None
    from elasticlab.store import buckets as B
    return t1c.load_runtime(mode, bucket_reader=lambda bid: _read_bucket(B, bid))


def _read_bucket(B, bid: str):
    try:
        return B.load(LEARNING, bid)
    except Exception:  # noqa: BLE001 — grup necitit = fara consens (pasul urmator), niciodata inchidere
        return None


def _cascade_stats(stats: dict | None, d) -> None:
    if stats is None:
        return
    c = stats.setdefault("cascade", {"mode": d.mode.value, "steps": {}, "would_close": 0,
                                     "closed": 0, "control": 0, "errors": 0, "outliers": 0})
    c["steps"][d.step.value] = c["steps"].get(d.step.value, 0) + 1
    c["would_close"] += int(d.would_close)
    c["closed"] += int(d.applied)
    c["control"] += int(d.control_sample)
    c["errors"] += int(d.step.value == "error")
    c["outliers"] += int(bool(d.prediction and d.prediction.outlier))


def _on_tier2_case(msg: CazDeInvestigat) -> None:
    """Handler-ul Tier 2 (abonat la `tier2.caz`): aceeasi investigatie ca apelul direct de dinainte.
    Exceptiile urca la publicator (process_alerts le prinde, ca inainte)."""
    hunt, stats = _T2_CTX.get("hunt") or HuntRunner(), _T2_CTX.get("stats")
    # bucket_id doar cand exista: apelul ramane identic cu cel de dinainte pe T1_CASCADE=off.
    kw = {"bucket_id": msg.bucket_id} if msg.bucket_id else {}
    hunt.run({"case": msg.case}, "TIER2", msg.entity, msg.case.host, msg.case.evidence_refs,
             chain_id=msg.case.chain_id, **kw)
    if stats is not None:
        stats["tier2"] = stats.get("tier2", 0) + 1


def _on_cascade_bucket(msg: DecizieCascada) -> None:
    """Grupul (soc-buckets): contor, aparitii, exemple, decizia sistemului. Izolat: un esec aici nu
    atinge verdictul deja scris."""
    global _learning_warned
    d = msg.decision
    if d.bucket_id is None or d.pipeline is None or d.dp_version is None:
        return
    if LEARNING is None:
        if not _learning_warned:
            print("  [grupuri] fara ES_LEARNING_WRITER_API_KEY: soc-buckets nu se scrie", flush=True)
            _learning_warned = True
        return
    from elasticlab.contracts.learning import BucketKey
    writer.observe_bucket(LEARNING, BucketKey(pipeline=d.pipeline, dp_version=d.dp_version,
                                              values=d.values, bucket_id=d.bucket_id),
                          d, at=datetime.now(timezone.utc), alert_count=msg.alert_count,
                          examples=[r.model_dump() for r in msg.alert_refs], chain_id=msg.chain_id,
                          final_classification=msg.final_classification)


_TAGGER = None


def _on_cascade_tag(msg: DecizieCascada) -> None:
    """Post-decizia: eticheta pe alerta prin API-ul Kibana, doar pe pipeline activ, mod on."""
    global _TAGGER
    from elasticlab.ops import kibana_tags
    tag = kibana_tags.tag_for(msg.decision)
    if tag is None or not msg.alert_refs:
        return
    if _TAGGER is None:
        _TAGGER = kibana_tags.Tagger()
    _TAGGER.tag([r.id for r in msg.alert_refs], tag)


def _on_tier2_summary(msg: RezumatTier2) -> None:
    if LEARNING is not None:
        writer.set_bucket_tier2(LEARNING, msg.bucket_id, summary=msg.summary, chain_id=msg.chain_id,
                                at=msg.at)


BUS.subscribe("tier2.caz", _on_tier2_case)
BUS.subscribe("cascada.decizie", _on_cascade_bucket, isolated=True)
BUS.subscribe("cascada.decizie", _on_cascade_tag, isolated=True)
BUS.subscribe("tier2.rezumat", _on_tier2_summary, isolated=True)


def process_alerts(alerts: list[dict], seen: BoundedSeen, stats: dict | None = None,
                   model_ok: bool = True, t2_limit: int = 0,
                   hunt: HuntRunner | None = None, notified: set[str] | None = None) -> str | None:
    """Trece fiecare alerta prin calea rapida + politica + escaladare + audit.
    Folosita si de modul manual si de cel cu pozitie (o singura implementare).

    Mod degradat (degraded.py): model cazut -> fiecare alerta escaladeaza fara
    model; peste BACKLOG_THRESHOLD alerte -> coada ordonata dupa severitate si
    criticitate, iar alertele critical escaladeaza direct; plafon de timp per caz.

    Tier 2: primele `t2_limit` alerte escaladate (in ordinea cozii) devin Case
    (case_adapter, FARA verdictul Tier 1) si trec prin calea lenta, cu acelasi
    chain_id; restul raman escaladate la om, marcate tier2=skipped_budget.

    `notified` (faza 26) = cheile cazurilor deja notificate la intrare: verdictul lor nu mai
    pagineaza omul a doua oara (persist).

    Intoarce cel mai nou @timestamp din lot (pentru avansarea pozitiei).
    `stats`, daca e dat, numara alertele procesate, escaladate, fara model si Tier 2."""
    hunt = hunt or HuntRunner()
    t2_used = 0
    # Faza 24: cascada. Cu T1_CASCADE=off (implicit) `rt` ramane None si nimic de mai jos nu se schimba.
    rt = _cascade_runtime()
    prefetched = None
    _T2_CTX.update(hunt=hunt, stats=stats)
    last_ts = max((_g(a, "@timestamp") or "" for a in alerts), default="") or None
    # 10.2: restanta se masoara in CAZURI noi, nu in alerte brute (o rafala de la un IP pe o
    # regula e un singur caz; inainte, 100 de duplicate treceau tot SOC-ul pe modul fara model).
    groups = group_alerts(alerts)
    new_cases = sum(1 for k, _ in groups if k not in seen)
    if stats is not None:
        stats["alerts_in_cases"] = stats.get("alerts_in_cases", 0) + sum(len(m) - 1 for _, m in groups)
    backlog = degraded.is_backlog(new_cases)
    if stats is not None:
        stats["backlog"] = stats.get("backlog", False) or backlog
    if backlog:
        from elasticlab.tier1.fast_path import lookup_asset
        crit: dict[str, str | None] = {}
        def crit_of(host: str):
            if host not in crit:
                crit[host] = lookup_asset(host).get("criticality")
            return crit[host]
        by_lead = {id(m[0]): (k, m) for k, m in groups}
        groups = [by_lead[id(a)] for a in degraded.order_backlog([m[0] for _, m in groups], crit_of)]
        print(f"  RESTANTA: {new_cases} cazuri noi ({len(alerts)} alerte) > {degraded.BACKLOG_THRESHOLD}; "
              f"coada ordonata, alertele critical escaladeaza fara model", flush=True)
    if not model_ok:
        print("  MODEL CAZUT: alertele escaladeaza fara verdict de model", flush=True)
    fast = None
    for k, members in groups:
        sdnotify.watchdog()          # un lot lung (Tier 2) nu trebuie sa para blocaj
        a = members[0]
        rule = _g(a, "kibana.alert.rule.name")
        host = _g(a, "host.name")
        entity = f"{host} · {rule}" + (f" ({len(members)} alerte)" if len(members) > 1 else "")
        if k in seen:
            print(f"  [duplicat, sarit] {entity}")
            continue
        t0 = datetime.now(timezone.utc)
        failure = None
        out = None
        cdec, cctx = (None, None)
        if rt is not None:
            from elasticlab.tier1 import cascade as t1c
            cdec, cctx = t1c.evaluate(rt, a, sample_key=k)      # nu ridica exceptii (L6)
        try:
            with tracing.case() as tr:
                if backlog and degraded.is_severe(a):
                    v, narrative, esc = (degraded.no_model_verdict(host, "fast"),
                                         degraded.NARRATIVE[None], degraded.backlog_escalation())
                elif cdec is not None and cdec.applied:
                    # Cascada inchide (doar benign, pipeline activ, mod on; niciodata critic/podea).
                    v, narrative, esc = (t1c.close_verdict(cdec, host), t1c.close_narrative(cdec),
                                         EscalationDecision(escalate=False, reasons=[]))
                elif not model_ok:
                    failure = degraded.FailureKind.MODEL_UNAVAILABLE
                else:
                    if cctx is not None:
                        # Pasul 4 cu faptele deja calculate (pasul 0): aceleasi noduri fast_path.
                        if prefetched is None:
                            prefetched = t1c.build_prefetched()
                        graph, inp = prefetched, {"alert": a, "context": cctx}
                    else:
                        if fast is None:
                            from elasticlab.tier1.fast_path import build_fast_path
                            fast = build_fast_path()
                        graph, inp = fast, {"alert": a}
                    try:
                        out = degraded.run_with_timeout(
                            lambda: graph.invoke(inp, config={"recursion_limit": 25}),
                            degraded.CASE_TIMEOUT_FAST_S)
                        v, narrative = out["verdict"], out.get("narrative", "")
                        # Escaladarea o decide CODUL, din verdict + doua fapte calculate de cod.
                        # Tier 2 nu e apelat inca: decizia doar se inregistreaza in audit.
                        esc = should_escalate(v, floor_applied=bool(out.get("floor_applied")),
                                              pair_in_baseline=(out.get("context") or {}).get("pair_in_baseline"),
                                              native_detection=bool((out.get("context") or {}).get("native_detection")),
                                              honeytoken=(honeytokens.escalation_reason(a)
                                                          is EscalationReason.HONEYTOKEN),
                                              sensor_detection=sensor_rules.is_sensor_alert(a),
                                              behavioral=behavioral_rules.is_behavioral(a))
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
                # Momeala atinsa / detectie de senzor: motivul ajunge in audit si la Tier 2
                # si pe caile fara model (restanta, model cazut), unde should_escalate nu ruleaza.
                # Momeala atinsa de pe un IP propriu/benign: motiv separat (config_error), fara paginare.
                ht_reason = honeytokens.escalation_reason(a)
                if stats is not None:
                    if failure is not None:
                        fk = f"fail_{failure.value}"
                        stats[fk] = stats.get(fk, 0) + 1
                    if ht_reason is EscalationReason.HONEYTOKEN:
                        stats["honeytoken_hits"] = stats.get("honeytoken_hits", 0) + 1
                for flag, reason in ((ht_reason is not None, ht_reason),
                                     (sensor_rules.is_sensor_alert(a), EscalationReason.SENSOR_DETECTION)):
                    if flag and reason not in esc.reasons:
                        esc = EscalationDecision(escalate=True, reasons=[*esc.reasons, reason])
                cextra = {}
                if cdec is not None:
                    # Motivele cascadei (grup attack, model: atac probabil, esantion de control) se
                    # adauga doar cand au efect (mod on + pipeline activ); ele doar FORTEAZA escaladarea.
                    if cdec.applied_reasons:
                        for r in cdec.reasons:
                            if EscalationReason(r) not in esc.reasons:
                                esc = EscalationDecision(escalate=True, reasons=[*esc.reasons, EscalationReason(r)])
                    cextra = {"cascade": t1c.summary(cdec)}
                    _cascade_stats(stats, cdec)
                tier2 = None
                if esc.escalate:
                    tier2 = "investigated" if t2_used < t2_limit else "skipped_budget"
                v = _record("RAPID", entity, v, narrative, t0,
                            {"rule_name": rule, **case_extra(members), **cextra,
                             **({"notified_at_intake": True} if notified and k in notified else {})},
                            escalation=esc, failure=failure, trace=tr,
                            refs=[alert_ref(x) for x in members[:CASE_MAX_REFS]], tier2=tier2)
                if cdec is not None:
                    BUS.publish("cascada.decizie", DecizieCascada(
                        decision=cdec, chain_id=v.chain_id, alert_count=max(1, len(members)),
                        alert_refs=[AlertRef(**x["_soc_ref"]) for x in members[:CASE_MAX_REFS]
                                    if (x.get("_soc_ref") or {}).get("index") and (x.get("_soc_ref") or {}).get("id")],
                        event_at=_event_at(a), final_classification=v.classification.value,
                        escalated=esc.escalate))
                # Alerta e rezolvata: fie judecata, fie escaladata la om ca esec.
                seen.add(k)
                if stats is not None:
                    stats["total"] += 1
                    stats["escalated"] += int(esc.escalate)
                    stats["no_model"] = stats.get("no_model", 0) + int(v.model_id == "none")
                    stats["tier2_skipped"] = stats.get("tier2_skipped", 0) + int(tier2 == "skipped_budget")
        except Exception as e:
            # Nici auditul nu s-a putut scrie: nemarcat, dar cursorul trece mai departe.
            print(f"  [EROARE la inregistrare, ar escalada la om] {entity}: {e}")
            print()
            continue
        if tier2 == "investigated":
            t2_used += 1
            try:
                case = case_adapter.from_alert(a, esc, v.chain_id,
                                               facts=(out or {}).get("context"), refs=v.evidence_refs)
                bid = cdec.bucket_id if cdec is not None else None
                if bid:
                    case = case.model_copy(update={"bucket_id": bid})
                # Tier 1 -> Tier 2 prin magistrala (sincron, aceeasi ordine; handler-ul e _on_tier2_case).
                BUS.publish("tier2.caz", CazDeInvestigat(case=case, entity=entity[:600], bucket_id=bid))
            except Exception as e:
                # Cazul ramane escaladat la om din Tier 1; Tier 2 doar n-a putut adauga nimic.
                print(f"  [EROARE Tier 2, cazul ramane escaladat la om] {entity}: {e}", flush=True)
        print()
    return last_ts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=int, default=60, help="rulare manuala: ultimele N min")
    ap.add_argument("--limit", type=int, default=20,
                    help="cazuri NOI judecate per ciclu (duplicatele nu se numara)")
    ap.add_argument("--fetch-limit", type=int, default=int(os.environ.get("FETCH_LIMIT", "500")),
                    help="alerte citite per ciclu din care se aleg cazurile noi (drenarea duplicatelor)")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--once", action="store_true", help="un ciclu folosind pozitia, apoi iesi")
    ap.add_argument("--loop", action="store_true", help="cicluri la interval, folosind pozitia")
    ap.add_argument("--interval", type=int, default=120, help="secunde intre cicluri in --loop")
    ap.add_argument("--sweep-every", type=int, default=30,
                    help="in --loop: sweep la fiecare N cicluri (30 x 120s = o ora); 0 = niciodata")
    ap.add_argument("--hunt-limit", type=int, default=5,
                    help="cate findings investigheaza calea lenta pe ciclu (fiecare ~1 min)")
    ap.add_argument("--metrics-every", type=int, default=30,
                    help="in --loop: instantaneu de metrici la fiecare N cicluri (30 x 120s = o ora); 0 = niciodata")
    ap.add_argument("--t2-limit", type=int, default=3,
                    help="cate alerte escaladate de Tier 1 merg la Tier 2 pe ciclu; restul raman la om")
    ap.add_argument("--intake-page", type=int, default=int(os.environ.get("INTAKE_PAGE", "500")),
                    help="SOC_PIPELINE=intake: alerte pe pagina la citire")
    ap.add_argument("--intake-max", type=int, default=int(os.environ.get("INTAKE_MAX", "20000")),
                    help="SOC_PIPELINE=intake: plasa de memorie (alerte citite pe ciclu); restul la ciclul urmator")
    args = ap.parse_args()

    if args.once or args.loop:
        mode = pipeline()
        if mode not in PIPELINES:
            msg = (f"SOC_PIPELINE={mode!r} necunoscut sau inca neimplementat (valori: "
                   f"{', '.join(PIPELINES)}). Orchestratorul NU porneste.")
            print(f"[intrare] REFUZ: {msg}", flush=True)
            notify.notify_human("Orchestratorul refuza sa porneasca: SOC_PIPELINE", msg,
                                severity="critical", dedup_key="pipeline:unknown",
                                dedup_minutes=60, host="es-node-1")
            return 4
        # Pasul 8.2: un prompt schimbat fara bump de versiune (prompts/MANIFEST.json) -> refuz.
        ok, bad, pset = prompts.verify()
        if not ok:
            msg = (f"Prompturi schimbate fara bump de versiune: {', '.join(bad)}. Ruleaza `make "
                   "regression`, apoi `python prompts.py --update --reason ...`. Orchestratorul NU porneste.")
            print(f"[prompturi] REFUZ: {msg}", flush=True)
            notify.notify_human("Orchestratorul refuza sa porneasca: prompturi neversionate", msg,
                                severity="critical", dedup_key="prompts:mismatch",
                                dedup_minutes=60, host="es-node-1")
            return 3
        print(f"[prompturi] la zi, prompt_set={pset}", flush=True)
        return run_positioned(args)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    mode = ("SCRIE audit+verdicte" if WRITER is not None else "DRY-RUN, nu scrie nimic")
    shadow = shadow_mode()
    print(f"=== Orchestrator {stamp} | {mode} | shadow={shadow} ===\n")

    # Aceleasi functii ca modul cu pozitie. Dedup doar in memorie: o rulare manuala
    # nu atinge pozitia si nici cheile salvate ale serviciului.
    seen = BoundedSeen()
    alerts = fetch_new_alerts(args.minutes, args.limit)
    print(f"ALERTE: {len(alerts)} in ultimele {args.minutes} min\n")
    stats = {"total": 0, "escalated": 0, "no_model": 0}
    fast_ok = degraded.llm_healthy("fast") if alerts else True
    print(f"Model Tier 1: {'OK' if fast_ok else 'CAZUT -> mod degradat'}\n")
    process_alerts(alerts, seen, stats, model_ok=fast_ok, t2_limit=args.t2_limit)
    if stats["total"]:
        print(f"Escaladare Tier 1 -> Tier 2: {stats['escalated']}/{stats['total']} "
              f"({stats['escalated'] / stats['total']:.0%}), fara model: {stats['no_model']}; "
              f"Tier 2: {stats.get('tier2', 0)} investigate, {stats.get('tier2_skipped', 0)} peste buget\n")

    if args.sweep:
        from elasticlab.tier2.elastic_tools import run_full_sweep
        process_findings(run_full_sweep(1), seen, args.limit,
                         model_ok=degraded.llm_healthy("hunt"))

    if WRITER is None:
        print("=== Sfarsit. DRY-RUN: nimic nu a fost scris. ===")
    else:
        print("=== Sfarsit. Verdicte si audit scrise (ground_truth gol). ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

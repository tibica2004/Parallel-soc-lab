"""SCRIITORUL (faza 24): singurul modul care scrie in Elasticsearch verdicte, audit, urme, cazuri si
grupuri. Restul codului ii da documentul si clientul; un test (tests/test_scriitor_unic.py) verifica
ca nimeni altcineva nu cheama .index/.update/.create pe acesti indici.

Clientul il alege apelantul (cheile sunt scoped si raman cele de azi):
  verdicte, audit, urme   ES_WRITER_API_KEY            (orchestratorul)
  eticheta pe verdict     ES_WRITER_API_KEY            (label_ui, la actiunea omului)
  cazuri                  ES_CASES_WRITER_API_KEY      (store/cases.py)
  grupuri, audit invatare ES_LEARNING_WRITER_API_KEY   (nou: orchestrator, label_ui, tier3)

Nimic de aici nu completeaza ground_truth sau label_source: voturile umane vin gata construite din
eval/labeling.py (singurul loc care le construieste), la actiunea unui om autentificat (L2).
"""
from __future__ import annotations

import os
from datetime import datetime
from typing import Callable

from elasticlab.contracts.learning import BucketKey, CascadeDecision, Consensus, Vote
from elasticlab.core.buckets import consensus

VERDICTS_IDX = "verdicts-history"
AUDIT_IDX = "soc-audit"
TRACES_IDX = "soc-traces"
CASES_IDX = "soc-cases"
BUCKETS_IDX = "soc-buckets"
LEARNING_AUDIT_IDX = "soc-learning-audit"

MAX_EXAMPLES = 10
MAX_VOTES = 50
RMW_RETRIES = 4


# ---------------- clientii ----------------

def _client(var: str, timeout: int = 30):
    key = os.environ.get(var)
    if not key:
        return None
    from elasticsearch import Elasticsearch
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"), api_key=key,
                         request_timeout=timeout)


def verdict_client():
    return _client("ES_WRITER_API_KEY")


def learning_client():
    return _client("ES_LEARNING_WRITER_API_KEY", 20)


# ---------------- verdicte, audit, urme, cazuri ----------------

def index_verdict(es, doc: dict) -> None:
    es.index(index=VERDICTS_IDX, document=doc)


def index_audit(es, doc: dict) -> None:
    es.index(index=AUDIT_IDX, document=doc)


def index_trace(es, doc: dict) -> None:
    es.index(index=TRACES_IDX, document=doc)


def write_case(es, case_id: str, doc: dict) -> None:
    es.index(index=CASES_IDX, id=case_id, document=doc)


def update_verdict_label(es, doc_id: str, fields: dict, *, seq_no: int, primary_term: int) -> None:
    """Eticheta omului pe un verdict (campurile vin din labeling.build_label_update). Control de
    concurenta: doua etichetari simultane nu se calca (ConflictError urca la interfata)."""
    es.update(index=VERDICTS_IDX, id=doc_id, doc=fields, if_seq_no=seq_no,
              if_primary_term=primary_term)


def index_learning_audit(es, doc: dict) -> None:
    es.index(index=LEARNING_AUDIT_IDX, document=doc)


# ---------------- grupuri (soc-buckets) ----------------

def _rmw(es, bucket_id: str, change: Callable[[dict | None], dict | None]) -> dict | None:
    """Citeste-modifica-scrie cu control de concurenta (orchestratorul numara, omul voteaza, in
    acelasi timp). `change(None)` = documentul nu exista; intoarce None = nu scrie nimic."""
    from elasticsearch import ConflictError, NotFoundError
    for _ in range(RMW_RETRIES):
        try:
            got = es.get(index=BUCKETS_IDX, id=bucket_id)
            cur, seq = got["_source"], (got["_seq_no"], got["_primary_term"])
        except NotFoundError:
            cur, seq = None, None
        new = change(None if cur is None else dict(cur))
        if new is None:
            return cur
        try:
            if seq is None:
                es.index(index=BUCKETS_IDX, id=bucket_id, document=new, op_type="create")
            else:
                es.index(index=BUCKETS_IDX, id=bucket_id, document=new,
                         if_seq_no=seq[0], if_primary_term=seq[1])
            return new
        except ConflictError:
            continue
    raise RuntimeError(f"grupul {bucket_id}: prea multe conflicte de scriere")


def _system_view(d: CascadeDecision, at: datetime) -> dict:
    p = d.prediction
    return {"step": d.step.value, "would_close": d.would_close, "applied": d.applied,
            "control_sample": d.control_sample, "mode": d.mode.value,
            "decision": p.decision.value if p else None, "confidence": p.confidence if p else None,
            "p_attack": p.p_attack if p else None, "outlier": p.outlier if p else None,
            "model_hash": p.model_hash if p else None,
            "model_state": d.model_state.value if d.model_state else None, "at": at.isoformat()}


def observe_bucket(es, key: BucketKey, decision: CascadeDecision, *, at: datetime, alert_count: int,
                   examples: list[dict], chain_id: str | None,
                   final_classification: str | None) -> dict | None:
    """Un caz nou a cazut in grup: contor, prima/ultima aparitie, exemple (doar referinte), ce a
    decis sistemul (ascuns in interfata pana la etichetare). NU atinge voturile: o alerta care cade
    intr-un grup etichetat nu primeste eticheta (L2)."""
    iso = at.isoformat()

    def change(cur: dict | None) -> dict:
        doc = cur or {"bucket_id": key.bucket_id, "pipeline": key.pipeline,
                      "dp_version": key.dp_version, "values": key.values, "count": 0,
                      "first_seen": iso, "votes": [], "consensus": Consensus.NONE.value,
                      "votes_attack": 0, "votes_benign": 0, "cascade_closed": 0,
                      "control_samples": 0, "examples": []}
        doc["count"] = int(doc.get("count", 0)) + max(1, alert_count)
        doc["last_seen"] = max(iso, doc.get("last_seen") or iso)
        doc["first_seen"] = min(iso, doc.get("first_seen") or iso)
        ex = [{**e, "chain_id": chain_id, "final_classification": final_classification, "at": iso}
              for e in examples[:3]]
        doc["examples"] = (ex + list(doc.get("examples") or []))[:MAX_EXAMPLES]
        doc["system"] = _system_view(decision, at)
        if decision.applied:
            doc["cascade_closed"] = int(doc.get("cascade_closed", 0)) + 1
            doc["last_closed_at"] = iso
        if decision.control_sample:
            doc["control_samples"] = int(doc.get("control_samples", 0)) + 1
        return doc

    return _rmw(es, key.bucket_id, change)


def add_bucket_vote(es, bucket_id: str, vote: dict) -> dict | None:
    """Votul unui om (dictionarul din labeling.build_bucket_vote). Recalculeaza consensul din
    ultimul vot al fiecarui om. Grupul trebuie sa existe (se voteaza ce s-a vazut)."""
    v = Vote(user=vote["user"], label=vote["label"], at=datetime.fromisoformat(vote["at"]),
             notes=vote.get("notes") or "")

    def change(cur: dict | None) -> dict | None:
        if cur is None:
            return None
        votes = [x for x in (cur.get("votes") or [])][-MAX_VOTES + 1:] + [vote]
        c, a, b = consensus([Vote(user=x["user"], label=x["label"], at=datetime.fromisoformat(x["at"]),
                                  notes=x.get("notes") or "") for x in votes])
        cur.update(votes=votes, consensus=c.value, votes_attack=a, votes_benign=b,
                   labeled_at=v.at.isoformat())
        return cur

    return _rmw(es, bucket_id, change)


def set_bucket_tier2(es, bucket_id: str, *, summary: str, chain_id: str | None, at: datetime) -> dict | None:
    """Rezumatul Tier 2 in pagina grupului. Nu devine eticheta (nu atinge voturile)."""
    def change(cur: dict | None) -> dict | None:
        if cur is None:
            return None
        cur["tier2_summary"] = {"text": summary[:2000], "chain_id": chain_id, "at": at.isoformat()}
        return cur

    return _rmw(es, bucket_id, change)

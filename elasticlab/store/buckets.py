"""Citirea grupurilor (soc-buckets), faza 24. Scrierile trec prin store/writer.py.

Interogari Query DSL cu term/filter (principiul 3); identificatorii de grup sunt validati inainte.
"""
from __future__ import annotations

import re
from datetime import datetime

from elasticlab.contracts.learning import BUCKET_ID_RE, Consensus, LabeledBucket
from elasticlab.core.buckets import label_priority
from elasticlab.store.writer import BUCKETS_IDX

QUEUE_FETCH = 500


def valid_id(bucket_id: str) -> bool:
    return bool(re.match(BUCKET_ID_RE, bucket_id or ""))


def load(es, bucket_id: str) -> dict | None:
    if es is None or not valid_id(bucket_id):
        return None
    from elasticsearch import NotFoundError
    try:
        return es.get(index=BUCKETS_IDX, id=bucket_id)["_source"]
    except NotFoundError:
        return None


def consensus_of(doc: dict | None, dp_version: int | None = None) -> Consensus:
    """Consensul valid: doar pe versiunea curenta a punctelor de decizie."""
    if not doc or (dp_version is not None and doc.get("dp_version") != dp_version):
        return Consensus.NONE
    try:
        return Consensus(doc.get("consensus") or "none")
    except ValueError:
        return Consensus.NONE


def _ts(s) -> datetime:
    return datetime.fromisoformat(str(s).replace("Z", "+00:00"))


def labeled(es, pipeline: str, dp_version: int, size: int = 5000) -> list[LabeledBucket]:
    """Grupurile cu consens uman attack/benign (exemplele de antrenare, L3). Egalitatea si lipsa
    votului nu intra."""
    r = es.search(index=BUCKETS_IDX, size=size, query={"bool": {"filter": [
        {"term": {"pipeline": pipeline}}, {"term": {"dp_version": dp_version}},
        {"terms": {"consensus": ["attack", "benign"]}}]}}, sort=[{"bucket_id": "asc"}])
    out = []
    for h in r["hits"]["hits"]:
        d = h["_source"]
        try:
            out.append(LabeledBucket(bucket_id=d["bucket_id"], values=d["values"], label=d["consensus"],
                                     first_seen=_ts(d["first_seen"]), last_seen=_ts(d["last_seen"]),
                                     count=int(d.get("count") or 0)))
        except Exception:  # noqa: BLE001 — un document stricat nu intra la antrenare
            continue
    return out


def queue(es, pipeline: str | None = None, size: int = 50) -> list[dict]:
    """Coada de etichetare: grupurile fara consens (nevotate sau la egalitate), ordonate de COD
    dupa incertitudine x volum (core.buckets.label_priority)."""
    filt: list[dict] = [{"terms": {"consensus": ["none", "tie"]}}]
    if pipeline:
        filt.append({"term": {"pipeline": pipeline}})
    r = es.search(index=BUCKETS_IDX, size=QUEUE_FETCH, query={"bool": {"filter": filt}},
                  sort=[{"count": "desc"}, {"bucket_id": "asc"}])
    rows = []
    for h in r["hits"]["hits"]:
        d = h["_source"]
        sysv = d.get("system") or {}
        d["_priority"] = label_priority(int(d.get("count") or 0), sysv.get("p_attack"),
                                        bool(sysv.get("outlier")))
        rows.append(d)
    rows.sort(key=lambda d: (-d["_priority"], d.get("bucket_id", "")))
    return rows[:size]


def user_voted(doc: dict, user: str) -> bool:
    return any(v.get("user") == user for v in (doc.get("votes") or []))

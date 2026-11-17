#!/usr/bin/env python3
"""
FAZA 23, etapa 2 — masuratoarea pentru regula asimetrica Tier 2 (DOAR CITIRE).

Intrebarea: cate verdicte `hunt` cu clasificare benign, venite din findings de sweep (nu din cazuri
Tier 1), din ultimele N zile, NU au in soc-traces niciun apel de unealta cu rows > 0? Acestea ar
deveni undetermined + escalate_human sub regula din etapa 5 (daca nici faptul determinist din
prefetch_ctx nu le salveaza; acela nu e in urma, deci cifra de aici e o LIMITA SUPERIOARA).

Interogari (Query DSL cu filter/term/range pe campurile .keyword (mapare dinamica, ca in
  regression.export), nimic interpolat din telemetrie), cheia ES_READER_API_KEY:
  1. verdicts-history: source_path=hunt, classification=benign, @timestamp >= now-Nd
     -> investigation_id, chain_id, @timestamp
  2. verdicts-history: source_path=fast, chain_id in (lanturile de la 1)
     -> lanturile cu verdict Tier 1 = cazuri escaladate din Tier 1, EXCLUSE
  3. soc-traces: investigation_id in (ramase), source_path=hunt -> events (type, rows)
Nu scrie nimic nicaieri.

    source env.sh && python3 experiments/tier2_fara_dovezi.py --zile 30
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

PAGE = 10000
CHUNK = 500


# =============================================================================
# FUNCTII PURE
# =============================================================================

def has_rows(trace_docs: list[dict]) -> bool:
    """Cel putin un apel de unealta cu rows > 0 in urmele unei investigatii. Pur."""
    for t in trace_docs:
        for ev in t.get("events") or []:
            if ev.get("type") == "tool" and isinstance(ev.get("rows"), int) and ev["rows"] > 0:
                return True
    return False


def classify(verdicts: list[dict], tier1_chains: set[str], traces: dict[str, list[dict]]) -> dict:
    """verdicts: hunt/benign; tier1_chains: lanturi cu verdict fast; traces: investigation_id ->
    documente soc-traces. Intoarce numaratorile totale si pe zi (UTC). Pur."""
    sweep = [v for v in verdicts if v.get("chain_id") not in tier1_chains]
    no_ev = [v for v in sweep if not has_rows(traces.get(v.get("investigation_id"), []))]
    no_trace = sum(1 for v in no_ev if v.get("investigation_id") not in traces)
    per_day = Counter(str(v.get("@timestamp", ""))[:10] for v in no_ev)
    days = sorted(Counter(str(v.get("@timestamp", ""))[:10] for v in sweep))
    return {"hunt_benign": len(verdicts), "from_tier1": len(verdicts) - len(sweep), "from_sweep": len(sweep),
            "sweep_benign_without_rows": len(no_ev), "of_which_no_trace_doc": no_trace,
            "per_day": {d: per_day.get(d, 0) for d in days}}


# =============================================================================
# CITIRE ES
# =============================================================================

def _search(es, index: str, query: dict, fields: list[str]) -> list[dict]:
    r = es.search(index=index, size=PAGE, query=query, source=fields, sort=[{"@timestamp": "asc"}])
    hits = r["hits"]["hits"]
    if len(hits) >= PAGE:
        print(f"ATENTIE: {index}: limita {PAGE} atinsa, rezultat trunchiat", file=sys.stderr)
    return [h["_source"] for h in hits]


def main(argv=None) -> int:
    from elasticsearch import Elasticsearch
    ap = argparse.ArgumentParser()
    ap.add_argument("--zile", type=int, default=30)
    a = ap.parse_args(argv)
    es = Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                       api_key=os.environ["ES_READER_API_KEY"], request_timeout=60)
    since = (datetime.now(timezone.utc) - timedelta(days=a.zile)).isoformat()
    verdicts = _search(es, "verdicts-history", {"bool": {"filter": [
        {"term": {"source_path.keyword": "hunt"}}, {"term": {"classification.keyword": "benign"}},
        {"range": {"@timestamp": {"gte": since}}}]}}, ["investigation_id", "chain_id", "@timestamp"])
    chains = sorted({v["chain_id"] for v in verdicts if v.get("chain_id")})
    tier1 = set()
    for i in range(0, len(chains), CHUNK):
        tier1 |= {d["chain_id"] for d in _search(es, "verdicts-history", {"bool": {"filter": [
            {"term": {"source_path.keyword": "fast"}}, {"terms": {"chain_id.keyword": chains[i:i + CHUNK]}}]}}, ["chain_id"])}
    ids = sorted({v["investigation_id"] for v in verdicts if v.get("chain_id") not in tier1})
    traces: dict[str, list[dict]] = {}
    for i in range(0, len(ids), CHUNK):
        for t in _search(es, "soc-traces", {"bool": {"filter": [
                {"terms": {"investigation_id.keyword": ids[i:i + CHUNK]}}]}},
                ["investigation_id", "events.type", "events.rows", "@timestamp"]):
            traces.setdefault(t["investigation_id"], []).append(t)
    print(json.dumps(classify(verdicts, tier1, traces), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

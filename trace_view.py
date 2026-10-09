#!/usr/bin/env python3
"""
"De ce a gresit agentul la cazul X?" — reconstituie un caz din audit + urma.

Cauta dupa chain_id sau investigation_id (ambele apar in interfata de etichetare
si in verdicts-history) si tipareste: verdictul, escaladarea, apoi pas cu pas
apelurile de model (tokeni, durata, ce unelte a cerut) si de unelte (argumente,
randuri, documente atinse). Continutul documentelor nu e in urma; ID-urile
de aici se pot deschide in Kibana Discover cu _id:<id>.

    source env.sh
    python3 trace_view.py <chain_id | investigation_id>
"""

from __future__ import annotations

import argparse
import os
import re
import sys

from elasticsearch import Elasticsearch

ID_RE = re.compile(r"^[A-Za-z0-9\-]{8,64}$")


def _writer() -> Elasticsearch:
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                         api_key=os.environ["ES_WRITER_API_KEY"], request_timeout=30)


def _find(es: Elasticsearch, index: str, case_id: str) -> dict | None:
    q = {"bool": {"should": [{"term": {"chain_id.keyword": case_id}},
                             {"term": {"investigation_id.keyword": case_id}}],
                  "minimum_should_match": 1}}
    try:
        hits = es.search(index=index, size=1, query=q, sort=[{"@timestamp": "desc"}])["hits"]["hits"]
    except Exception as e:
        print(f"[{index}] citire esuata: {type(e).__name__}", file=sys.stderr)
        return None
    return hits[0]["_source"] if hits else None


def format_case(audit: dict | None, trace: dict | None) -> str:
    out: list[str] = []
    if audit:
        v = audit.get("verdict") or {}
        out.append(f"VERDICT  {v.get('classification')} / {v.get('confidence')} / {v.get('proposed_action')}"
                   f"  ({v.get('source_path')}, model {v.get('model_id')})")
        out.append(f"entitate {v.get('entity_type')}:{v.get('entity_id')}   chain {audit.get('chain_id')}")
        esc = audit.get("escalate")
        if esc is not None:
            out.append("escaladare Tier 2: " + ("DA (" + ", ".join(audit.get("escalation_reasons") or []) + ")"
                                                if esc else "nu, inchis la Tier 1"))
        if audit.get("failure"):
            out.append(f"FARA VERDICT DE MODEL: {audit['failure']}")
        out.append(f"politica: {audit.get('policy_decision')}")
        refs = v.get("evidence_refs") or []
        out.append(f"dovezi (evidence_refs): {len(refs)}")
        out.append("naratiune (text de model, neincrezator):")
        out.append("  " + (audit.get("narrative") or "").replace("\n", "\n  "))
    else:
        out.append("(nicio inregistrare de audit)")
    out.append("")
    if not trace:
        out.append("(nicio urma in soc-traces)")
        return "\n".join(out)
    t = trace.get("totals") or {}
    out.append(f"URMA  {t.get('llm_calls', 0)} apeluri de model, {t.get('tokens', 0)} tokeni, "
               f"{t.get('tool_calls', 0)} apeluri de unelte ({t.get('tool_errors', 0)} esuate), "
               f"{t.get('doc_refs', 0)} documente, {t.get('duration_ms', 0) / 1000:.1f}s")
    for i, ev in enumerate(trace.get("events") or [], 1):
        if ev.get("type") == "llm":
            asked = ", ".join(ev.get("tool_calls") or []) or "-"
            out.append(f"{i:3d}. MODEL  {ev.get('role')}: {ev.get('tokens')} tokeni, "
                       f"{ev.get('duration_ms')} ms, cere: {asked}")
        else:
            err = f"  EROARE {ev['error']}" if ev.get("error") else ""
            out.append(f"{i:3d}. UNEALTA {ev.get('name')} {ev.get('args')}")
            out.append(f"       -> {ev.get('rows')} randuri, {len(ev.get('doc_refs') or [])} documente, "
                       f"{ev.get('duration_ms')} ms{err}")
            for r in (ev.get("doc_refs") or [])[:5]:
                out.append(f"          {r.get('index')}  _id:{r.get('id')}")
            if len(ev.get("doc_refs") or []) > 5:
                out.append(f"          ... inca {len(ev['doc_refs']) - 5}")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("case_id", help="chain_id sau investigation_id")
    args = ap.parse_args()
    if not ID_RE.match(args.case_id):
        print("identificator invalid", file=sys.stderr)
        return 2
    es = _writer()
    print(format_case(_find(es, "soc-audit", args.case_id), _find(es, "soc-traces", args.case_id)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

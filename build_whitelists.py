#!/usr/bin/env python3
"""
Genereaza listele albe pentru regulile comportamentale c (www-data exec) si d (outbound)
din baseline-ul REAL de 7 zile, nu din intuitie. Scrie data/behavioral-whitelists.json,
pe care behavioral_rules.py il citeste la construirea regulilor inainte de import.

Fara asta, regula c ar alerta pe apache2/php-fpm insusi (zgomot masiv). Se ruleaza pe
es-node-1 inainte de importul regulilor, si ori de cate ori baseline-ul se schimba.

Doar CITIRE din ES (logs-endpoint.events.*). Nicio scriere in ES. Niciun model.
Praguri: ultimele BASELINE_DAYS zile, min_doc_count executabile/IP-uri recurente, ca o
aparitie unica sa nu intre in lista alba. Valorile raman DATE: intra ca liste EQL de
siruri citate in behavioral_rules, nu in query_string.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s",
                    stream=sys.stderr)
log = logging.getLogger("soc.whitelists")

ROOT = Path(__file__).resolve().parent
OUT_FILE = ROOT / "data" / "behavioral-whitelists.json"

HOST = os.environ.get("BWL_HOST", "web-prod")
BASELINE_DAYS = int(os.environ.get("BWL_BASELINE_DAYS", "7"))
MIN_DOC_COUNT = int(os.environ.get("BWL_MIN_DOC_COUNT", "3"))
TERMS_SIZE = int(os.environ.get("BWL_TERMS_SIZE", "200"))
PROC_INDEX = os.environ.get("BWL_PROC_INDEX", "logs-endpoint.events.process-*")
NET_INDEX = os.environ.get("BWL_NET_INDEX", "logs-endpoint.events.network-*")


def es_client() -> Elasticsearch:
    key = os.environ.get("ES_READER_API_KEY") or os.environ.get("ES_API_KEY")
    if not key:
        raise RuntimeError("lipseste ES_READER_API_KEY / ES_API_KEY")
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                         api_key=key, request_timeout=60)


def _terms(es: Elasticsearch, index: str, field: str, filters: list[dict]) -> list[str]:
    body = {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": f"now-{BASELINE_DAYS}d"}}},
                                      *filters]}},
        "aggs": {"v": {"terms": {"field": field, "size": TERMS_SIZE,
                                 "min_doc_count": MIN_DOC_COUNT}}},
    }
    r = es.search(index=index, body=body)
    return [b["key"] for b in r.get("aggregations", {}).get("v", {}).get("buckets", [])]


def build(es: Elasticsearch) -> dict:
    # c) executabilele reale rulate de www-data (contul de serviciu web)
    wwwdata_exec = _terms(es, PROC_INDEX, "process.executable", [
        {"term": {"user.name": "www-data"}},
        {"term": {"event.type": "start"}},
    ])
    # d) destinatiile outbound vazute de web-prod in afara retelei interne (DNS/NTP excluse)
    egress_ip = _terms(es, NET_INDEX, "destination.ip", [
        {"term": {"host.name": HOST}},
        {"term": {"network.direction": "egress"}},
    ])
    internal = [ip for ip in egress_ip if ip.startswith("192.168.10.")]
    egress_ip = [ip for ip in egress_ip if not ip.startswith("192.168.10.")
                 and ip not in ("::1", "127.0.0.1")]
    log.info("executabile www-data: %d; egress extern: %d (interne excluse: %d)",
             len(wwwdata_exec), len(egress_ip), len(internal))
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": HOST, "lookback_days": BASELINE_DAYS, "min_doc_count": MIN_DOC_COUNT,
        "wwwdata_exec": sorted(wwwdata_exec), "egress_ip": sorted(egress_ip),
    }


def main() -> int:
    try:
        es = es_client()
        data = build(es)
        OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
        OUT_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        log.info("scris %s", OUT_FILE)
        return 0
    except Exception as e:  # noqa: BLE001 — orice eroare: log + exit 1 (R14)
        log.exception("build_whitelists a esuat: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())

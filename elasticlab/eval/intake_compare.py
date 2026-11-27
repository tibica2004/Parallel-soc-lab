"""Faza 26: calea veche si calea noua de intrare produc aceleasi cazuri pe aceeasi fereastra?

Simuleaza ciclurile orchestratorului pana se goleste fereastra, FARA model si FARA scriere:
  - legacy: o pagina de --fetch-limit alerte, take_until_cap, cursorul ca in _run_legacy;
  - intake: citire paginata (intake.adapter), plan_cycle FARA potop, cursorul ca in _run_intake.
Compara cazurile judecate (cheia de deduplicare -> alerta care deschide cazul). Contorul (cate
alerte intra in fiecare caz) poate diferi: pe calea veche duplicatele dintr-un ciclu urmator
sunt sarite, pe cea noua sunt numarate.

Pe laborator (doar citire, cheia ES_API_KEY / ES_READONLY_API_KEY din env.sh; nimic nu se scrie,
nimic nu iese din laborator):

    source env.sh && python3 -m elasticlab.eval.intake_compare --hours 24 \\
        | tee results/faza26-intrare-$(date +%F-%H%M).json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone

from elasticlab.intake import adapter
from elasticlab.intake.grouping import BoundedSeen, group_alerts, plan_cycle, take_until_cap


def drain(es, since: datetime, until: datetime, cap: int, *, legacy: bool, fetch_limit: int = 500,
          page_size: int = 500, max_cycles: int = 100_000) -> tuple[dict[str, str], int]:
    """Cazurile judecate pe fereastra: ({cheie: id-ul alertei care deschide cazul}, cicluri)."""
    seen = BoundedSeen(maxlen=10**9, ttl_hours=10**6)
    judged: dict[str, str] = {}
    for cycle in range(1, max_cycles + 1):
        if legacy:
            hits = es.search(index=adapter.ALERTS_IDX, size=fetch_limit, sort=[{"@timestamp": "asc"}],
                             query=adapter._query(since, until))["hits"]["hits"]
            fetched = [{**h["_source"], "_soc_ref": {"index": h["_index"], "id": h["_id"]}}
                       for h in hits]
            alerts = take_until_cap(fetched, seen, cap)
            left, trunc = len(fetched) - len(alerts), len(fetched) >= fetch_limit
        else:
            fetched, _, trunc = adapter.read_window(es, since, until, page_size=page_size,
                                                    max_alerts=10**7)
            plan = plan_cycle(fetched, seen, cap, normalize=adapter.normalize, flood=None)
            alerts, left = plan.alerts, plan.acct.amanate
        for k, members in group_alerts(alerts):
            if k not in seen:
                judged[k] = members[0]["_soc_ref"]["id"]
                seen.add(k)
        last = max((a.get("@timestamp") or "" for a in alerts), default="") or None
        new = adapter.next_cursor(since, until, last, left, trunc)
        if new == until:
            return judged, cycle
        since = new
    raise RuntimeError("fereastra nu s-a golit in numarul maxim de cicluri")


def compare(es, since: datetime, until: datetime, cap: int, fetch_limit: int = 500) -> dict:
    old, c_old = drain(es, since, until, cap, legacy=True, fetch_limit=fetch_limit)
    new, c_new = drain(es, since, until, cap, legacy=False)
    only_old = sorted(set(old) - set(new))
    only_new = sorted(set(new) - set(old))
    other_lead = sorted(k for k in set(old) & set(new) if old[k] != new[k])
    return {"since": since.isoformat(), "until": until.isoformat(), "cap": cap,
            "fetch_limit": fetch_limit, "cases_legacy": len(old), "cases_intake": len(new),
            "cycles_legacy": c_old, "cycles_intake": c_new,
            "only_legacy": len(only_old), "only_intake": len(only_new),
            "different_lead": len(other_lead), "identical": not (only_old or only_new or other_lead)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hours", type=float, default=24)
    ap.add_argument("--until", help="ISO 8601; implicit acum")
    ap.add_argument("--cap", type=int, default=50, help="--limit al serviciului")
    ap.add_argument("--fetch-limit", type=int, default=500)
    args = ap.parse_args()
    from elasticsearch import Elasticsearch
    es = Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                       api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"],
                       request_timeout=60)
    until = (datetime.fromisoformat(args.until.replace("Z", "+00:00")) if args.until
             else datetime.now(timezone.utc))
    out = compare(es, until - timedelta(hours=args.hours), until, args.cap, args.fetch_limit)
    json.dump(out, sys.stdout, indent=2)
    print()
    return 0 if out["identical"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

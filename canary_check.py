#!/usr/bin/env python3
"""
CANARUL — detectia detectorului.

Pe web-prod, cron ruleaza /usr/local/bin/soc-canary la fiecare 5 minute.
Scriptul asta verifica in Elasticsearch doua lucruri:

  1. FLUX: ultimul canar a fost indexat in ultimele 12 minute.
     Altfel telemetria de proces s-a oprit — agentul poate raporta HEALTHY
     si totusi sa nu trimita nimic.

  2. CEAS: diferenta dintre event.ingested si @timestamp e sub 5 minute.
     Altfel Defend stampileaza gresit (de ex. dupa suspendarea VM-ului) si
     toate interogarile pe ferestre de timp devin oarbe.

Sortam dupa event.ingested, nu dupa @timestamp: un eveniment cu ora stricata
ar fi ascuns tocmai de o sortare dupa ora lui.

Iesire: 0 = OK, 1 = problema. Ruleaza din cron si scrie intr-un log.
"""

import os
import sys
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

HOST = os.environ.get("CANARY_HOST", "web-prod")
MAX_AGE_MIN = 12
MAX_SKEW_MIN = 5

ES = Elasticsearch(
    os.environ.get("ES_URL", "http://localhost:9200"),
    api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"],
    request_timeout=20,
)


def parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def main() -> int:
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%d %H:%M:%S")
    try:
        r = ES.esql.query(query=f"""
            FROM logs-endpoint.events.process-*
            | WHERE host.name == "{HOST}" AND process.name == "soc-canary"
            | SORT event.ingested DESC
            | KEEP @timestamp, event.ingested
            | LIMIT 1
        """, format="json")
    except Exception as e:
        print(f"{stamp} ALERTA interogare esuata: {e}")
        return 1

    if not r["values"]:
        print(f"{stamp} ALERTA niciun canar gasit pentru {HOST} (cron-ul ruleaza?)")
        return 1

    ts, ingested = r["values"][0]
    ts, ingested = parse(ts), parse(ingested)
    age_min = (now - ingested).total_seconds() / 60
    skew_min = abs((ingested - ts).total_seconds()) / 60

    problems = []
    if age_min > MAX_AGE_MIN:
        problems.append(f"telemetria s-a oprit: ultimul canar acum {age_min:.0f} min")
    if skew_min > MAX_SKEW_MIN:
        problems.append(f"ceas stricat: @timestamp difera de ingested cu {skew_min:.0f} min "
                        f"-> ruleaza 'sudo systemctl restart ElasticEndpoint' pe {HOST}")

    if problems:
        for p in problems:
            print(f"{stamp} ALERTA {p}")
        return 1
    print(f"{stamp} OK canar acum {age_min:.1f} min, decalaj ceas {skew_min*60:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())

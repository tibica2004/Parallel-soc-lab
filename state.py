"""
POZITIE PERSISTENTA a orchestratorului.

Tine minte, in Elasticsearch, momentul ultimei alerte procesate. La repornire,
ciclul continua exact de acolo — nu reproceseaza tot, nu sare peste ce a aparut
cat era oprit.

De ce in Elasticsearch, nu intr-un fisier: daca muti orchestratorul pe alta
masina sau rulezi doua instante, pozitia trebuie sa fie una singura, partajata.
Scrie cu cheia de writer (indexul soc-state e in permisiunile ei).

Un mic decalaj (LAG) in urma prezentului acopera intarzierea de indexare: o
alerta poate ajunge in index cu cateva secunde dupa @timestamp-ul ei, deci nu
citim pana in "acum", ci pana in "acum - LAG".
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from elasticsearch import Elasticsearch

STATE_IDX = "soc-state"
CURSOR_ID = "orchestrator-cursor"
LAG_SECONDS = 30          # marja pentru intarzierea de indexare
DEFAULT_LOOKBACK_MIN = 15  # de unde pornim la prima rulare, daca nu exista pozitie


def _writer() -> Elasticsearch:
    key = os.environ.get("ES_WRITER_API_KEY")
    if not key:
        raise RuntimeError("ES_WRITER_API_KEY lipseste — pozitia are nevoie de cheia de scriere")
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                         api_key=key, request_timeout=30)


def load_cursor() -> datetime:
    """Momentul de la care sa citim alertele. Prima data: acum - DEFAULT_LOOKBACK."""
    try:
        doc = _writer().get(index=STATE_IDX, id=CURSOR_ID)["_source"]
        return datetime.fromisoformat(doc["last_ts"].replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc) - timedelta(minutes=DEFAULT_LOOKBACK_MIN)


def save_cursor(ts: datetime) -> None:
    """Salveaza pozitia. `ts` = @timestamp-ul ultimei alerte procesate."""
    _writer().index(index=STATE_IDX, id=CURSOR_ID,
                    document={"last_ts": ts.isoformat(),
                              "updated_at": datetime.now(timezone.utc).isoformat()})


def window_end() -> datetime:
    """Capatul de sus al ferestrei de citit: prezentul minus marja de indexare."""
    return datetime.now(timezone.utc) - timedelta(seconds=LAG_SECONDS)

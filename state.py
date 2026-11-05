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

from elasticsearch import Elasticsearch, NotFoundError

STATE_IDX = "soc-state"
CURSOR_ID = "orchestrator-cursor"
SEEN_ID = "orchestrator-seen"
LAG_SECONDS = 30          # marja pentru intarzierea de indexare
DEFAULT_LOOKBACK_MIN = 15  # de unde pornim la prima rulare, daca nu exista pozitie


def _writer() -> Elasticsearch:
    key = os.environ.get("ES_WRITER_API_KEY")
    if not key:
        raise RuntimeError("ES_WRITER_API_KEY lipseste — pozitia are nevoie de cheia de scriere")
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                         api_key=key, request_timeout=30)


def load_cursor() -> datetime:
    """Momentul de la care sa citim alertele. Prima data (documentul lipseste): acum - DEFAULT_LOOKBACK.

    "Lipsa" nu e "eroare": un 403 sau un timeout tranzitoriu pe soc-state ridica exceptia mai
    departe; run_positioned o prinde ca eroare de ciclu (ciclul se sare, cursorul nu se muta).
    Inainte, orice exceptie intorcea now-15min si save_cursor(until) pierdea definitiv alertele
    dintre cursorul real si now-15min."""
    try:
        doc = _writer().get(index=STATE_IDX, id=CURSOR_ID)["_source"]
    except NotFoundError:
        return datetime.now(timezone.utc) - timedelta(minutes=DEFAULT_LOOKBACK_MIN)
    return datetime.fromisoformat(doc["last_ts"].replace("Z", "+00:00"))


def save_cursor(ts: datetime) -> None:
    """Salveaza pozitia. `ts` = @timestamp-ul ultimei alerte procesate."""
    _writer().index(index=STATE_IDX, id=CURSOR_ID,
                    document={"last_ts": ts.isoformat(),
                              "updated_at": datetime.now(timezone.utc).isoformat()})


def window_end() -> datetime:
    """Capatul de sus al ferestrei de citit: prezentul minus marja de indexare."""
    return datetime.now(timezone.utc) - timedelta(seconds=LAG_SECONDS)


# --------------------------------------------------------------------------
# Cheile de deduplicare, langa cursor. Fara ele, la fiecare repornire a
# serviciului findings-urile din ultima ora ar trece iar prin calea lenta.
# Fiecare cheie are momentul (epoch) cand a fost marcata, pentru expirare.
# Lista e ordonata: cele mai vechi primele (ordinea din BoundedSeen).
# --------------------------------------------------------------------------


def load_seen() -> list[tuple[str, float]]:
    """Cheile salvate. Orice esec -> lista goala: reprocesarea e sigura,
    sarirea peste un caz nu este."""
    try:
        doc = _writer().get(index=STATE_IDX, id=SEEN_ID)["_source"]
    except Exception:
        return []
    out = []
    for e in doc.get("entries") or []:
        if isinstance(e, dict) and isinstance(e.get("k"), str) and isinstance(e.get("t"), (int, float)):
            out.append((e["k"], float(e["t"])))
    return out


def save_seen(entries: list[tuple[str, float]]) -> None:
    _writer().index(index=STATE_IDX, id=SEEN_ID,
                    document={"entries": [{"k": k, "t": t} for k, t in entries],
                              "updated_at": datetime.now(timezone.utc).isoformat()})

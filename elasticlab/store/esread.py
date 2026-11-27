"""Clientul Elasticsearch de CITIRE comun caii de verdict (faza 24 Arcanna, regula de importuri).

Inainte statea in tier2/elastic_tools.py si tier1.fast_path il importa de acolo (incalcarea
tier1 -> tier2 din docs/faza-24-importuri.md). Acum e aici; elastic_tools il importa sub acelasi
nume (`ES`), deci exista un singur client, cu aceeasi cheie read-only ca inainte.
"""
from __future__ import annotations

import os
from typing import Any

from elasticsearch import Elasticsearch

ES = Elasticsearch(
    os.environ.get("ES_URL", "http://localhost:9200"),
    # rol: read pe logs-*, .alerts-*, baseline-*, asset-inventory, verdicts-history
    api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"],
    request_timeout=30,
)


def esql(query: str, params: list[Any] | None = None) -> list[dict]:
    """ES|QL parametrizat (`?` + params), randurile ca dictionare. Identic cu elastic_tools._esql."""
    resp = ES.esql.query(query=query, params=params or [], format="json")
    cols = [c["name"] for c in resp["columns"]]
    return [dict(zip(cols, row)) for row in resp["values"]]

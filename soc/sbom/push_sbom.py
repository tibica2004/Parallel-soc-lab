#!/usr/bin/env python3
"""push_sbom.py — valideaza un SBOM (JSON) si il indexeaza in asset-inventory.

Rulat pe es-node-1. SBOM-ul vine de pe web-prod prin scp manual (pana la
ForceCommand din pasul 6). doc_id = host:data, ca sa pastram un snapshot/zi.
Asigura mapping explicit keyword pe components.name / components.version.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vulnwatch"))
from schemas import Sbom  # noqa: E402

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
READ_KEY = os.environ.get("ES_API_KEY")
WRITE_KEY = os.environ.get("ES_ASSET_INVENTORY_WRITER_KEY") or os.environ.get("ES_WRITER_API_KEY")
IDX = "asset-inventory"

# Mapping aditiv (PUT _mapping e idempotent / nu strica datele existente).
COMPONENT_MAPPING = {
    "properties": {
        "host": {"type": "keyword"},
        "generated_at": {"type": "date"},
        "components": {
            "type": "nested",
            "properties": {
                "type": {"type": "keyword"},
                "name": {"type": "keyword"},
                "version": {"type": "keyword"},
                "active": {"type": "boolean"},
            },
        },
    }
}


def _es(method, path, key, body=None):
    headers = {"Authorization": f"ApiKey {key}", "Content-Type": "application/json"}
    return requests.request(method, f"{ES_URL}{path}", headers=headers,
                            data=json.dumps(body) if body is not None else None, timeout=30)


def ensure_mapping() -> None:
    # creeaza indexul cu mapping daca lipseste; altfel aplica mapping aditiv.
    h = _es("HEAD", f"/{IDX}", READ_KEY)
    if h.status_code == 404:
        _es("PUT", f"/{IDX}", WRITE_KEY, {"mappings": COMPONENT_MAPPING})
    else:
        r = _es("PUT", f"/{IDX}/_mapping", WRITE_KEY, COMPONENT_MAPPING)
        if r.status_code not in (200, 201):
            print(f"[push_sbom] mapping (ne-fatal) {r.status_code}: {r.text[:200]}")


def main(path: str) -> int:
    if not WRITE_KEY:
        print("[push_sbom] lipseste cheia de scriere asset-inventory.", file=sys.stderr)
        return 2
    try:
        raw = json.load(open(path))
    except Exception as e:
        print(f"[push_sbom] nu pot citi {path}: {e}", file=sys.stderr)
        return 1
    try:
        sbom = Sbom(**raw)  # validare stricta
    except Exception as e:
        print(f"[push_sbom] SBOM invalid: {e}", file=sys.stderr)
        return 1

    ensure_mapping()
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    doc_id = f"{sbom.host}:{day}"
    r = _es("PUT", f"/{IDX}/_doc/{doc_id}", WRITE_KEY, sbom.model_dump())
    if r.status_code not in (200, 201):
        print(f"[push_sbom] index esuat {r.status_code}: {r.text[:200]}", file=sys.stderr)
        return 1
    print(f"[push_sbom] {len(sbom.components)} componente indexate ca {IDX}/{doc_id}")
    return 0


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "/tmp/sbom.json"
    sys.exit(main(src))

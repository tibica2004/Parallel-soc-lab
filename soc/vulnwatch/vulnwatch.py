#!/usr/bin/env python3
"""vulnwatch — N-day watch.

Citeste ultimul SBOM din asset-inventory si, pentru fiecare componenta,
coreleaza versiunea instalata cu CVE cunoscute (OSV + NVD + Wordfence),
marcheaza cele din CISA KEV ca exploited_in_wild, si scrie in asset-vulns.

EXCLUSIV DEFENSIV: nu testeaza exploatarea, doar coreleaza versiuni cu CVE
publice. Read-only pe tot ce nu e asset-vulns (scris cu cheia dedicata).
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sources  # noqa: E402
from schemas import Sbom, VulnRecord  # noqa: E402

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
READ_KEY = os.environ.get("ES_API_KEY")
WRITE_KEY = os.environ.get("ES_ASSET_VULNS_WRITER_KEY")
IDX = "asset-vulns"


def _es(method: str, path: str, key: str, body: dict | None = None) -> requests.Response:
    headers = {"Authorization": f"ApiKey {key}", "Content-Type": "application/json"}
    return requests.request(
        method, f"{ES_URL}{path}", headers=headers,
        data=json.dumps(body) if body is not None else None, timeout=30,
    )


def latest_sbom() -> Sbom | None:
    q = {"size": 1, "sort": [{"generated_at": {"order": "desc"}}], "query": {"match_all": {}}}
    r = _es("POST", "/asset-inventory/_search", READ_KEY, q)
    if r.status_code != 200:
        print(f"[vulnwatch] asset-inventory search {r.status_code}: {r.text[:200]}")
        return None
    hits = r.json().get("hits", {}).get("hits", [])
    if not hits:
        return None
    try:
        return Sbom(**hits[0]["_source"])
    except Exception as e:
        print(f"[vulnwatch] SBOM invalid: {e}")
        return None


def upsert(rec: VulnRecord) -> None:
    # pastreaza first_seen si statusul setat manual (accepted_risk/patched)
    g = _es("GET", f"/{IDX}/_doc/{rec.doc_id()}", READ_KEY)
    if g.status_code == 200 and g.json().get("found"):
        src = g.json().get("_source", {})
        rec.first_seen = src.get("first_seen", rec.first_seen)
        if src.get("status") in ("accepted_risk", "patched"):
            rec.status = src["status"]
    r = _es("PUT", f"/{IDX}/_doc/{rec.doc_id()}", WRITE_KEY, rec.model_dump())
    if r.status_code not in (200, 201):
        print(f"[vulnwatch] scriere {rec.cve_id}/{rec.component} esuat {r.status_code}: {r.text[:200]}")


def main() -> int:
    if not WRITE_KEY:
        print("[vulnwatch] lipseste ES_ASSET_VULNS_WRITER_KEY — nu pot scrie.", file=sys.stderr)
        return 2
    sbom = latest_sbom()
    if not sbom:
        print("[vulnwatch] niciun SBOM in asset-inventory — ruleaza push_sbom intai.")
        return 1

    kev = sources.load_kev()
    now = datetime.now(timezone.utc).isoformat()
    written = 0

    for c in sbom.components:
        found: dict[str, dict] = {}
        for d in sources.query_osv(c.name, c.version, c.type):
            if d["cve_id"]:
                found[d["cve_id"].upper()] = d
        for d in sources.query_nvd(c.name, c.version, c.type):
            found.setdefault(d["cve_id"].upper(), d)  # OSV prioritar
        if c.type in ("wp-plugin", "wp-theme"):
            for d in sources.query_wordfence(c.name, c.version, c.type):
                found.setdefault(d["cve_id"].upper(), d)

        for cve_id, d in found.items():
            if not cve_id.startswith("CVE"):
                continue
            d = dict(d)
            d.update({
                "cve_id": cve_id,
                "component": c.name,
                "component_type": c.type,
                "host": sbom.host,
                "installed_version": c.version,
                "exploited_in_wild": cve_id in kev,
                "first_seen": now,
                "last_seen": now,
            })
            try:
                upsert(VulnRecord(**d))
                written += 1
            except Exception as e:
                print(f"[vulnwatch] rec invalid {cve_id}/{c.name}: {e}")

    print(f"[vulnwatch] {written} CVE scrise in {IDX} pentru host {sbom.host} ({len(sbom.components)} componente)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

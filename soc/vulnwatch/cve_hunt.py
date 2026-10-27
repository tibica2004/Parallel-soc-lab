"""cve_hunt — puntea dintre asset-vulns si vanatoarea Tier 3 (spec 1.5).

Pentru fiecare CVE nou cu cvss_score >= 7 SAU exploited_in_wild = true, produce
un job de hunting cu ipoteza fixa. NU executa nimic ofensiv: cauta in telemetrie
CONSECINTE ale exploatarii. Rezultatul huntului -> soc-incidents, cu referinta
la cve_id.

Design: cod pur, fara efecte, usor de testat. tier3.py doar apeleaza
pending_cve_hunts() la fiecare ciclu si trece fiecare job prin HuntRunner-ul
existent. Hook-ul minim din tier3.py e propus separat (nu-l aplic fara aprobare).
"""
from __future__ import annotations

import json
import os
from typing import Any

import requests

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
READ_KEY = os.environ.get("ES_API_KEY")
IDX = "asset-vulns"
STATE = os.environ.get("SOC_CVE_HUNT_STATE", "/var/lib/soc/cve_hunt_seen.json")
CVSS_THRESHOLD = 7.0
LOOKBACK_DAYS = 30


def _es(method, path, body=None):
    headers = {"Authorization": f"ApiKey {READ_KEY}", "Content-Type": "application/json"}
    return requests.request(method, f"{ES_URL}{path}", headers=headers,
                            data=json.dumps(body) if body is not None else None, timeout=30)


def _load_seen() -> set[str]:
    try:
        return set(json.load(open(STATE)))
    except Exception:
        return set()


def _save_seen(seen: set[str]) -> None:
    try:
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        json.dump(sorted(seen), open(STATE, "w"))
    except Exception as e:
        print(f"[cve_hunt] nu pot salva state: {e}", flush=True)


def build_hypothesis(v: dict[str, Any]) -> str:
    """Ipoteza fixa, in romana. Continutul din CVE (summary) e DATE, deci
    il incadram clar ca neincrezut si taiat (principiul 10)."""
    summary = (v.get("summary") or "").replace("\n", " ")[:300]
    return (
        f"Componenta {v.get('component')} {v.get('installed_version')} este afectata "
        f"de {v.get('cve_id')}. Descriere (UNTRUSTED, din feed CVE): \"{summary}\". "
        f"Cauta in telemetria ultimelor {LOOKBACK_DAYS} de zile dovezi de exploatare: "
        "requesturi catre endpoint-urile vulnerabile, procese neasteptate din "
        "apache2/php-fpm, fisiere noi in webroot, conexiuni outbound neobisnuite."
    )


def pending_cve_hunts() -> list[dict[str, Any]]:
    """Intoarce job-uri de hunt pentru CVE noi (nevazute) ce depasesc pragul.
    Fiecare job: {cve_id, component, host, hypothesis}. Marcheaza-le vazute
    doar dupa ce apelantul le-a rulat -> foloseste mark_hunted()."""
    q = {
        "size": 100,
        "query": {
            "bool": {
                "filter": [{"term": {"status": "open"}}],
                "should": [
                    {"range": {"cvss_score": {"gte": CVSS_THRESHOLD}}},
                    {"term": {"exploited_in_wild": True}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    r = _es("POST", f"/{IDX}/_search", q)
    if r.status_code != 200:
        print(f"[cve_hunt] search {r.status_code}: {r.text[:200]}", flush=True)
        return []
    seen = _load_seen()
    jobs = []
    for h in r.json().get("hits", {}).get("hits", []):
        src = h["_source"]
        key = f"{src.get('cve_id')}:{src.get('component')}"
        if key in seen:
            continue
        jobs.append({
            "cve_id": src.get("cve_id"),
            "component": src.get("component"),
            "host": src.get("host"),
            "exploited_in_wild": src.get("exploited_in_wild", False),
            "cvss_score": src.get("cvss_score", 0.0),
            "hypothesis": build_hypothesis(src),
        })
    return jobs


def mark_hunted(jobs: list[dict[str, Any]]) -> None:
    seen = _load_seen()
    for j in jobs:
        seen.add(f"{j['cve_id']}:{j['component']}")
    _save_seen(seen)


if __name__ == "__main__":
    # rulare manuala: afiseaza ce hunt-uri ar porni, fara sa le marcheze.
    for j in pending_cve_hunts():
        print(f"- {j['cve_id']} ({j['component']}, cvss={j['cvss_score']}, "
              f"kev={j['exploited_in_wild']})")
        print(f"    {j['hypothesis']}")

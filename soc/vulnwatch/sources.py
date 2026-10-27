"""Clienti pentru sursele de vulnerabilitati: OSV, NVD, CISA KEV, Wordfence.
Fiecare client esueaza GRATIOS: daca sursa cade, logheaza si intoarce [] / set()
gol, nu arunca. Nimic din aici nu atinge tinta; doar API-uri publice.

Toate functiile intorc dict-uri cu chei compatibile cu VulnRecord
(cve_id, affected_range, fixed_version, cvss_score, cvss_vector, source, summary).
Campurile host/component/installed_version/first_seen/last_seen le pune apelantul.
"""
from __future__ import annotations

import json
import os
import time

import requests

UA = {"User-Agent": "soc-vulnwatch/1.0 (defensive asset monitoring)"}
TIMEOUT = 20
CACHE_DIR = os.environ.get("SOC_CACHE_DIR", "/var/lib/soc/cache")

# OSV ecosystem per tip de componenta (best-effort)
OSV_ECO = {"wp-core": "WordPress", "wp-plugin": "WordPress",
           "wp-theme": "WordPress", "deb": "Debian"}


def _cached_json_get(url: str, cache_name: str, ttl: int = 86400):
    """GET cu cache local pe disc. La esec, incearca cache-ul vechi."""
    cache = os.path.join(CACHE_DIR, cache_name)
    try:
        if os.path.exists(cache) and time.time() - os.path.getmtime(cache) < ttl:
            return json.load(open(cache))
    except Exception:
        pass
    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(cache, "w") as f:
            json.dump(data, f)
        return data
    except Exception as e:
        print(f"[vulnwatch] GET {url} esuat: {e}", flush=True)
        try:
            return json.load(open(cache))
        except Exception:
            return None


# ---------------------------------------------------------------- CISA KEV
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_kev() -> set[str]:
    data = _cached_json_get(KEV_URL, "kev.json")
    ids: set[str] = set()
    if data:
        for v in data.get("vulnerabilities", []):
            cid = v.get("cveID")
            if cid:
                ids.add(cid.upper())
    print(f"[vulnwatch] CISA KEV: {len(ids)} CVE exploatate in salbaticie", flush=True)
    return ids


# ---------------------------------------------------------------- OSV
OSV_URL = "https://api.osv.dev/v1/query"


def _osv_cvss(v: dict) -> tuple[float, str]:
    for sev in v.get("severity", []) or []:
        if sev.get("type", "").startswith("CVSS") and sev.get("score"):
            vec = sev["score"]
            score = 0.0
            # severity.score la OSV e vectorul; scorul numeric e in database_specific
            ds = v.get("database_specific", {}) or {}
            try:
                score = float(ds.get("cvss_score") or 0.0)
            except Exception:
                score = 0.0
            return score, vec
    return 0.0, ""


def _osv_fixed(v: dict) -> tuple[str, str]:
    fixed, ranges = "", []
    for aff in v.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if ev.get("introduced"):
                    ranges.append(f">={ev['introduced']}")
                if ev.get("fixed"):
                    fixed = ev["fixed"]
                    ranges.append(f"<{ev['fixed']}")
    return fixed, ",".join(ranges)


def normalize_osv(v: dict, ctype: str) -> dict:
    cid = v.get("id", "")
    # OSV poate intoarce id-uri GHSA; cauta un alias CVE
    cve = cid if cid.upper().startswith("CVE") else ""
    for al in v.get("aliases", []) or []:
        if al.upper().startswith("CVE"):
            cve = al
            break
    score, vec = _osv_cvss(v)
    fixed, rng = _osv_fixed(v)
    return {
        "cve_id": cve or cid,
        "affected_range": rng,
        "fixed_version": fixed,
        "cvss_score": score,
        "cvss_vector": vec,
        "source": "osv",
        "summary": (v.get("summary") or v.get("details") or "")[:1000],
        "status": "open",
    }


def query_osv(name: str, version: str, ctype: str) -> list[dict]:
    eco = OSV_ECO.get(ctype)
    payloads = []
    if eco:
        payloads.append({"package": {"name": name, "ecosystem": eco}, "version": version})
    payloads.append({"package": {"name": name}, "version": version})
    for p in payloads:
        try:
            r = requests.post(OSV_URL, json=p, headers=UA, timeout=TIMEOUT)
            if r.status_code == 200:
                vulns = r.json().get("vulns", []) or []
                if vulns:
                    return [normalize_osv(v, ctype) for v in vulns]
        except Exception as e:
            print(f"[vulnwatch] OSV {name}: {e}", flush=True)
    return []


# ---------------------------------------------------------------- NVD
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_nvd(name: str, version: str, ctype: str) -> list[dict]:
    # keywordSearch simplu; filtram local pe cpe cand e posibil.
    kw = f"{name} {version}".strip()
    params = {"keywordSearch": kw, "resultsPerPage": 20}
    try:
        r = requests.get(NVD_URL, params=params, headers=UA, timeout=TIMEOUT)
        if r.status_code != 200:
            return []
        out = []
        for item in r.json().get("vulnerabilities", []) or []:
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            if not cid.upper().startswith("CVE"):
                continue
            score, vec = 0.0, ""
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    d = metrics[key][0].get("cvssData", {})
                    score = float(d.get("baseScore") or 0.0)
                    vec = d.get("vectorString", "")
                    break
            desc = ""
            for d in cve.get("descriptions", []) or []:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            out.append({
                "cve_id": cid,
                "affected_range": "",
                "fixed_version": "",
                "cvss_score": score,
                "cvss_vector": vec,
                "source": "nvd",
                "summary": desc[:1000],
                "status": "open",
            })
        # pastram doar CVE cu scor (reduce zgomotul keywordSearch)
        return [o for o in out if o["cvss_score"] > 0]
    except Exception as e:
        print(f"[vulnwatch] NVD {name}: {e}", flush=True)
        return []


# ---------------------------------------------------------------- Wordfence (optional)
# Feed-ul 'production' din spec intoarce 410 (URL invechit). Incercam, apoi
# WPScan API daca exista cheie, altfel sarim gratios.
WORDFENCE_URL = os.environ.get(
    "WORDFENCE_FEED_URL",
    "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production",
)


def query_wordfence(name: str, version: str, ctype: str) -> list[dict]:
    data = _cached_json_get(WORDFENCE_URL, "wordfence.json")
    if not data:
        return []  # 410 / indisponibil -> gratios
    out = []
    try:
        entries = data.values() if isinstance(data, dict) else data
        for v in entries:
            soft = v.get("software", []) or []
            if not any(s.get("slug") == name for s in soft):
                continue
            cves = v.get("cve")
            cid = cves if isinstance(cves, str) else (cves[0] if cves else "")
            if not cid:
                continue
            out.append({
                "cve_id": cid,
                "affected_range": "",
                "fixed_version": "",
                "cvss_score": float((v.get("cvss") or {}).get("score") or 0.0),
                "cvss_vector": (v.get("cvss") or {}).get("vector", ""),
                "source": "wordfence",
                "summary": (v.get("title") or "")[:1000],
                "status": "open",
            })
    except Exception as e:
        print(f"[vulnwatch] Wordfence parse {name}: {e}", flush=True)
    return out

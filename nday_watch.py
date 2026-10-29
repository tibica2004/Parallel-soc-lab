#!/usr/bin/env python3
"""
N-DAY WATCH (pasul 1.B) — corelatie determinista intre componentele instalate pe
web-prod (SBOM colectat la 1.A) si vulnerabilitati publice cunoscute.

Rulati pe es-node-1 dintr-un timer (soc-nday.timer, 04:00). Fluxul, tot determinist:

  1. load_latest_sbom(es_ro): ultimul doc din logs-soc.sbom-* pentru host web-prod.
  2. Pentru Apache / PHP / WordPress core: OSV (querybatch) + NVD (CPE). Acestea au
     identificatori stabili (purl pkg:generic, cpe:2.3). OSV NU are ecosistem
     WordPress (corectia A2), deci pluginurile/temele NU trec pe aici.
  3. Pentru plugin-uri si teme: WPScan (cache local 24h) si/sau feedul Wordfence.
     Daca niciuna nu e disponibila pentru un slug -> needs_review=true, NU se arunca.
  4. Fiecare potrivire -> VulnRecord (Pydantic, extra=forbid; fara exploit/poc/payload,
     E2). cvss -> severity. Comparatia de versiuni reutilizeaza exposure.in_range;
     versiunea neparsabila -> needs_review (prudent), nu "nevulnerabil".
  5. upsert in asset-vulns cu _id FIX = sha256(host+cve+component) -> idempotent.
     Reaparitie -> last_seen=now; installed >= fixed -> resolved=true.
  6. Pentru fiecare VulnRecord NOU cu cvss>=7 sau patch_available -> hunt_request in
     soc-incidents (pentru Tier 3). Pentru patch manual (B2) -> patch_request.
  7. write_metrics -> soc-metrics (type=nday).

Principii (CLAUDE.md): codul decide, modelul NU e implicat aici deloc. Niciun camp
din telemetrie (nume de plugin, versiune) nu ajunge intr-un sir de interogare ES:
Query DSL cu term/match, valori ca string. Esecul de retea escaladeaza spre
needs_review, nu arunca componenta. Global try/except -> exit 1, fara print (R14).

Chei: ES_API_KEY (citeste logs-soc.sbom-*), ES_VULNS_WRITER_API_KEY (asset-vulns),
ES_INCIDENTS_WRITER_API_KEY (soc-incidents), ES_METRICS_WRITER_API_KEY (soc-metrics).
Optional: NVD_API_KEY, WPSCAN_API_KEY. Niciun secret in cod (R15).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from elasticsearch import Elasticsearch
from pydantic import BaseModel, ConfigDict, Field, field_validator

from exposure import in_range, parse_version

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s",
                    stream=sys.stderr)
log = logging.getLogger("soc.nday")

ROOT = Path(__file__).resolve().parent

# --- configuratie din mediu (implicite sigure) --------------------------------
SBOM_INDEX = os.environ.get("NDAY_SBOM_INDEX", "logs-soc.sbom-*")
VULNS_INDEX = os.environ.get("NDAY_VULNS_INDEX", "asset-vulns")
INCIDENTS_INDEX = os.environ.get("NDAY_INCIDENTS_INDEX", "soc-incidents")
METRICS_INDEX = os.environ.get("NDAY_METRICS_INDEX", "soc-metrics")
HOST = os.environ.get("NDAY_HOST", "web-prod")

HTTP_TIMEOUT = float(os.environ.get("NDAY_HTTP_TIMEOUT", "30"))
HTTP_RETRIES = int(os.environ.get("NDAY_HTTP_RETRIES", "3"))
WPSCAN_CACHE_TTL_S = int(os.environ.get("NDAY_WPSCAN_CACHE_TTL_S", str(24 * 3600)))
CACHE_DIR = Path(os.environ.get("NDAY_CACHE_DIR", str(ROOT / "data" / "nday-cache")))
# Flag pentru teste hermetice: sare peste orice retea; totul -> needs_review.
OFFLINE = os.environ.get("NDAY_OFFLINE", "0") == "1"
# Prag + plafon pentru hunt-uri, ca sa nu inundam tier3: primesc hunt DOAR
# inregistrarile NOI, confirmate (needs_review=False), cu cvss >= HUNT_MIN_CVSS;
# dintre ele, cele mai severe HUNT_MAX per rulare. Restul raman in asset-vulns
# pentru triaj uman. Ambele reglabile din mediu.
HUNT_MIN_CVSS = float(os.environ.get("NDAY_HUNT_MIN_CVSS", "9.0"))  # 9.0 = doar critical
HUNT_MAX = int(os.environ.get("NDAY_HUNT_MAX", "10"))

OSV_URL = "https://api.osv.dev/v1/querybatch"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WPSCAN_URL = "https://wpscan.com/api/v3"

# Componentele pentru care avem identificatori stabili CPE/purl (A2).
CPE_VENDOR_PRODUCT = {
    "apache": ("apache", "http_server"),
    "php": ("php", "php"),
    "wp_core": ("wordpress", "wordpress"),
}
SEVERITIES = ("low", "medium", "high", "critical")
CVE_SOURCES = ("osv", "nvd", "wporg", "wpscan", "patchstack", "wordfence")
CVSS_UNKNOWN = -1.0  # marcam lipsa scorului; devine severity "medium" prudent


# =============================================================================
# FUNCTII PURE (testabile fara retea si fara Elasticsearch)
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cvss_to_severity(cvss: float | None) -> str:
    """<4 low, <7 medium, <9 high, >=9 critical. Scor necunoscut -> medium (prudent)."""
    if cvss is None or cvss < 0:
        return "medium"
    if cvss < 4:
        return "low"
    if cvss < 7:
        return "medium"
    if cvss < 9:
        return "high"
    return "critical"


def vuln_id(host: str, cve: str, component_name: str) -> str:
    """_id stabil in asset-vulns -> upsert idempotent, zero duplicate."""
    raw = f"{host}\0{cve.upper()}\0{component_name.lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def to_cpe(component_type: str, version: str) -> str | None:
    """cpe:2.3 pentru componentele cu identificator stabil (apache/php/wp_core)."""
    vp = CPE_VENDOR_PRODUCT.get(component_type)
    if not vp or parse_version(version) is None:
        return None
    vendor, product = vp
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def to_purl(component_type: str, version: str) -> str | None:
    """purl pkg:generic pentru OSV (doar apache/php/wp_core; A2)."""
    name = {"apache": "apache", "php": "php", "wp_core": "wordpress"}.get(component_type)
    if not name or parse_version(version) is None:
        return None
    return f"pkg:generic/{name}@{version}"


def osv_affects(installed: str, affected: list[dict]) -> tuple[bool, str | None, bool]:
    """
    Potrivire determinista installed vs. intervalele OSV. Returneaza
    (vulnerabil, fixed_version, needs_review). O versiune neparsabila sau un
    interval pe care nu-l intelegem -> needs_review=true, NU "nevulnerabil".
    """
    if parse_version(installed) is None:
        return (False, None, True)
    needs_review = False
    for aff in affected or []:
        for rng in aff.get("ranges", []) or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER", "GIT"):
                needs_review = True
                continue
            introduced, fixed = "0", None
            for ev in rng.get("events", []) or []:
                if "introduced" in ev:
                    introduced = ev["introduced"] or "0"
                elif "fixed" in ev:
                    fixed = ev["fixed"]
                elif "last_affected" in ev or "limit" in ev:
                    needs_review = True
            if introduced == "0" and parse_version("0") is None:
                needs_review = True
                continue
            if fixed is not None and parse_version(fixed) is None:
                needs_review = True
                continue
            if in_range(installed, introduced if introduced != "0" else "0", fixed):
                return (True, fixed, needs_review)
        # versiuni exacte enumerate (fara range)
        for v in aff.get("versions", []) or []:
            if v == installed:
                return (True, None, needs_review)
    return (False, None, needs_review)


def _version_cmp(a: str, b: str) -> int | None:
    """-1/0/1 comparand doua versiuni (completate cu 0). Neparsabil -> None."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        return None
    n = max(len(pa), len(pb))
    pa, pb = pa + (0,) * (n - len(pa)), pb + (0,) * (n - len(pb))
    return (pa > pb) - (pa < pb)


def nvd_affects(component_type: str, installed: str,
                cve_obj: dict) -> tuple[bool, str | None, bool]:
    """
    Confirma daca versiunea instalata e in intervalul vulnerabil declarat de NVD
    (configurations[].nodes[].cpeMatch[] cu vulnerable=true, pentru produsul nostru).
    Returneaza (vulnerabil, fixed_version, needs_review). Un interval pe care nu-l
    putem parsa -> needs_review=true (prudent: nu confirmam, dar nici nu aruncam).
    O versiune exacta in CPE se potriveste doar la egalitate; versionEndExcluding
    devine fixed_version. Fara configurations utile -> needs_review=true.
    """
    vp = CPE_VENDOR_PRODUCT.get(component_type)
    if vp is None or parse_version(installed) is None:
        return (False, None, True)
    vendor, product = vp
    prefix = f"cpe:2.3:a:{vendor}:{product}:"
    saw = False            # am vazut vreun cpeMatch pentru produsul nostru
    unparsable = False     # un interval pe care nu l-am putut compara
    for conf in cve_obj.get("configurations", []) or []:
        for node in conf.get("nodes", []) or []:
            for m in node.get("cpeMatch", []) or []:
                if not m.get("vulnerable"):
                    continue
                crit = m.get("criteria", "") or ""
                if not crit.startswith(prefix):
                    continue
                saw = True
                parts = crit.split(":")
                exact = parts[5] if len(parts) > 5 else "*"
                if exact not in ("*", "-", ""):
                    c = _version_cmp(installed, exact)
                    if c is None:
                        unparsable = True
                    elif c == 0:
                        return (True, None, False)
                    continue
                ok = True
                for bound, op in ((m.get("versionStartIncluding"), "ge"),
                                  (m.get("versionStartExcluding"), "gt"),
                                  (m.get("versionEndIncluding"), "le"),
                                  (m.get("versionEndExcluding"), "lt")):
                    if bound is None:
                        continue
                    c = _version_cmp(installed, bound)
                    if c is None:
                        ok = False
                        unparsable = True
                        break
                    if ((op == "ge" and c < 0) or (op == "gt" and c <= 0)
                            or (op == "le" and c > 0) or (op == "lt" and c >= 0)):
                        ok = False
                        break
                if ok:
                    ee = m.get("versionEndExcluding")
                    return (True, ee if ee else None, False)
    # niciun interval confirmat: needs_review daca n-am putut parsa ceva relevant
    # sau daca produsul nici n-a aparut (NVD l-a intors, dar fara config utile)
    return (False, None, unparsable or not saw)


def is_update_available(installed: str, current: str) -> bool:
    """installed < current (ambele parsabile) -> exista update (semnal, nu CVE)."""
    pi, pc = parse_version(installed), parse_version(current)
    if pi is None or pc is None:
        return False
    n = max(len(pi), len(pc))
    pi, pc = pi + (0,) * (n - len(pi)), pc + (0,) * (n - len(pc))
    return pi < pc


# =============================================================================
# SCHEMA DE GRANITA (extra=forbid; fara exploit/poc/payload — E2)
# =============================================================================

class VulnRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve: str
    component_type: str
    component_name: str
    installed_version: str
    fixed_version: str | None = None
    cvss: float | None = None
    severity: str
    patch_available: bool = False
    first_seen: str
    last_seen: str
    resolved: bool = False
    resolved_at: str | None = None
    source: str
    summary: str = ""
    references: list[str] = Field(default_factory=list)
    host: str
    hunt_requested: bool = False
    needs_review: bool = False

    @field_validator("cve")
    @classmethod
    def _cve_shape(cls, v: str) -> str:
        v = v.strip().upper()
        # acceptam CVE-... si identificatori WPScan/GHSA (string opac, fara spatii)
        if not v or len(v) > 64 or any(c.isspace() for c in v):
            raise ValueError(f"identificator vuln invalid: {v!r}")
        return v

    @field_validator("severity")
    @classmethod
    def _sev(cls, v: str) -> str:
        if v not in SEVERITIES:
            raise ValueError(f"severitate invalida: {v!r}")
        return v

    @field_validator("component_type")
    @classmethod
    def _ctype(cls, v: str) -> str:
        if v not in ("apache", "php", "wp_core", "plugin", "theme"):
            raise ValueError(f"tip componenta invalid: {v!r}")
        return v


# =============================================================================
# RETEA (thin; esecul -> needs_review, nu exceptie care arunca componenta)
# =============================================================================

def _http_get(url: str, params: dict | None = None, headers: dict | None = None):
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            r = requests.get(url, params=params, headers=headers, timeout=HTTP_TIMEOUT)
            if r.status_code == 429 or r.status_code >= 500:
                raise requests.RequestException(f"status {r.status_code}")
            return r
        except requests.RequestException as e:
            log.warning("GET %s esuat (incercarea %d/%d): %s", url, attempt, HTTP_RETRIES, e)
            if attempt < HTTP_RETRIES:
                time.sleep(2 ** attempt)
    return None


def _http_post(url: str, payload: dict):
    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            r = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)
            if r.status_code == 429 or r.status_code >= 500:
                raise requests.RequestException(f"status {r.status_code}")
            return r
        except requests.RequestException as e:
            log.warning("POST %s esuat (incercarea %d/%d): %s", url, attempt, HTTP_RETRIES, e)
            if attempt < HTTP_RETRIES:
                time.sleep(2 ** attempt)
    return None


def query_osv_batch(purls: list[str]) -> dict[str, list[dict]]:
    """purl -> lista de vulnerabilitati OSV (doc complet per CVE). Esec -> {}."""
    if OFFLINE or not purls:
        return {}
    queries = [{"package": {"purl": p}} for p in purls]
    r = _http_post(OSV_URL, {"queries": queries})
    if r is None or r.status_code != 200:
        return {}
    out: dict[str, list[dict]] = {}
    results = (r.json() or {}).get("results", [])
    for purl, res in zip(purls, results):
        ids = [v.get("id") for v in (res or {}).get("vulns", []) if v.get("id")]
        vulns = []
        for vid in ids:
            d = _http_get(f"https://api.osv.dev/v1/vulns/{vid}")
            if d is not None and d.status_code == 200:
                vulns.append(d.json())
        out[purl] = vulns
    return out


def query_nvd(cpe: str, api_key: str | None) -> list[dict]:
    """Vulnerabilitati NVD pentru un CPE. Rate limit respectat (sleep). Esec -> []."""
    if OFFLINE:
        return []
    headers = {"apiKey": api_key} if api_key else None
    r = _http_get(NVD_URL, params={"cpeName": cpe}, headers=headers)
    # 5 req/30s fara cheie, 50 cu cheie; conservator intre apeluri
    time.sleep(0.6 if api_key else 6.5)
    if r is None or r.status_code != 200:
        return []
    return (r.json() or {}).get("vulnerabilities", [])


def _wpscan_cache_path(slug: str) -> Path:
    safe = hashlib.sha256(slug.encode("utf-8")).hexdigest()[:16]
    return CACHE_DIR / "wpscan" / f"{safe}.json"


def query_wpscan(slug: str, api_key: str | None) -> dict | None:
    """
    WPScan pentru un plugin/tema (cache local 24h per slug, limita planului gratuit).
    Returneaza dict-ul brut sau None (necunoscut -> apelantul pune needs_review).
    """
    cache = _wpscan_cache_path(slug)
    if cache.is_file() and (time.time() - cache.stat().st_mtime) < WPSCAN_CACHE_TTL_S:
        try:
            return json.loads(cache.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    if OFFLINE or not api_key:
        return None
    r = _http_get(f"{WPSCAN_URL}/plugins/{slug}",
                  headers={"Authorization": f"Token token={api_key}"})
    if r is None or r.status_code != 200:
        return None
    data = r.json()
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(data), encoding="utf-8")
    except OSError as e:
        log.warning("nu pot scrie cache WPScan pentru %s: %s", slug, e)
    return data


# =============================================================================
# ELASTICSEARCH
# =============================================================================

def es_client(key_env: str) -> Elasticsearch:
    """Client ES pentru cheia din mediu. FARA fallback: o cheie lipsa trebuie sa
    opreasca rularea (R9 — esecul escaladeaza), NU sa cada tacut pe alta cheie.
    In special cheile de SCRIERE nu au voie sa cada pe ES_API_KEY (read-only):
    fiecare upsert ar primi 403, l-am inghiti in api_errors si rularea ar iesi 0
    fara sa scrie nimic = esec tacut, exact ce interzice R9."""
    key = os.environ.get(key_env)
    if not key:
        raise RuntimeError(f"lipseste cheia {key_env}")
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                         api_key=key, request_timeout=30)


def es_client_optional(key_env: str) -> Elasticsearch | None:
    """Ca es_client, dar o cheie lipsa -> None (nu opreste rularea). Doar pentru
    metrici: observabilitatea nu trebuie sa doboare scrierea de vulnerabilitati."""
    return es_client(key_env) if os.environ.get(key_env) else None


def load_latest_sbom(es: Elasticsearch) -> dict | None:
    """Ultimul document SBOM pentru host (sort @timestamp desc, size 1). A1: citim
    din logs-soc.sbom-*, nu din asset-inventory. Query DSL parametrizat (term)."""
    body = {
        "size": 1,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [{"term": {"host": HOST}}]}},
        "_source": ["@timestamp", "host", "components"],
    }
    try:
        r = es.search(index=SBOM_INDEX, body=body)
    except Exception as e:  # noqa: BLE001 — orice eroare ES e nefatala aici
        log.error("citire SBOM esuata: %s", e)
        return None
    hits = r.get("hits", {}).get("hits", [])
    if not hits:
        # unele pipeline-uri pun campurile sub 'host.name'; incercam o data
        body["query"]["bool"]["filter"] = [{"term": {"host.name": HOST}}]
        try:
            r = es.search(index=SBOM_INDEX, body=body)
            hits = r.get("hits", {}).get("hits", [])
        except Exception:  # noqa: BLE001
            return None
    return hits[0]["_source"] if hits else None


def upsert_vuln(es: Elasticsearch, rec: VulnRecord) -> str:
    """
    Scrie/actualizeaza o vulnerabilitate cu _id fix. Daca exista deja: pastreaza
    first_seen/hunt_requested, improspateaza last_seen; marcheaza resolved cand
    versiunea instalata a trecut de fixed. Fara delete. Returneaza:
      'new'             — nu exista inainte;
      'newly_confirmed' — exista ca needs_review, acum e confirmat si inca nevanaut
                          (merita un hunt chiar daca documentul nu e nou);
      'update'          — orice alta actualizare.
    """
    _id = vuln_id(rec.host, rec.cve, rec.component_name)
    try:
        existing = es.get(index=VULNS_INDEX, id=_id)["_source"]
    except Exception:  # noqa: BLE001 — not found sau index nou
        existing = None

    doc = rec.model_dump()
    if existing:
        doc["first_seen"] = existing.get("first_seen", rec.first_seen)
        doc["hunt_requested"] = existing.get("hunt_requested", False) or rec.hunt_requested
        doc["last_seen"] = rec.last_seen
        was_review = existing.get("needs_review", True)
        already_hunted = existing.get("hunt_requested", False)
        if was_review and not rec.needs_review and not already_hunted:
            disposition = "newly_confirmed"
        else:
            disposition = "update"
    else:
        disposition = "new"

    # resolved daca installed >= fixed
    if rec.fixed_version and parse_version(rec.installed_version) and parse_version(rec.fixed_version):
        if not in_range(rec.installed_version, "0", rec.fixed_version):
            doc["resolved"] = True
            doc["resolved_at"] = rec.last_seen

    es.index(index=VULNS_INDEX, id=_id, document=doc)
    return disposition


def request_hunt(es: Elasticsearch, rec: VulnRecord) -> None:
    """hunt_request in soc-incidents pentru Tier 3 (cvss>=7 sau patch_available)."""
    doc = {
        "type": "hunt_request", "status": "pending", "created": now_iso(),
        "cve": rec.cve, "component_name": rec.component_name,
        "installed_version": rec.installed_version,
        "hypothesis": (
            f"Componenta {rec.component_name} {rec.installed_version} are {rec.cve}. "
            "Verifica semne de exploatare in ultimele 30 de zile: request-uri catre "
            "endpoint-urile componentei cu status anormal, procese copil ale "
            "apache/php-fpm, fisiere noi in webroot, conexiuni outbound noi."
        ),
        "lookback_days": 30, "attack_techniques": [], "source": "nday_watch",
    }
    es.index(index=INCIDENTS_INDEX, document=doc)


def request_patch(es: Elasticsearch, rec: VulnRecord, remediation: str) -> None:
    """patch_request (B2) pentru patch manual. NU executa patch-ul (ramane la om)."""
    doc = {
        "type": "patch_request", "status": "pending", "created": now_iso(),
        "cve": rec.cve, "component_name": rec.component_name,
        "installed_version": rec.installed_version, "fixed_version": rec.fixed_version,
        "remediation": remediation, "severity": rec.severity, "source": "nday_watch",
    }
    es.index(index=INCIDENTS_INDEX, document=doc)


def mark_hunt_requested(es: Elasticsearch, rec: VulnRecord) -> None:
    """Dupa ce am creat hunt-ul, marcheaza inregistrarea in asset-vulns ca sa nu-l
    reluam (upsert-ul urmator o vede 'update' oricum; flagul reflecta realitatea)."""
    _id = vuln_id(rec.host, rec.cve, rec.component_name)
    es.update(index=VULNS_INDEX, id=_id, doc={"hunt_requested": True})


def write_metrics(es: Elasticsearch | None, metrics: dict) -> None:
    if es is None:
        log.warning("fara ES_METRICS_WRITER_API_KEY; sar peste metrici: %s",
                    json.dumps(metrics))
        return
    # @timestamp (nu ts): campul standard Kibana, acelasi pe care il scrie orchestratorul,
    # ca metricile nday sa apara pe aceeasi axa de timp in dashboard (pasul 7).
    doc = {"type": "nday", "@timestamp": now_iso(), **metrics}
    try:
        es.index(index=METRICS_INDEX, document=doc)
    except Exception as e:  # noqa: BLE001 — metricile nu trebuie sa opreasca rularea
        log.warning("scriere metrici esuata: %s", e)


# =============================================================================
# ORCHESTRARE
# =============================================================================

def iter_sbom_components(sbom: dict):
    """Normalizeaza lista de componente din SBOM. Valorile (nume/versiune) sunt DATE."""
    for c in sbom.get("components", []) or []:
        if not isinstance(c, dict):
            continue
        ctype = str(c.get("type") or "").strip()
        name = str(c.get("name") or "").strip()
        version = str(c.get("version") or "").strip()
        if ctype and name and version:
            yield ctype, name, version


def build_core_records(ctype: str, name: str, version: str,
                       osv_by_purl: dict, nvd_vulns: list[dict]) -> list[VulnRecord]:
    """VulnRecord-uri pentru apache/php/wp_core din OSV + NVD (dedup pe CVE)."""
    records: dict[str, VulnRecord] = {}
    ts = now_iso()

    purl = to_purl(ctype, version)
    for vuln in osv_by_purl.get(purl or "", []):
        cve = vuln.get("id", "")
        if not cve:
            continue
        vulnerable, fixed, needs_review = osv_affects(version, vuln.get("affected", []))
        if not vulnerable and not needs_review:
            continue
        cvss = _osv_cvss(vuln)
        records[cve.upper()] = VulnRecord(
            cve=cve, component_type=ctype, component_name=name,
            installed_version=version, fixed_version=fixed, cvss=cvss,
            severity=cvss_to_severity(cvss), patch_available=bool(fixed),
            first_seen=ts, last_seen=ts, source="osv",
            summary=str(vuln.get("summary") or "")[:500],
            references=[r.get("url", "") for r in vuln.get("references", []) if r.get("url")][:10],
            host=HOST, needs_review=needs_review or not vulnerable,
        )

    for item in nvd_vulns:
        cve_obj = item.get("cve", {})
        cve = cve_obj.get("id", "")
        if not cve or cve.upper() in records:
            continue
        vulnerable, fixed, needs_review = nvd_affects(ctype, version, cve_obj)
        if not vulnerable and not needs_review:
            continue
        cvss = _nvd_cvss(cve_obj)
        records[cve.upper()] = VulnRecord(
            cve=cve, component_type=ctype, component_name=name,
            installed_version=version, fixed_version=fixed, cvss=cvss,
            severity=cvss_to_severity(cvss), patch_available=bool(fixed),
            first_seen=ts, last_seen=ts, source="nvd",
            summary=_nvd_summary(cve_obj)[:500],
            references=[r.get("url", "") for r in cve_obj.get("references", []) if r.get("url")][:10],
            host=HOST, needs_review=needs_review or not vulnerable,
        )
    return list(records.values())


def build_plugin_records(ctype: str, slug: str, version: str,
                         wpscan: dict | None) -> list[VulnRecord]:
    """VulnRecord-uri pentru un plugin/tema din WPScan. Necunoscut -> needs_review."""
    ts = now_iso()
    if wpscan is None:
        # semnalam ca nu stim, fara sa inventam un CVE
        return [VulnRecord(
            cve="UNKNOWN-NO-FEED", component_type=ctype, component_name=slug,
            installed_version=version, severity="medium", first_seen=ts, last_seen=ts,
            source="wpscan", summary="fara date WPScan/Wordfence pentru acest slug",
            host=HOST, needs_review=True,
        )]
    records: list[VulnRecord] = []
    node = wpscan.get(slug, wpscan)
    for v in node.get("vulnerabilities", []) or []:
        fixed = (v.get("fixed_in") or None)
        vulnerable = True
        needs_review = False
        if fixed and parse_version(fixed) and parse_version(version):
            vulnerable = in_range(version, "0", fixed)
        elif fixed is None:
            needs_review = True
        if not vulnerable and not needs_review:
            continue
        cve_list = (v.get("references", {}) or {}).get("cve", [])
        cve = f"CVE-{cve_list[0]}" if cve_list else f"WPSCAN-{v.get('id', 'NA')}"
        cvss = _wpscan_cvss(v)
        records.append(VulnRecord(
            cve=cve, component_type=ctype, component_name=slug,
            installed_version=version, fixed_version=fixed, cvss=cvss,
            severity=cvss_to_severity(cvss), patch_available=bool(fixed),
            first_seen=ts, last_seen=ts, source="wpscan",
            summary=str(v.get("title") or "")[:500],
            host=HOST, needs_review=needs_review,
        ))
    return records


def _osv_cvss(vuln: dict) -> float | None:
    for sev in vuln.get("severity", []) or []:
        score = sev.get("score", "")
        # OSV da vectorul CVSS; extragem scorul numeric daca e prezent separat
        if isinstance(score, (int, float)):
            return float(score)
    db = vuln.get("database_specific", {}) or {}
    s = db.get("cvss", {}).get("score") if isinstance(db.get("cvss"), dict) else None
    return float(s) if isinstance(s, (int, float)) else None


def _nvd_cvss(cve_obj: dict) -> float | None:
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            try:
                return float(arr[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError, ValueError):
                continue
    return None


def _nvd_summary(cve_obj: dict) -> str:
    for d in cve_obj.get("descriptions", []) or []:
        if d.get("lang") == "en":
            return str(d.get("value") or "")
    return ""


def _wpscan_cvss(v: dict) -> float | None:
    cvss = v.get("cvss") or {}
    s = cvss.get("score") if isinstance(cvss, dict) else None
    try:
        return float(s) if s is not None else None
    except (TypeError, ValueError):
        return None


def run() -> int:
    es_ro = es_client("ES_API_KEY")                       # citeste SBOM; fara el nu pornim
    es_vulns = es_client("ES_VULNS_WRITER_API_KEY")       # scrie asset-vulns; hard-fail daca lipseste
    es_inc = es_client("ES_INCIDENTS_WRITER_API_KEY")     # scrie hunt/patch_request; hard-fail
    es_met = es_client_optional("ES_METRICS_WRITER_API_KEY")  # metrici optionale (None -> skip)

    nvd_key = os.environ.get("NVD_API_KEY")
    wpscan_key = os.environ.get("WPSCAN_API_KEY")

    sbom = load_latest_sbom(es_ro)
    if not sbom:
        log.error("niciun SBOM pentru host %s in %s", HOST, SBOM_INDEX)
        write_metrics(es_met, {"error": "no_sbom", "host": HOST})
        return 1

    components = list(iter_sbom_components(sbom))
    core = [(t, n, v) for (t, n, v) in components if t in CPE_VENDOR_PRODUCT]
    plugins = [(t, n, v) for (t, n, v) in components if t in ("plugin", "theme")]

    # OSV in lot pentru componentele core
    purls = [p for (t, _n, v) in core if (p := to_purl(t, v))]
    osv_by_purl = query_osv_batch(purls)

    m = {"components_total": len(components), "vulns_open": 0, "vulns_critical": 0,
         "vulns_patch_available": 0, "vulns_resolved_today": 0, "needs_review_count": 0,
         "api_errors": 0, "hunt_candidates": 0, "hunts_requested": 0,
         "patch_requests": 0, "host": HOST}

    all_records: list[VulnRecord] = []
    for (ctype, name, version) in core:
        cpe = to_cpe(ctype, version)
        nvd_vulns = query_nvd(cpe, nvd_key) if cpe else []
        all_records += build_core_records(ctype, name, version, osv_by_purl, nvd_vulns)

    for (ctype, slug, version) in plugins:
        wpscan = query_wpscan(slug, wpscan_key)
        all_records += build_plugin_records(ctype, slug, version, wpscan)

    # Faza 1: upsert toate; aduna candidatii de hunt = NOI, confirmati (nu needs_review,
    # nu resolved), cu cvss >= HUNT_MIN_CVSS. hunt_requested se seteaza abia in Faza 2,
    # doar pe setul plafonat (altfel am marca si cele pe care nu le vanam).
    hunt_candidates: list[VulnRecord] = []
    for rec in all_records:
        try:
            disposition = upsert_vuln(es_vulns, rec)
        except Exception as e:  # noqa: BLE001
            log.error("upsert esuat pentru %s/%s: %s", rec.component_name, rec.cve, e)
            m["api_errors"] += 1
            continue

        m["needs_review_count"] += int(rec.needs_review)
        if not rec.resolved:
            m["vulns_open"] += 1
            m["vulns_critical"] += int(rec.severity == "critical")
            m["vulns_patch_available"] += int(rec.patch_available)
        else:
            m["vulns_resolved_today"] += 1

        if (disposition in ("new", "newly_confirmed") and not rec.resolved
                and not rec.needs_review
                and rec.cvss is not None and rec.cvss >= HUNT_MIN_CVSS):
            hunt_candidates.append(rec)

    # Faza 2: plafon ca sa nu inundam tier3 — cei mai severi HUNT_MAX primesc hunt
    # (+ patch_request daca exista fix). Restul raman in asset-vulns pentru triaj.
    m["hunt_candidates"] = len(hunt_candidates)
    hunt_candidates.sort(key=lambda r: r.cvss or 0.0, reverse=True)
    for rec in hunt_candidates[:HUNT_MAX]:
        try:
            request_hunt(es_inc, rec)
            mark_hunt_requested(es_vulns, rec)
            m["hunts_requested"] += 1
        except Exception as e:  # noqa: BLE001
            log.error("hunt_request esuat: %s", e)
            m["api_errors"] += 1
            continue
        if rec.patch_available:
            try:
                request_patch(es_inc, rec, remediation="manual_required")
                m["patch_requests"] += 1
            except Exception as e:  # noqa: BLE001
                log.error("patch_request esuat: %s", e)
                m["api_errors"] += 1

    write_metrics(es_met, m)
    log.info("nday gata: %s (cap=%d, min_cvss=%.1f)",
             json.dumps(m), HUNT_MAX, HUNT_MIN_CVSS)
    return 0


def main() -> int:
    try:
        return run()
    except Exception as e:  # noqa: BLE001 — orice eroare neprinsa: log + exit 1 (R14)
        log.exception("nday_watch a esuat: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())

"""
EXPUNERE WORDPRESS — potriviri deterministe intre versiunile instalate si o lista
de versiuni vulnerabile cunoscute (kb/wp_vulns.yml). Fara model, fara retea.

Scopul: sa stim CE componente vulnerabile sunt instalate (nucleu + plugin-uri),
inainte ca cineva sa le exploateze. Combinat cu recon-ul (faza 16) si tentativa de
exploit (faza 17): daca stim ca pluginul X e vulnerabil SI cineva ii loveste
endpoint-ul, corelatia (cod determinist) devine o alerta de incredere mare, devreme.

Inventarul de versiuni vine din asta-inventory (scris de un colector pe web-prod,
controlat de om); modulul asta NU citeste de pe host si NU descarca feed-uri. Aici
e doar logica pura de potrivire, testabila fara Elasticsearch.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
LOCAL_FILE = ROOT / "kb" / "wp_vulns.yml"

SEVERITIES = ("low", "medium", "high", "critical")
# slug de plugin ca in `wp plugin list` (litere mici, cifre, cratima), sau "core".
COMPONENT_RE = re.compile(r"^(core|[a-z0-9][a-z0-9\-]{0,62})$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+)*([.\-][0-9A-Za-z]+)*$")
MAX_MATCHES = 50


def parse_version(v) -> tuple[int, ...] | None:
    """Versiune in tuplu de intregi pentru comparatie ('1.2.3' -> (1,2,3)). Partile
    nenumerice (pre-release) se ignora la comparatie; forma invalida -> None. Pur."""
    if not isinstance(v, str) or not VERSION_RE.match(v.strip()):
        return None
    parts = re.split(r"[.\-]", v.strip())
    nums = tuple(int(p) for p in parts if p.isdigit())
    return nums or (0,)


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Compara doua versiuni deja parsate, completand cu 0 partea mai scurta. Pur."""
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def in_range(version: str, introduced: str, fixed) -> bool:
    """introduced <= version < fixed. fixed gol/None = fara limita de sus. Pur.
    O versiune instalata neparsabila nu se declara vulnerabila (prudent)."""
    v = parse_version(version)
    lo = parse_version(introduced if introduced not in (None, "") else "0")
    if v is None or lo is None:
        return False
    if _cmp(v, lo) < 0:
        return False
    if fixed in (None, ""):
        return True
    hi = parse_version(fixed)
    return hi is not None and _cmp(v, hi) < 0


def parse_entries(raw: dict | None, origin: str) -> list[dict]:
    """Intrarile valide din fisier. Una invalida e sarita, nu strica toata lista."""
    out = []
    for e in (raw or {}).get("components") or []:
        if not isinstance(e, dict):
            continue
        comp = str(e.get("component") or "").strip().lower()
        if not COMPONENT_RE.match(comp):
            continue
        introduced = e.get("introduced")
        introduced = str(introduced).strip() if introduced not in (None, "") else "0"
        if parse_version(introduced) is None:
            continue
        fixed = e.get("fixed")
        fixed = str(fixed).strip() if fixed not in (None, "") else None
        if fixed is not None and parse_version(fixed) is None:
            continue
        sev = e.get("severity") if e.get("severity") in SEVERITIES else "medium"
        cve = str(e.get("cve") or "").strip().upper()
        cve = cve if CVE_RE.match(cve) else None
        out.append({"component": comp, "introduced": introduced, "fixed": fixed,
                    "severity": sev, "cve": cve, "source": str(e.get("source") or origin)[:40],
                    "note": str(e.get("note") or "")[:160]})
    return out


@lru_cache(maxsize=1)
def load() -> tuple[dict, ...]:
    entries = parse_entries(yaml.safe_load(LOCAL_FILE.read_text(encoding="utf-8")), "local")
    feed = os.environ.get("WP_VULNS_FEED")
    if feed and Path(feed).is_file():
        entries += parse_entries(yaml.safe_load(Path(feed).read_text(encoding="utf-8")), "feed")
    return tuple(entries)


def normalize_installed(raw) -> dict[str, str]:
    """{component: versiune} dintr-un inventar brut. Accepta forma `wp plugin list`
    (lista de {name, version}) si forma deja-dict. Nucleul e cheia 'core'. Valorile
    vin din telemetrie: validate (slug + versiune), restul sarit. Pur."""
    out: dict[str, str] = {}
    items = []
    if isinstance(raw, dict):
        items = [{"name": k, "version": v} for k, v in raw.items()]
    elif isinstance(raw, list):
        items = raw
    for it in items:
        if not isinstance(it, dict):
            continue
        name = str(it.get("name") or it.get("component") or "").strip().lower()
        ver = it.get("version")
        if COMPONENT_RE.match(name) and parse_version(str(ver) if ver is not None else "") is not None:
            out[name] = str(ver).strip()
    return out


def vulnerable_components(installed: dict[str, str], entries: tuple[dict, ...] | None = None) -> list[dict]:
    """Componentele instalate care cad intr-un interval vulnerabil. Pur.
    `installed` = {component: versiune} (vezi normalize_installed)."""
    entries = load() if entries is None else entries
    out = []
    for e in entries:
        ver = installed.get(e["component"])
        if ver is not None and in_range(ver, e["introduced"], e["fixed"]):
            out.append({"component": e["component"], "installed_version": ver,
                        "cve": e["cve"], "severity": e["severity"], "fixed": e["fixed"],
                        "source": e["source"], "note": e["note"]})
    # cele mai grave intai (critical > high > medium > low)
    out.sort(key=lambda m: SEVERITIES.index(m["severity"]), reverse=True)
    return out[:MAX_MATCHES]

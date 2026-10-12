"""
THREAT INTEL LOCAL — cautari exacte, deterministe, fara model si fara retea.

Sursa: kb/threat_intel.yml (in git, revizuita de om) plus, optional, un feed
real descarcat separat in acelasi format (THREAT_INTEL_FEED = calea fisierului).
Codul NU descarca nimic: feed-ul e adus de un pas separat, controlat de om.

Indicatorii se extrag din campurile alertei si, prin expresii regulate, din
command_line (adrese IP, gazde din URL-uri). Extragerea nu interpreteaza textul:
doar scoate candidati si ii VALIDEAZA (ipaddress, forma de domeniu, hex) inainte
de comparatie. Un candidat invalid e ignorat, nu ajunge nicaieri.
"""

from __future__ import annotations

import ipaddress
import os
import re
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
LOCAL_FILE = ROOT / "kb" / "threat_intel.yml"

TYPES = ("ip", "domain", "sha256")
CONFIDENCES = ("low", "medium", "high")
MAX_MATCHES = 10
MAX_CANDIDATES = 50

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9\-]{0,62}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_IPV4_IN_TEXT = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_URL_HOST_IN_TEXT = re.compile(r"(?i)\b(?:https?|ftp)://([a-z0-9.\-]{1,253})")

# campurile alertei din care se iau indicatori, pe tip
ALERT_FIELDS = {
    "ip": ("source.ip", "destination.ip"),
    "domain": ("url.domain", "destination.domain", "dns.question.name"),
    "sha256": ("process.hash.sha256", "file.hash.sha256"),
}


def _g(d: dict, path: str):
    if path in d:
        return d[path]
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def normalize(kind: str, value) -> str | None:
    """Forma canonica a unui indicator, sau None daca nu e valid."""
    if not isinstance(value, str):
        return None
    v = value.strip().lower().rstrip(".")
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return None
    if kind == "domain":
        return v if DOMAIN_RE.match(v) else None
    if kind == "sha256":
        return v if SHA256_RE.match(v) else None
    return None


def parse_entries(raw: dict | None, origin: str) -> list[dict]:
    """Intrarile valide din fisier. Una invalida e sarita (si numarata), nu
    strica toata lista."""
    out = []
    for e in (raw or {}).get("indicators") or []:
        if not isinstance(e, dict) or e.get("type") not in TYPES:
            continue
        kind, value = e["type"], e.get("value")
        if kind == "ip":
            try:
                net = ipaddress.ip_network(str(value).strip(), strict=False)
            except ValueError:
                continue
            key = str(net)
        else:
            key = normalize(kind, value)
            if key is None:
                continue
        conf = e.get("confidence") if e.get("confidence") in CONFIDENCES else "low"
        out.append({"type": kind, "value": key, "source": str(e.get("source") or origin)[:40],
                    "confidence": conf, "note": str(e.get("note") or "")[:160]})
    return out


@lru_cache(maxsize=1)
def load() -> tuple[dict, ...]:
    entries = parse_entries(yaml.safe_load(LOCAL_FILE.read_text(encoding="utf-8")), "local")
    feed = os.environ.get("THREAT_INTEL_FEED")
    if feed and Path(feed).is_file():
        entries += parse_entries(yaml.safe_load(Path(feed).read_text(encoding="utf-8")), "feed")
    return tuple(entries)


def extract_indicators(alert: dict) -> list[tuple[str, str]]:
    """(tip, valoare) unice, validate. Din campurile alertei si din command_line."""
    cands: list[tuple[str, str]] = []
    for kind, fields in ALERT_FIELDS.items():
        for f in fields:
            val = _g(alert, f)
            for x in (val if isinstance(val, list) else [val]):
                cands.append((kind, x))
    cmd = _g(alert, "process.command_line")
    if isinstance(cmd, str):
        cmd = cmd[:4000]
        cands += [("ip", m) for m in _IPV4_IN_TEXT.findall(cmd)]
        for host in _URL_HOST_IN_TEXT.findall(cmd):
            cands.append(("ip", host) if normalize("ip", host) else ("domain", host))
    seen, out = set(), []
    for kind, raw in cands:
        n = normalize(kind, raw)
        if n and (kind, n) not in seen:
            seen.add((kind, n))
            out.append((kind, n))
        if len(out) >= MAX_CANDIDATES:
            break
    return out


def _matches_entry(kind: str, value: str, e: dict) -> bool:
    if e["type"] != kind:
        return False
    if kind == "ip":
        return ipaddress.ip_address(value) in ipaddress.ip_network(e["value"])
    if kind == "domain":
        return value == e["value"] or value.endswith("." + e["value"])
    return value == e["value"]


def lookup(indicators: list[tuple[str, str]], entries: tuple[dict, ...] | None = None) -> list[dict]:
    entries = load() if entries is None else entries
    out = []
    for kind, value in indicators:
        for e in entries:
            if _matches_entry(kind, value, e):
                out.append({"indicator": value, "type": kind, "listed_as": e["value"],
                            "source": e["source"], "confidence": e["confidence"], "note": e["note"]})
                break
        if len(out) >= MAX_MATCHES:
            break
    return out


def lookup_one(indicator: str, entries: tuple[dict, ...] | None = None) -> dict:
    """Pentru unealta agentului L1: un singur indicator, tipul ghicit de cod."""
    for kind in ("ip", "sha256", "domain"):
        n = normalize(kind, indicator)
        if n:
            m = lookup([(kind, n)], entries)
            return {"indicator": n, "type": kind, "listed": bool(m), "match": m[0] if m else None}
    return {"error": "indicator invalid: se accepta adresa IP, domeniu sau sha256"}

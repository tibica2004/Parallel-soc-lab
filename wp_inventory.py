#!/usr/bin/env python3
"""
COLECTOR DE INVENTAR WORDPRESS (faza 18, bucata 2).

Aduna versiunile instalate pe web-prod (nucleu + plugin-uri) si le scrie intr-un
document curent in soc-wp-inventory. De acolo, vanatoarea Tier 3 (--expunere)
le potriveste cu lista de vulnerabilitati (exposure.py) si le coreleaza cu
recon-ul/exploitul (fazele 16-17).

Ruleaza pe elastic-lab, NU pe web-prod: cheia de writer ramane aici, nu se copiaza
pe hostul web (CLAUDE.md). web-prod e interogat prin ssh, cu WP-CLI, fara sudo:
    wp core version
    wp plugin list --fields=name,version,status --format=json
Comanda ssh foloseste doar argumente constante (cale din env, controlata de om);
nicio valoare din telemetrie nu intra in ea.

  python3 wp_inventory.py arata                 # colecteaza prin ssh + afiseaza (dry-run)
  python3 wp_inventory.py scrie                 # colecteaza + scrie in soc-wp-inventory
  python3 wp_inventory.py arata --fisier inv.json   # dintr-un JSON local, fara ssh (test)

Variabile (toate cu implicit): WP_HOST (numele host.name, implicit web-prod),
WP_SSH_TARGET (tinta ssh, implicit tiberiu@172.20.99.240), WP_PATH (radacina
WordPress pe host, implicit /var/www/html).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import exposure as E  # noqa: E402

INDEX = "soc-wp-inventory"
HOST = os.environ.get("WP_HOST", "web-prod")
SSH_TARGET = os.environ.get("WP_SSH_TARGET", "tiberiu@172.20.99.240")
WP_PATH = os.environ.get("WP_PATH", "/var/www/html")
SSH_TIMEOUT_S = 30


def parse_plugin_json(text: str) -> list[dict]:
    """Iesirea lui `wp plugin list --format=json` -> lista de {name, version, status}.
    Validarea slug/versiune o face normalize_installed; aici doar parsam JSON-ul. Pur."""
    try:
        data = json.loads(text or "")
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    out = []
    for p in data:
        if isinstance(p, dict) and p.get("name"):
            out.append({"name": str(p["name"]), "version": str(p.get("version") or ""),
                        "status": str(p.get("status") or "")[:20]})
    return out


def build_doc(host: str, core_version: str, plugins: list[dict], now_iso: str) -> dict:
    """Documentul curent de inventar pentru un host. Pur. Nucleul e componenta 'core';
    normalize_installed valideaza slug-urile si versiunile, restul e sarit."""
    installed = E.normalize_installed([{"name": "core", "version": core_version}] + list(plugins or []))
    status = {str(p.get("name") or "").strip().lower(): str(p.get("status") or "")[:20] for p in (plugins or [])}
    comps = [{"component": c, "version": v, "status": status.get(c, "active" if c == "core" else "")}
             for c, v in sorted(installed.items())]
    return {"@timestamp": now_iso, "host": host, "collected_by": "wp_inventory",
            "components": comps, "component_count": len(comps)}


# ------------------------------------------------------------------------------
# I/O: ssh catre web-prod (colectare) si scriere in ES (cu cheia writer)
# ------------------------------------------------------------------------------

def _ssh(args: list[str]) -> str:
    """Ruleaza WP-CLI pe web-prod prin ssh, fara shell, cu argumente constante."""
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={SSH_TIMEOUT_S}", SSH_TARGET] + args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=SSH_TIMEOUT_S + 10)
    if r.returncode != 0:
        raise RuntimeError(f"ssh/wp esuat ({r.returncode}): {r.stderr.strip()[:200]}")
    return r.stdout


def collect() -> dict:
    """Interogheaza web-prod si construieste documentul. Cale din env (constanta)."""
    core = _ssh(["wp", "core", "version", f"--path={WP_PATH}"]).strip()
    plugins = parse_plugin_json(_ssh(
        ["wp", "plugin", "list", "--fields=name,version,status", "--format=json", f"--path={WP_PATH}"]))
    return build_doc(HOST, core, plugins, datetime.now(timezone.utc).isoformat())


def _writer():
    from elasticsearch import Elasticsearch
    key = os.environ.get("ES_WRITER_API_KEY")
    if not key:
        raise RuntimeError("ES_WRITER_API_KEY lipseste")
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"), api_key=key, request_timeout=30)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("mod", choices=["arata", "scrie"], help="arata = dry-run; scrie = in soc-wp-inventory")
    ap.add_argument("--fisier", help="citeste documentul dintr-un JSON local in loc de ssh (test)")
    args = ap.parse_args()

    if args.fisier:
        doc = json.loads(Path(args.fisier).read_text(encoding="utf-8"))
    else:
        try:
            doc = collect()
        except Exception as e:
            print(f"Colectare esuata: {type(e).__name__}: {e}")
            return 1

    print(json.dumps(doc, ensure_ascii=False, indent=1))
    vuln = E.vulnerable_components(E.installed_from_doc(doc))
    if vuln:
        print(f"\nComponente vulnerabile cunoscute ({len(vuln)}):")
        for v in vuln:
            print(f"  - {v['component']} {v['installed_version']}  {v['severity']}  {v['cve'] or ''}")
    else:
        print("\nNicio componenta in lista de vulnerabilitati cunoscute.")

    if args.mod == "scrie":
        try:
            _writer().index(index=INDEX, id=doc["host"], document=doc, refresh=True)
            print(f"\nScris in {INDEX} (id={doc['host']}).")
        except Exception as e:
            print(f"\nScriere esuata: {type(e).__name__}: {str(e)[:200]}")
            return 1
    else:
        print(f"\n(dry-run: nimic scris. `scrie` scrie in {INDEX}.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

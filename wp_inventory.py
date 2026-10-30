#!/usr/bin/env python3
"""
COLECTOR DE INVENTAR WORDPRESS (faza 18, bucata 2).

Aduna versiunile instalate pe web-prod (nucleu + plugin-uri) si le scrie intr-un
document curent in soc-wp-inventory. De acolo, vanatoarea Tier 3 (--expunere)
le potriveste cu lista de vulnerabilitati (exposure.py) si le coreleaza cu
recon-ul/exploitul (fazele 16-17).

Ruleaza pe es-node-1, NU pe web-prod. Pasul 1b: sursa e SBOM-ul zilnic (logs-soc.sbom-*,
colectat pe web-prod de soc-sbom.sh, pasul 1.A), NU ssh + WP-CLI. WP-CLI porneste tot
WordPress-ul: citeste wp-config.php (parola reala a bazei) si se conecteaza la baza, deci ar
cere un cont cu acces la secretele aplicatiei. Codul SOC nu mai intra prin ssh ca tiberiu@ (D1).

  python3 wp_inventory.py arata                 # citeste ultimul SBOM + afiseaza (dry-run)
  python3 wp_inventory.py scrie                 # + scrie in soc-wp-inventory
  python3 wp_inventory.py arata --fisier inv.json   # dintr-un JSON local, fara ES (test)

Variabile: WP_HOST (host.name, implicit web-prod), ES_URL, ES_API_KEY (citire logs-*).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import exposure as E  # noqa: E402

INDEX = "soc-wp-inventory"
HOST = os.environ.get("WP_HOST", "web-prod")
SBOM_IDX = "logs-soc.sbom-*"


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
# I/O: ultimul SBOM din ES (colectare) si scriere in ES (cu cheia writer)
# ------------------------------------------------------------------------------

def from_sbom(components: list[dict]) -> tuple[str, list[dict]]:
    """(versiunea nucleului, plugin-urile) din componentele unui SBOM. Pur. SBOM-ul nu are
    starea activ/inactiv (expunerea nu o foloseste); status ramane gol."""
    comps = [c for c in components or [] if isinstance(c, dict)]
    core = next((str(c.get("version") or "") for c in comps if c.get("type") == "wp_core"), "")
    plugins = [{"name": str(c["name"]), "version": str(c.get("version") or ""), "status": ""}
               for c in comps if c.get("type") == "plugin" and c.get("name")]
    return core, plugins


def collect() -> dict:
    """Ultimul SBOM al hostului (term pe host.name, R7) -> documentul de inventar."""
    from elasticsearch import Elasticsearch
    es = Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                       api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"],
                       request_timeout=30)
    r = es.search(index=SBOM_IDX, size=1, sort=[{"@timestamp": "desc"}],
                  query={"term": {"host.name": HOST}}, source=["@timestamp", "components"])
    hits = r["hits"]["hits"]
    if not hits:
        raise RuntimeError(f"niciun SBOM pentru {HOST} in {SBOM_IDX}")
    core, plugins = from_sbom(hits[0]["_source"].get("components"))
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

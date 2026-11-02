#!/usr/bin/env python3
# DEPRECAT (plann.md, 2026-11-02): inventar Windows, nefolosit in laboratorul Linux. Pastrat ca istoric.
"""
FERESTRELE DE MENTENANTA din asset-inventory. Le gestioneaza OMUL: o fereastra
ridica podeaua "actiune sensibila" pentru adminii cunoscuti, deci e o decizie de
acelasi fel ca o exceptie. Formatul si validarea sunt in maintenance.py (sursa
unica, aceeasi folosita de Tier 1 si Tier 2).

  arata   — cu cheia read-only din env.sh: ferestrele fiecarui host, valide sau
            respinse, expirate, si daca acum e cineva in fereastra.
  adauga  — cu contul elastic (parola la tastatura, nesalvata): valideaza si,
            cu confirmare, adauga o fereastra.
  sterge  — cu contul elastic: sterge fereastra cu numarul dat (din `arata`).
  curata  — cu contul elastic: sterge ferestrele unice expirate si intrarile invalide.

Toate orele sunt UTC. Zilele: 0 = luni ... 6 = duminica.

    cd ~/lab && source env.sh
    python3 deploy/inventory_windows.py arata
    # recurenta: duminica 02:00-04:00 UTC
    python3 deploy/inventory_windows.py adauga web-prod --zile 6 --start 02:00 --sfarsit 04:00 \\
        --motiv "actualizari apt saptamanale"
    # unica: o interventie anuntata
    python3 deploy/inventory_windows.py adauga web-prod --de-la 2026-10-20T08:00Z \\
        --pana-la 2026-10-20T12:00Z --motiv "instalare senzori, tichet 42"
    python3 deploy/inventory_windows.py sterge web-prod 1
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

from elasticsearch import Elasticsearch
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import maintenance as M  # noqa: E402

warnings.filterwarnings("ignore")
INDEX = "asset-inventory"
ES_URL = os.environ.get("ES_URL", "http://localhost:9200")


def ask(msg: str) -> bool:
    return input(f"\n{msg} [y/N] ").strip().lower() == "y"


def reader() -> Elasticsearch:
    return Elasticsearch(ES_URL, api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"],
                         request_timeout=30)


def writer() -> Elasticsearch:
    return Elasticsearch(ES_URL, basic_auth=("elastic", getpass.getpass("Parola contului elastic: ")),
                         request_timeout=30)


def raw_windows(es: Elasticsearch, host: str) -> tuple[list, int]:
    """(lista bruta din inventar, versiunea documentului pentru scriere sigura)."""
    d = es.get(index=INDEX, id=host)
    return list(d["_source"].get("maintenance_windows") or []), (d["_seq_no"], d["_primary_term"])


def save(es: Elasticsearch, host: str, windows: list, version) -> None:
    # if_seq_no: daca altcineva a schimbat documentul intre timp, scrierea esueaza
    es.update(index=INDEX, id=host, doc={"maintenance_windows": windows},
              if_seq_no=version[0], if_primary_term=version[1], refresh=True)


def describe(raw: list, now: datetime) -> list[str]:
    out = []
    for i, w in enumerate(raw, 1):
        try:
            v = M.Window.model_validate(w)
        except (ValidationError, TypeError, ValueError):
            out.append(f"  {i}. RESPINSA (ignorata de SOC): {json.dumps(w, ensure_ascii=False)[:160]}")
            continue
        state = "EXPIRATA" if v.expired(now) else ("DESCHISA ACUM" if v.contains(now) else "")
        out.append(f"  {i}. {v.describe()}  {state}".rstrip())
    return out


def arata(_a) -> None:
    es = reader()
    now = datetime.now(timezone.utc)
    print(f"Acum: {now:%Y-%m-%d %H:%M} UTC ({M.ZILE[now.weekday()]})")
    for h in es.search(index=INDEX, size=100)["hits"]["hits"]:
        raw = h["_source"].get("maintenance_windows") or []
        admins = ", ".join(h["_source"].get("normal_admins") or []) or "-"
        print(f"\n{h['_id']}  (admini: {admins})")
        print("\n".join(describe(raw, now)) if raw else "  fara ferestre")


def build(a) -> M.Window:
    if a.zile is not None:
        return M.Window(days=a.zile, start=a.start, end=a.sfarsit, reason=a.motiv)
    return M.Window(start_at=a.de_la, end_at=a.pana_la, reason=a.motiv)


def adauga(a) -> None:
    try:
        w = build(a)
    except ValidationError as e:
        sys.exit(f"Fereastra respinsa:\n{e}")
    print(f"{a.host}: + {w.describe()}")
    es = writer()
    raw, ver = raw_windows(es, a.host)
    if ask(f"Adaug fereastra pe {a.host}?"):
        save(es, a.host, raw + [w.model_dump(mode="json", exclude_none=True)], ver)
        print("  adaugata")


def sterge(a) -> None:
    es = writer()
    raw, ver = raw_windows(es, a.host)
    if not 1 <= a.nr <= len(raw):
        sys.exit(f"{a.host} are {len(raw)} ferestre; numarul {a.nr} nu exista")
    print("\n".join(describe([raw[a.nr - 1]], datetime.now(timezone.utc))))
    if ask(f"Sterg fereastra {a.nr} de pe {a.host}?"):
        save(es, a.host, raw[:a.nr - 1] + raw[a.nr:], ver)
        print("  stearsa")


def curata(a) -> None:
    es = writer()
    now = datetime.now(timezone.utc)
    raw, ver = raw_windows(es, a.host)
    keep = []
    for w in raw:
        try:
            if not M.Window.model_validate(w).expired(now):
                keep.append(w)
        except (ValidationError, TypeError, ValueError):
            pass
    if len(keep) == len(raw):
        print(f"{a.host}: nimic de curatat")
        return
    if ask(f"Sterg {len(raw) - len(keep)} ferestre expirate/invalide de pe {a.host}?"):
        save(es, a.host, keep, ver)
        print("  curatat")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("arata")
    p = sub.add_parser("adauga")
    p.add_argument("host")
    p.add_argument("--motiv", required=True)
    p.add_argument("--zile", type=int, nargs="+", help="0=luni ... 6=duminica")
    p.add_argument("--start", help="HH:MM UTC")
    p.add_argument("--sfarsit", help="HH:MM UTC")
    p.add_argument("--de-la", dest="de_la", help="ISO cu fus orar, ex. 2026-10-20T08:00Z")
    p.add_argument("--pana-la", dest="pana_la")
    p = sub.add_parser("sterge")
    p.add_argument("host")
    p.add_argument("nr", type=int)
    p = sub.add_parser("curata")
    p.add_argument("host")
    a = ap.parse_args()
    {"arata": arata, "adauga": adauga, "sterge": sterge, "curata": curata}[a.cmd](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())

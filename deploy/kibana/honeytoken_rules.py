#!/usr/bin/env python3
"""
REGULILE DE HONEYTOKEN SI DE SENZOR IN KIBANA. Le ruleaza OMUL: sunt reguli ale
omului, in spatiul default, nu reguli Tier 3. Definitiile vin din honeytokens.py si
sensor_rules.py (sursa unica, aceeasi pe care o folosesc orchestratorul si testele).

  arata    — fara retea: afiseaza corpurile regulilor.
  verifica — cu contul elastic, doar citire: exista regulile? sunt pornite?
  aplica   — cu contul elastic (parola la tastatura, nesalvata): creeaza
             regulile care lipsesc, cu confirmare pentru fiecare. Nu modifica
             si nu sterge reguli existente.

    cd ~/lab && source env.sh
    python3 deploy/kibana/honeytoken_rules.py arata
    python3 deploy/kibana/honeytoken_rules.py verifica
    python3 deploy/kibana/honeytoken_rules.py aplica
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import honeytokens as H  # noqa: E402
import sensor_rules as S  # noqa: E402

# rule_id -> functia care ii construieste corpul
ALL = {**{rid: H.kibana_payload for rid in H.RULES}, **{rid: S.kibana_payload for rid in S.RULES}}

KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601")
RULES_API = "/api/detection_engine/rules"


def ask(msg: str) -> bool:
    return input(f"\n{msg} [y/N] ").strip().lower() == "y"


class Kibana:
    def __init__(self):
        self.auth = ("elastic", getpass.getpass("Parola contului elastic: "))
        self.h = {"kbn-xsrf": "soc-honeytokens", "elastic-api-version": "2023-10-31"}

    def get(self, rule_id: str):
        r = requests.get(KIBANA_URL + RULES_API, params={"rule_id": rule_id},
                         auth=self.auth, headers=self.h, timeout=30)
        if r.status_code == 404:
            return None
        if r.status_code >= 400:
            sys.exit(f"Kibana GET {rule_id}: {r.status_code} {r.text[:300]}")
        return r.json()

    def create(self, payload: dict) -> dict:
        r = requests.post(KIBANA_URL + RULES_API, json=payload, auth=self.auth, headers=self.h, timeout=30)
        if r.status_code >= 400:
            sys.exit(f"Kibana POST {payload['rule_id']}: {r.status_code} {r.text[:300]}")
        return r.json()


def arata() -> None:
    for rid, build in ALL.items():
        print(json.dumps(build(rid), indent=1, ensure_ascii=False))
        print()


def verifica(k: Kibana) -> None:
    for rid in ALL:
        r = k.get(rid)
        if r is None:
            print(f"  {rid:22s} LIPSESTE")
        else:
            print(f"  {rid:22s} {'pornita' if r.get('enabled') else 'OPRITA'}  {r.get('name')}")
    print("\nNimic nu a fost modificat.")


def aplica(k: Kibana) -> None:
    for rid, build in ALL.items():
        if k.get(rid) is not None:
            print(f"  {rid}: exista deja, neatinsa")
            continue
        p = build(rid)
        print(f"\n{rid}: {p['name']}\n  index: {p['index']}\n  query: {p['query']}")
        if ask(f"Creez regula {rid} (spatiul default, severitate {p['severity']})?"):
            r = k.create(p)
            print(f"  creata: id={r.get('id')} pornita={r.get('enabled')}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["arata", "verifica", "aplica"])
    a = ap.parse_args()
    if a.cmd == "arata":
        arata()
        return 0
    k = Kibana()
    verifica(k) if a.cmd == "verifica" else aplica(k)
    return 0


if __name__ == "__main__":
    sys.exit(main())

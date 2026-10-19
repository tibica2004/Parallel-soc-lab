#!/usr/bin/env python3
"""
ACCESUL TIER 3 LA KIBANA. Il ruleaza OMUL, cu contul elastic (parola ceruta la
tastatura, nesalvata). Fiecare schimbare cere confirmare. Nu afiseaza secrete.

  verifica  — doar citire: ce drepturi are acum cheia de writer, ce feature-uri
              de securitate exista in Kibana, daca spatiul tier3 exista.
  writer    — doar pasul 4 de mai jos (indici noi pentru cheia de writer).
  aplica    — dupa verifica:
     1. spatiul Kibana `tier3` (regulile Tier 3 stau separat de ale omului);
     2. rolul soc_tier3_rules: feature-urile date cu --feature, DOAR in spatiul
        tier3, plus read pe evenimentele de proces (regulile ruleaza cu
        drepturile cheii care le-a creat);
     3. utilizatorul soc_tier3 (parola aleatoare, nefolosita de om) si o cheie
        API acordata lui -> KIBANA_TIER3_API_KEY adaugata in env.sh, neafisata;
     4. cheia de writer primeste si soc-traces, soc-incidents, soc-hunts (restul
        drepturilor ei raman exact cum sunt).

    cd ~/lab && source env.sh
    python3 deploy/kibana/tier3_access.py verifica
    python3 deploy/kibana/tier3_access.py aplica --feature <id> [--feature <id>]
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import secrets
import sys
from pathlib import Path

import requests

ES_URL = os.environ.get("ES_URL", "http://localhost:9200")
KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601")
SPACE = "tier3"
ROLE = "soc_tier3_rules"
USER = "soc_tier3"
SOURCE_IDX = ["logs-endpoint.events.process-*"]
WRITER_ADD = ["soc-traces", "soc-incidents", "soc-hunts"]
ENV_SH = Path(__file__).resolve().parents[2] / "env.sh"


def ask(msg: str) -> bool:
    return input(f"\n{msg} [y/N] ").strip().lower() == "y"


def writer_key_id() -> str:
    k = os.environ.get("ES_WRITER_API_KEY", "")
    try:
        return base64.b64decode(k).decode().split(":")[0]
    except Exception:
        sys.exit("ES_WRITER_API_KEY lipseste sau nu e in formatul obisnuit (source env.sh)")


class Client:
    def __init__(self):
        self.auth = ("elastic", getpass.getpass("Parola contului elastic: "))
        self.kh = {"kbn-xsrf": "tier3-access", "elastic-api-version": "2023-10-31"}

    def es(self, method, path, **kw):
        r = requests.request(method, ES_URL + path, auth=self.auth, timeout=30, **kw)
        if r.status_code >= 400:
            sys.exit(f"ES {method} {path}: {r.status_code} {r.text[:300]}")
        return r.json()

    def kb(self, method, path, ok=(200,), **kw):
        r = requests.request(method, KIBANA_URL + path, auth=self.auth, headers=self.kh, timeout=30, **kw)
        if r.status_code not in ok and r.status_code >= 400:
            sys.exit(f"Kibana {method} {path}: {r.status_code} {r.text[:300]}")
        return r


def show_writer(c: Client) -> dict:
    kid = writer_key_id()
    key = c.es("GET", f"/_security/api_key?id={kid}")["api_keys"][0]
    print(f"\nCheia de writer: id={kid} nume={key.get('name')!r} proprietar={key.get('username')}")
    for name, d in (key.get("role_descriptors") or {}).items():
        for i in d.get("indices", []):
            print(f"  [{name}] {i['names']} -> {i['privileges']}")
    return key


def verifica(c: Client) -> None:
    show_writer(c)
    feats = c.kb("GET", "/api/features").json()
    print("\nFeature-uri Kibana de securitate (alege-le pe cele pentru reguli de detectie):")
    for f in feats:
        fid = f.get("id", "")
        if any(s in fid.lower() for s in ("siem", "securitysolution", "rules")):
            print(f"  {fid:40s} {f.get('name')}")
    r = c.kb("GET", f"/api/spaces/space/{SPACE}", ok=(200, 404))
    print(f"\nSpatiul {SPACE}: {'exista' if r.status_code == 200 else 'nu exista'}")
    print("\nNimic nu a fost modificat.")


def aplica(c: Client, features: list[str]) -> None:
    if not features:
        sys.exit("da cel putin un --feature (vezi `verifica`)")

    # 1. spatiul
    if c.kb("GET", f"/api/spaces/space/{SPACE}", ok=(200, 404)).status_code == 404:
        if ask(f"Creez spatiul Kibana `{SPACE}`?"):
            c.kb("POST", "/api/spaces/space", json={"id": SPACE, "name": "Tier 3 (reguli generate)",
                 "description": "Reguli EQL generate de Tier 3; separate de regulile omului."})
            print("  creat")
    else:
        print(f"Spatiul {SPACE} exista deja.")

    # 2. rolul: feature-urile doar in spatiul tier3
    role = {"elasticsearch": {"cluster": [], "indices": [
                {"names": SOURCE_IDX, "privileges": ["read", "view_index_metadata"]}]},
            "kibana": [{"base": [], "spaces": [SPACE], "feature": {f: ["all"] for f in features}}]}
    print(f"\nRolul {ROLE}:\n" + json.dumps(role, indent=1))
    if ask(f"Creez/actualizez rolul {ROLE}?"):
        c.kb("PUT", f"/api/security/role/{ROLE}", ok=(200, 204), json=role)
        print("  aplicat")

    # 3. utilizatorul si cheia
    if ask(f"Creez utilizatorul {USER} (parola aleatoare) si cheia API pentru Tier 3, salvata in env.sh?"):
        pw = secrets.token_urlsafe(24)
        c.es("PUT", f"/_security/user/{USER}", json={"password": pw, "roles": [ROLE],
             "full_name": "SOC Tier 3 (reguli generate)"})
        k = c.es("POST", "/_security/api_key/grant", json={
            "grant_type": "password", "username": USER, "password": pw,
            "api_key": {"name": "soc-tier3-rules", "metadata": {"purpose": "tier3-generated rules"}}})
        with ENV_SH.open("a") as f:
            f.write(f"\nexport KIBANA_TIER3_API_KEY='{k['encoded']}'\n")
        print(f"  cheia {k['id']} adaugata in {ENV_SH.name} (neafisata)")

    # 4. writer: + indicii Tier 3, restul neschimbat
    writer_add(c)


def writer_add(c: Client) -> None:
    """Doar pasul 4: adauga indicii din WRITER_ADD care lipsesc la blocul cheii de
    writer care contine verdicts-history. Restul drepturilor raman exact cum sunt."""
    key = show_writer(c)
    rd = json.loads(json.dumps(key.get("role_descriptors") or {}))
    target = None
    for d in rd.values():
        for i in d.get("indices", []):
            if "verdicts-history" in i["names"]:
                target = i
    if target is None:
        print("\nNu gasesc blocul cu verdicts-history in cheia de writer; nu modific nimic.")
        return
    missing = [n for n in WRITER_ADD if n not in target["names"]]
    if not missing:
        print(f"\nCheia de writer are deja {WRITER_ADD}.")
        return
    target["names"] = target["names"] + missing
    print(f"\nAdaug {missing} la blocul {target['names']} -> {target['privileges']}")
    if ask("Actualizez cheia de writer?"):
        c.es("PUT", f"/_security/api_key/{writer_key_id()}", json={"role_descriptors": rd})
        show_writer(c)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["verifica", "aplica", "writer"])
    ap.add_argument("--feature", action="append", default=[])
    a = ap.parse_args()
    c = Client()
    {"verifica": lambda: verifica(c), "aplica": lambda: aplica(c, a.feature),
     "writer": lambda: writer_add(c)}[a.cmd]()
    return 0


if __name__ == "__main__":
    sys.exit(main())

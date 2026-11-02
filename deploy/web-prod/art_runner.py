#!/usr/bin/env python3
"""
RUNNER ATOMIC RED TEAM (pasul 5) — ruleaza UN test din depozitul OFICIAL (redcanaryco/atomic-red-team,
commit fixat, clonat de om in /opt/atomic-red-team), pe web-prod, CU OMUL LA TASTATURA.

Nu scriem teste si nu modificam teste (R1). Runner-ul doar:
  1. citeste testul <tehnica>#<numar> din atomics/<T>/<T>.yaml;
  2. refuza, decis de cod, testele care nu sunt pentru laborator: alta platforma decat linux,
     executor manual, dependinte (get_prereq_command descarca de obicei), URL-uri http(s), IP-uri
     in afara listei permise (127.0.0.1 si lab-sink 192.168.10.160);
  3. AFISEAZA comanda exacta (cu argumentele implicite sau date cu --arg nume=valoare) si
     asteapta "OK" tastat de om; altfel nu ruleaza nimic;
  4. scrie inceputul in /var/log/soc/emulation.ndjson, ruleaza, apoi AFISEAZA cleanup-ul si
     asteapta din nou "OK", ruleaza cleanup-ul, scrie sfarsitul (cleanup_ok).
Fara chei pe web-prod (R16): fisierul NDJSON ajunge prin Fleet (Custom Logs, dataset
soc.emulation) in logs-soc.emulation-*, de unde il citeste coverage.py pe es-node-1.

  sudo /opt/soc/art_runner.py T1082 1 --show     # doar arata, nu ruleaza
  sudo /opt/soc/art_runner.py T1082 1
  sudo /opt/soc/art_runner.py T1105 3 --arg remote_host=192.168.10.160
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ART_ROOT = Path(os.environ.get("ART_ROOT", "/opt/atomic-red-team"))
LOG = Path(os.environ.get("ART_LOG", "/var/log/soc/emulation.ndjson"))
ALLOWED_IPS = frozenset({"127.0.0.1", "192.168.10.160"})      # localhost + lab-sink (A11)
EXECUTORS = {"sh": ["sh", "-c"], "bash": ["bash", "-c"]}
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_ARG_RE = re.compile(r"#\{(\w+)\}")
TIMEOUT_S = 300


# ---------------- functii pure (testate pe es-node-1/local, fara sa ruleze nimic) ----------------

def load_test(doc: dict, number: int) -> dict:
    tests = doc.get("atomic_tests") or []
    if not 1 <= number <= len(tests):
        raise ValueError(f"testul {number} nu exista ({len(tests)} teste)")
    return tests[number - 1]


def render(text: str, test: dict, overrides: dict[str, str]) -> str:
    args = {k: str(v.get("default", "")) for k, v in (test.get("input_arguments") or {}).items()}
    unknown = set(overrides) - set(args)
    if unknown:
        raise ValueError(f"argumente necunoscute: {sorted(unknown)}")
    args.update(overrides)
    return _ARG_RE.sub(lambda m: args.get(m.group(1), m.group(0)), text or "")


def refusal(test: dict, command: str, cleanup: str) -> str | None:
    """Motivul pentru care testul NU e pentru laborator, sau None. Decis de cod."""
    if "linux" not in (test.get("supported_platforms") or []):
        return "nu e pentru linux"
    ex = (test.get("executor") or {}).get("name")
    if ex not in EXECUTORS:
        return f"executor nepermis: {ex}"
    if test.get("dependencies"):
        return "are dependinte (prerechizitele descarca/instaleaza de obicei ceva)"
    for part in (command, cleanup):
        if _URL_RE.search(part):
            return "contine un URL (fara internet si fara descarcari)"
        for ip in _IP_RE.findall(part):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip not in ALLOWED_IPS:
                return f"IP in afara laboratorului permis: {ip} (permise: {sorted(ALLOWED_IPS)})"
    return None


def record(phase: str, run_id: str, technique: str, number: int, name: str, user: str, **kw) -> dict:
    return {"@timestamp": datetime.now(timezone.utc).isoformat(), "event": f"art_{phase}",
            "run_id": run_id, "technique_id": technique, "test_number": number,
            "test_name": name[:200], "host": socket.gethostname(), "executor_user": user, **kw}


# ---------------- efecte ----------------

def _confirm(what: str, text: str) -> bool:
    print(f"\n===== {what} =====\n{text}\n=====")
    try:
        return input('Tasteaza OK ca sa rulezi (orice altceva = nu): ').strip() == "OK"
    except EOFError:
        return False


def _log(doc: dict) -> None:
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(doc, ensure_ascii=False) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("technique")
    ap.add_argument("number", type=int)
    ap.add_argument("--arg", action="append", default=[], help="nume=valoare (suprascrie implicitul)")
    ap.add_argument("--show", action="store_true", help="doar afiseaza comanda, cleanup-ul si refuzul; nu ruleaza")
    a = ap.parse_args(argv)
    if not TECH_RE.match(a.technique):
        print("tehnica invalida", file=sys.stderr)
        return 2
    import yaml
    path = ART_ROOT / "atomics" / a.technique / f"{a.technique}.yaml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    test = load_test(doc, a.number)
    overrides = dict(x.split("=", 1) for x in a.arg)
    ex = test["executor"]
    cmd = render(ex.get("command", ""), test, overrides)
    cleanup = render(ex.get("cleanup_command", ""), test, overrides)
    why = refusal(test, cmd, cleanup)
    print(f"{a.technique} #{a.number}: {test.get('name')}  (executor {ex.get('name')}, "
          f"elevation_required={ex.get('elevation_required', False)})")
    if a.show:
        print(f"--- COMANDA ---\n{cmd}\n--- CLEANUP ---\n{cleanup or '(fara cleanup)'}")
        print(f"--- VERDICTUL CODULUI: {'REFUZAT: ' + why if why else 'permis'}")
        return 3 if why else 0
    if why:
        print(f"REFUZAT: {why}")
        return 3
    if not cleanup.strip():
        print("ATENTIE: testul nu are cleanup; urmele raman pe host (verifica tu dupa).")
    if not _confirm("COMANDA", cmd):
        print("nimic rulat")
        return 0
    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
    run_id = str(uuid.uuid4())
    _log(record("start", run_id, a.technique, a.number, test.get("name", ""), user))
    r = subprocess.run(EXECUTORS[ex["name"]] + [cmd], timeout=TIMEOUT_S)
    print(f"cod de iesire: {r.returncode}")
    cleanup_ok = None
    if cleanup.strip():
        if _confirm("CLEANUP", cleanup):
            c = subprocess.run(EXECUTORS[ex["name"]] + [cleanup], timeout=TIMEOUT_S)
            cleanup_ok = c.returncode == 0
        else:
            cleanup_ok = False
            print("CLEANUP NERULAT: conditie de oprire (5.7) — curata manual si noteaza.")
    _log(record("end", run_id, a.technique, a.number, test.get("name", ""), user,
                exit_code=r.returncode, cleanup_ok=cleanup_ok))
    print(f"inregistrat: {run_id} (cleanup_ok={cleanup_ok})")
    return 0 if cleanup_ok in (True, None) else 4


if __name__ == "__main__":
    sys.exit(main())

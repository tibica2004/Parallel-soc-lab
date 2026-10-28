#!/usr/bin/env python3
"""
Update-uri WordPress controlate (pasul 0.2), rulate de timer ca www-data (proprietarul
webroot-ului). Auto-update-ul intern al WordPress e oprit din wp-config.php
(AUTOMATIC_UPDATER_DISABLED), deci update-urile trec doar pe aici.

- APPLY=0 (implicit): doar raporteaza ce update-uri exista (action=wp_update_available).
- APPLY=1: aplica update-ul minor de core si update-urile pentru PLUGINS / THEMES din
  lista aprobata de om (action=wp_update), apoi raporteaza versiunile noi.

Fiecare schimbare (sau update disponibil) e o linie NDJSON in
/var/log/soc/benign-actions.ndjson: ajunge prin Custom Logs in benign-ground-truth, ca
scrierile in webroot din fereastra de update sa poata fi explicate, nu ignorate.
Config: /usr/local/etc/soc-wp-update.conf (KEY=VALUE). wp-cli se apeleaza cu argv, fara shell.
"""
from __future__ import annotations

import json
import logging
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

CONF = Path("/usr/local/etc/soc-wp-update.conf")
WP = "/usr/local/bin/wp"
WP_PATH = "/var/www/html"
ACTIONS = Path("/var/log/soc/benign-actions.ndjson")
LOG = Path("/var/log/soc/soc-wp-update.log")
TIMEOUT_S = 600

log = logging.getLogger("soc-wp-update")


def parse_conf(text: str) -> dict[str, str]:
    """KEY=VALUE, comentarii cu #. Fara evaluare de shell."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def approved(value: str) -> list[str]:
    """Lista aprobata de slug-uri (separate prin spatiu sau virgula); doar [a-z0-9-_],
    prima litera alfanumerica (altfel `--all` ar ajunge flag la wp-cli)."""
    items = [x for x in value.replace(",", " ").split() if x]
    bad = [x for x in items
           if not x[0].isalnum() or not all(c.isalnum() or c in "-_" for c in x)]
    if bad:
        raise ValueError(f"slug invalid in lista aprobata: {bad}")
    return items


def records(kind: str, rows: list[dict], applied: bool, host: str, ts: str) -> list[dict]:
    """Randurile wp-cli (`plugin|theme list --update=available` sau `core check-update`)
    -> inregistrari benign-actions. Pentru core, `name` lipseste si devine 'core'."""
    action = "wp_update" if applied else "wp_update_available"
    out = []
    for r in rows:
        out.append({
            "ts": ts, "host": host, "action": action, "component_type": kind,
            "target": r.get("name") or "core",
            "old": r.get("version_before") or r.get("version_installed") or r.get("version"),
            "new": r.get("update_version") or r.get("version"),
            "applied": applied,
        })
    return out


def wp(*args: str) -> str:
    res = subprocess.run([WP, f"--path={WP_PATH}", *args], capture_output=True, text=True,
                         timeout=TIMEOUT_S, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"wp {' '.join(args)} -> {res.returncode}: {res.stderr.strip()[:500]}")
    return res.stdout


def wp_json(*args: str) -> list[dict]:
    """`core check-update` fara update-uri scrie un mesaj de succes, nu JSON: -> []."""
    out = wp(*args, "--format=json").strip()
    return json.loads(out) if out.startswith("[") else []


def installed_core() -> str:
    return wp("core", "version").strip()


def main() -> int:
    logging.basicConfig(filename=LOG, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        conf = parse_conf(CONF.read_text()) if CONF.exists() else {}
        apply = conf.get("APPLY", "0") == "1"
        plugins = approved(conf.get("PLUGINS", ""))
        themes = approved(conf.get("THEMES", ""))
        host = socket.gethostname()
        ts = datetime.now(timezone.utc).isoformat()

        core_before = installed_core()
        core_av = wp_json("core", "check-update", "--minor")
        plug_av = wp_json("plugin", "list", "--update=available",
                          "--fields=name,version,update_version")
        theme_av = wp_json("theme", "list", "--update=available",
                           "--fields=name,version,update_version")

        recs: list[dict] = []
        if apply:
            if core_av:
                wp("core", "update", "--minor")
                recs += records("core", [{"version_before": core_before,
                                          "version": installed_core()}], True, host, ts)
            todo_p = [p for p in plug_av if p["name"] in plugins]
            if todo_p:
                wp("plugin", "update", *[p["name"] for p in todo_p])
                recs += records("plugin", todo_p, True, host, ts)
            todo_t = [t for t in theme_av if t["name"] in themes]
            if todo_t:
                wp("theme", "update", *[t["name"] for t in todo_t])
                recs += records("theme", todo_t, True, host, ts)
            # Ce a ramas neaplicat (in afara listei aprobate) se raporteaza ca disponibil.
            plug_av = [p for p in plug_av if p["name"] not in plugins]
            theme_av = [t for t in theme_av if t["name"] not in themes]
            core_av = []
        recs += records("core", [{"version_installed": core_before, **c} for c in core_av],
                        False, host, ts)
        recs += records("plugin", plug_av, False, host, ts)
        recs += records("theme", theme_av, False, host, ts)

        with ACTIONS.open("a") as f:
            for r in recs:
                f.write(json.dumps(r, separators=(",", ":")) + "\n")
        log.info("apply=%s core=%s inregistrari=%d", apply, core_before, len(recs))
        return 0
    except Exception:
        log.exception("esec")
        return 1


if __name__ == "__main__":
    sys.exit(main())

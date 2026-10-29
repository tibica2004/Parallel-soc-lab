#!/usr/bin/env python3
"""
ALERTE DE ABSENTA (0.4) — ce NU se mai intampla.

Ruleaza pe es-node-1 dintr-un timer (soc-absence.timer, la 10 min) si pagineaza
omul pe Discord cand un semn de viata dispare. Trei lucruri, independente (esecul
unuia nu-i opreste pe ceilalti):

  1. BACKUP vechi: ultimul `soc-backup OK` (logs-system.syslog-*, de pe web-prod)
     mai vechi de 26 h -> copia de siguranta nu mai ruleaza.
  2. ORCHESTRATOR / TUNEL cazut: `systemctl is-active` local != active -> creierul
     SOC nu mai judeca sau nu mai ajunge la model. (Verificare locala, directa; nu
     depinde de tiparul de scriere in ES. Varianta Kibana de rezerva vine la pasul 7.5.)
  3. CANAR lipsa: ultimul eveniment soc-canary (logs-endpoint.events.process-*) mai
     vechi de 12 min -> telemetria de proces de pe web-prod s-a oprit, desi agentul
     poate raporta HEALTHY.

Limita cunoscuta: scriptul ruleaza PE es-node-1; daca es-node-1 insusi pica, nu mai
poate pagina. De asta exista si verificari pe partea Kibana (pasul 7.5) ca rezerva.

Dedup-ul e in notify.py (per kind). Iesire: 0 daca verificarile au rulat (chiar daca
s-au trimis alerte), 1 doar daca Elasticsearch e de neatins (ca journalul sa arate rosu).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from datetime import datetime, timezone

from elasticsearch import Elasticsearch

import notify

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s",
                    stream=sys.stderr)
log = logging.getLogger("soc.absence")

BACKUP_MAX_AGE_H = float(os.environ.get("ABSENCE_BACKUP_MAX_AGE_H", "26"))
CANARY_MAX_AGE_MIN = float(os.environ.get("ABSENCE_CANARY_MAX_AGE_MIN", "12"))
CANARY_HOST = os.environ.get("CANARY_HOST", "web-prod")
SERVICES = os.environ.get("ABSENCE_SERVICES", "soc-orchestrator,soc-llm-tunnel").split(",")


def _es() -> Elasticsearch:
    return Elasticsearch(
        os.environ.get("ES_URL", "http://localhost:9200"),
        api_key=os.environ.get("ES_READONLY_API_KEY") or os.environ["ES_API_KEY"],
        request_timeout=20,
    )


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def check_backup(es: Elasticsearch, now: datetime) -> None:
    r = es.esql.query(query="""
        FROM logs-system.syslog-*
        | WHERE process.name == "soc-backup" AND STARTS_WITH(message, "OK")
        | SORT @timestamp DESC
        | KEEP @timestamp
        | LIMIT 1
    """, format="json")
    if not r["values"]:
        notify.notify_human(
            "Backup: niciun `soc-backup OK` gasit",
            "Nu exista niciun log de backup reusit in logs-system.syslog-*. "
            "Verifica soc-backup.timer pe web-prod si maparea campului (tag=soc-backup).",
            severity="high", dedup_key="absence:backup_none", dedup_minutes=720, host="web-prod")
        log.warning("backup: niciun log soc-backup OK")
        return
    age_h = (now - _parse(r["values"][0][0])).total_seconds() / 3600
    if age_h > BACKUP_MAX_AGE_H:
        notify.notify_human(
            "Backup vechi: nu mai ruleaza",
            f"Ultimul `soc-backup OK` acum {age_h:.1f} h (prag {BACKUP_MAX_AGE_H:.0f} h). "
            "Verifica soc-backup.timer pe web-prod si soc-backup-pull.timer pe es-node-1.",
            severity="high", dedup_key="absence:backup_stale", dedup_minutes=360, host="web-prod")
        log.warning("backup vechi: %.1f h", age_h)
    else:
        log.info("backup OK: acum %.1f h", age_h)


def check_canary(es: Elasticsearch, now: datetime) -> None:
    r = es.esql.query(query=f"""
        FROM logs-endpoint.events.process-*
        | WHERE host.name == "{CANARY_HOST}" AND process.name == "soc-canary"
        | SORT event.ingested DESC
        | KEEP event.ingested
        | LIMIT 1
    """, format="json")
    if not r["values"]:
        notify.notify_human(
            "Canar lipsa: telemetrie oprita?",
            f"Niciun eveniment soc-canary pentru {CANARY_HOST}. Cron-ul ruleaza? Agentul trimite?",
            severity="critical", dedup_key="absence:canary_none", dedup_minutes=30, host=CANARY_HOST)
        log.warning("canar: niciun eveniment")
        return
    age_min = (now - _parse(r["values"][0][0])).total_seconds() / 60
    if age_min > CANARY_MAX_AGE_MIN:
        notify.notify_human(
            "Telemetrie oprita (canar vechi)",
            f"Ultimul soc-canary acum {age_min:.0f} min (prag {CANARY_MAX_AGE_MIN:.0f} min). "
            f"Elastic Agent de pe {CANARY_HOST} raporteaza HEALTHY dar nu trimite evenimente?",
            severity="critical", dedup_key="absence:canary_stale", dedup_minutes=30, host=CANARY_HOST)
        log.warning("canar vechi: %.0f min", age_min)
    else:
        log.info("canar OK: acum %.1f min", age_min)


def check_services() -> None:
    for svc in (s.strip() for s in SERVICES if s.strip()):
        try:
            out = subprocess.run(["systemctl", "is-active", svc],
                                 capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception as e:
            out = f"eroare: {e}"
        if out != "active":
            notify.notify_human(
                f"Serviciu cazut: {svc}",
                f"`systemctl is-active {svc}` = {out}. Creierul SOC sau tunelul LLM nu mai ruleaza.",
                severity="critical", dedup_key=f"absence:svc:{svc}", dedup_minutes=30, host="es-node-1")
            log.warning("serviciu %s: %s", svc, out)
        else:
            log.info("serviciu %s: active", svc)


def main() -> int:
    now = datetime.now(timezone.utc)
    # Serviciile locale se verifica mereu, chiar daca ES e cazut.
    check_services()
    try:
        es = _es()
    except Exception as e:
        notify.notify_human("Absence-check: Elasticsearch de neatins",
                            f"Nu pot initializa clientul ES: {e}",
                            severity="high", dedup_key="absence:es_init", dedup_minutes=30,
                            host="es-node-1")
        log.error("ES init esuat: %s", e)
        return 1
    rc = 0
    for name, fn in (("backup", check_backup), ("canar", check_canary)):
        try:
            fn(es, now)
        except Exception as e:
            notify.notify_human(f"Absence-check: verificarea `{name}` a esuat",
                                f"Interogare ES esuata: {e}",
                                severity="high", dedup_key=f"absence:err:{name}",
                                dedup_minutes=30, host="es-node-1")
            log.error("verificarea %s a esuat: %s", name, e)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())

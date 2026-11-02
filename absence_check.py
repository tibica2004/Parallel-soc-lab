#!/usr/bin/env python3
"""
ALERTE DE ABSENTA SI INTEGRITATE (0.4 + 3.D) — ce NU se mai intampla.

Ruleaza pe es-node-1 dintr-un timer (soc-absence.timer, la 1 minut) si pagineaza
omul pe Discord cand un semn de viata dispare. Verificari independente (esecul
uneia nu le opreste pe celelalte):

  1. BACKUP vechi: ultimul `soc-backup OK` (logs-system.syslog-*, de pe web-prod)
     mai vechi de 26 h -> copia de siguranta nu mai ruleaza.
  2. ORCHESTRATOR / TUNEL cazut: `systemctl is-active` local != active.
  3. CANAR lipsa: ultimul eveniment soc-canary (logs-endpoint.events.process-*) mai
     vechi de 12 min -> telemetria de proces de pe web-prod s-a oprit.
  4. TACERE PE FLUX (3.D): fiecare flux de telemetrie al web-prod (Defend proces/
     fisier/retea, auditd, syslog, auth, Suricata) are un prag propriu, ales din
     pauzele reale masurate pe 3 zile (max 4-6 min). Prinde o integrare care moare
     singura cat agentul ramane "Healthy". Apache NU e aici: poate tacea ore legitim.
  5. FLEET-SERVER (3.D): /api/status != HEALTHY -> agentii nu mai primesc politici.

Fiecare problema: pointer pe Discord (notify.py, dedup per tip) + document
`integrity_alert` in soc-incidents (inregistrarea durabila, dedup separat, ca un
Discord cazut sa nu piarda alerta). La fiecare rulare: un puls `integrity_check` in
soc-metrics; orchestratorul pagineaza daca pulsul lipseste (cine pazeste paznicul).

  6. HASH-URI PE WEB-PROD (1b.2), la fiecare HASH_EVERY_MIN minute, prin gate-ul read-only
     soc-reader (reader.py): canarul (binar + cron) comparat cu o referinta SCRISA DE OM
     (CANARY_REF; nu se actualizeaza singura) si fisierele cron (/etc/crontab, /etc/cron.d/*)
     comparate cu ultima stare vazuta (CRON_STATE; prima rulare o invata, apoi fiecare
     schimbare se raporteaza o data, ca la AIDE).

  7. ORCHESTRATOR (pasul 7): ultimul document soc-metrics type=cycle mai vechi de
     CYCLE_MAX_AGE_MIN -> bucla e blocata chiar daca serviciul e "active"; >= SLOW_COUNT
     cicluri cu duration_s > SLOW_CYCLE_S in ultimele 10 min -> lent.
  8. SONDA LLM (pasul 7): ultimul type=llm_probe mai vechi de PROBE_MAX_AGE_MIN -> sonda e
     moarta (tunelul cazut il raporteaza sonda insasi, llm_probe.py).
     Citire cu ES_READER_API_KEY: ES_API_KEY nu are drept pe soc-metrics (403, masurat).

Inca NU: starea agentului din Fleet API (cere o cheie Kibana cu fleet:read, creata de om).

Iesire: 0 daca verificarile au rulat (chiar daca s-au gasit probleme), 1 daca o
verificare sau o scriere a esuat (ca journalul sa arate rosu).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

import requests
from elasticsearch import Elasticsearch
from pydantic import BaseModel, ConfigDict, Field

import notify
import reader

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s",
                    stream=sys.stderr)
log = logging.getLogger("soc.absence")

BACKUP_MAX_AGE_H = float(os.environ.get("ABSENCE_BACKUP_MAX_AGE_H", "26"))
CANARY_MAX_AGE_MIN = float(os.environ.get("ABSENCE_CANARY_MAX_AGE_MIN", "12"))
CANARY_HOST = os.environ.get("CANARY_HOST", "web-prod")
SERVICES = os.environ.get("ABSENCE_SERVICES", "soc-orchestrator,soc-llm-tunnel").split(",")
FLEET_STATUS_URL = os.environ.get("FLEET_STATUS_URL", "http://localhost:8220/api/status")
INCIDENTS_IDX = "soc-incidents"
METRICS_IDX = "soc-metrics"
INCIDENT_DEDUP_MIN = 10
CYCLE_MAX_AGE_MIN = float(os.environ.get("ABSENCE_CYCLE_MAX_AGE_MIN", "15"))
SLOW_CYCLE_S = float(os.environ.get("ABSENCE_SLOW_CYCLE_S", "110"))
SLOW_COUNT = int(os.environ.get("ABSENCE_SLOW_COUNT", "3"))
SURICATA_RULES_MAX_AGE_H = float(os.environ.get("ABSENCE_SURICATA_RULES_MAX_AGE_H", "26"))
# Activ doar dupa instalarea soc-suricata-update.timer pe web-prod (altfel ar pagina "niciun log").
SURICATA_RULES_CHECK = os.environ.get("ABSENCE_SURICATA_RULES", "0") == "1"
ES_DISK_MAX_PCT = float(os.environ.get("ABSENCE_ES_DISK_MAX_PCT", "80"))
ES_HEAP_MAX_PCT = float(os.environ.get("ABSENCE_ES_HEAP_MAX_PCT", "90"))
PROBE_MAX_AGE_MIN = float(os.environ.get("ABSENCE_PROBE_MAX_AGE_MIN", "5"))
HASH_EVERY_MIN = int(os.environ.get("INTEGRITY_HASH_EVERY_MIN", "10"))
_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
CANARY_REF = os.environ.get("INTEGRITY_CANARY_REF", os.path.join(_DATA, "canary.sha256"))
CRON_STATE = os.environ.get("INTEGRITY_CRON_STATE", os.path.join(_DATA, "cron.sha256"))

# (nume, data stream, campul cu numele hostului, prag in minute). Pragurile: ~2x pauza
# maxima reala pe 3 zile (2026-10-30: 4 min peste tot, 6 min la fisiere, 0 la Suricata).
# Suricata nu are host.name in evenimente, doar agent.name.
STREAMS: tuple[tuple[str, str, str, float], ...] = (
    ("defend_process", "logs-endpoint.events.process-*", "host.name", 10),
    ("defend_network", "logs-endpoint.events.network-*", "host.name", 10),
    ("defend_file", "logs-endpoint.events.file-*", "host.name", 15),
    ("auditd", "logs-auditd_manager.auditd-*", "host.name", 10),
    ("syslog", "logs-system.syslog-*", "host.name", 10),
    ("auth", "logs-system.auth-*", "host.name", 10),
    ("suricata", "logs-suricata.eve-*", "agent.name", 10),
)


class IntegrityKind(str, Enum):
    """Ce s-a stricat. Enumerare inchisa (R6): textul liber sta doar in detail."""
    TELEMETRY_SILENCE = "telemetry_silence"
    CANARY_MISSING = "canary_missing"
    FLEET_DOWN = "fleet_down"
    SERVICE_DOWN = "service_down"
    BACKUP_STALE = "backup_stale"
    CHECK_FAILED = "check_failed"
    CANARY_TAMPERED = "canary_tampered"
    CRON_CHANGED = "cron_changed"
    ORCHESTRATOR_STALLED = "orchestrator_stalled"   # 7.5: procesul traieste, bucla nu
    ORCHESTRATOR_SLOW = "orchestrator_slow"
    LLM_TUNNEL_DOWN = "llm_tunnel_down"             # scris de llm_probe.py
    PROBE_MISSING = "probe_missing"                 # llm_probe nu mai raporteaza
    ES_RED = "es_red"                               # pasul 11: cluster rosu
    ES_DISK = "es_disk"                             # disc peste prag
    ES_HEAP = "es_heap"                             # heap JVM peste prag
    SURICATA_RULES_STALE = "suricata_rules_stale"   # pasul 12: reguli IDS neactualizate


class IntegrityAlert(BaseModel):
    """Documentul din soc-incidents. extra=forbid: nimic in afara schemei."""
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    timestamp: datetime = Field(alias="@timestamp")
    type: Literal["integrity_alert"] = "integrity_alert"
    kind: IntegrityKind
    severity: Literal["critical", "high"]
    host: str = Field(max_length=64)
    subject: str = Field(max_length=64)          # fluxul / serviciul / verificarea
    detail: str = Field(max_length=500)          # audit, text liber
    age_min: float | None = None
    threshold_min: float | None = None
    status: Literal["open"] = "open"
    source: Literal["absence_check"] = "absence_check"


class Run:
    """Ce a gasit o rulare: problemele (pentru puls) si erorile (pentru codul de iesire)."""

    def __init__(self, now: datetime, incidents: Elasticsearch | None):
        self.now = now
        self.incidents = incidents
        self.kinds: list[str] = []
        self.ages: dict[str, float | None] = {}
        self.failed = False

    def problem(self, kind: IntegrityKind, title: str, detail: str, *, severity: str,
                host: str, subject: str, dedup_minutes: float,
                age_min: float | None = None, threshold_min: float | None = None) -> None:
        """Discord (dedup in notify.py) + soc-incidents (dedup propriu, mai scurt)."""
        self.kinds.append(f"{kind.value}:{subject}")
        key = f"absence:{kind.value}:{subject}"
        notify.notify_human(title, detail, severity=severity, dedup_key=key,
                            dedup_minutes=dedup_minutes, host=host)
        ikey = f"incident:{key}"
        if notify.recent(ikey, INCIDENT_DEDUP_MIN):
            return
        if self.incidents is None:
            log.error("ES_INCIDENTS_WRITER_API_KEY lipsa: integrity_alert %s nescris", key)
            self.failed = True
            return
        doc = IntegrityAlert(timestamp=self.now, kind=kind, severity=severity, host=host,
                             subject=subject, detail=detail[:500], age_min=age_min,
                             threshold_min=threshold_min)
        try:
            self.incidents.index(index=INCIDENTS_IDX,
                                 document=doc.model_dump(mode="json", by_alias=True))
            notify.mark(ikey)
        except Exception as e:
            log.error("scriere integrity_alert %s esuata: %s", key, e)
            self.failed = True


def _client(var: str, required: bool) -> Elasticsearch | None:
    key = os.environ.get(var)
    if not key:
        if required:
            raise KeyError(var)
        return None
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"), api_key=key,
                         request_timeout=20)


def _es() -> Elasticsearch:
    if os.environ.get("ES_READONLY_API_KEY"):
        return _client("ES_READONLY_API_KEY", True)
    return _client("ES_API_KEY", True)


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def check_backup(es: Elasticsearch, run: Run) -> None:
    r = es.esql.query(query="""
        FROM logs-system.syslog-*
        | WHERE process.name == "soc-backup" AND STARTS_WITH(message, "OK")
        | SORT @timestamp DESC
        | KEEP @timestamp
        | LIMIT 1
    """, format="json")
    if not r["values"]:
        run.problem(IntegrityKind.BACKUP_STALE, "Backup: niciun `soc-backup OK` gasit",
                    "Nu exista niciun log de backup reusit in logs-system.syslog-*. "
                    "Verifica soc-backup.timer pe web-prod si maparea campului (tag=soc-backup).",
                    severity="high", host="web-prod", subject="backup_none", dedup_minutes=720)
        log.warning("backup: niciun log soc-backup OK")
        return
    age_h = (run.now - _parse(r["values"][0][0])).total_seconds() / 3600
    run.ages["backup_h"] = round(age_h, 2)
    if age_h > BACKUP_MAX_AGE_H:
        run.problem(IntegrityKind.BACKUP_STALE, "Backup vechi: nu mai ruleaza",
                    f"Ultimul `soc-backup OK` acum {age_h:.1f} h (prag {BACKUP_MAX_AGE_H:.0f} h). "
                    "Verifica soc-backup.timer pe web-prod si soc-backup-pull.timer pe es-node-1.",
                    severity="high", host="web-prod", subject="backup", dedup_minutes=360,
                    age_min=round(age_h * 60, 1), threshold_min=BACKUP_MAX_AGE_H * 60)
        log.warning("backup vechi: %.1f h", age_h)
    else:
        log.info("backup OK: acum %.1f h", age_h)


def check_suricata_rules(es: Elasticsearch, run: Run) -> None:
    """Pasul 12: ultima actualizare reusita a regulilor Suricata (soc-suricata-update OK)."""
    if not SURICATA_RULES_CHECK:
        return
    r = es.esql.query(query="""
        FROM logs-system.syslog-*
        | WHERE process.name == "soc-suricata-update" AND STARTS_WITH(message, "OK")
        | SORT @timestamp DESC
        | KEEP @timestamp
        | LIMIT 1
    """, format="json")
    age_h = None if not r["values"] else (run.now - _parse(r["values"][0][0])).total_seconds() / 3600
    run.ages["suricata_rules_h"] = None if age_h is None else round(age_h, 2)
    if age_h is None or age_h > SURICATA_RULES_MAX_AGE_H:
        shown = "nicio actualizare reusita" if age_h is None else f"ultima reusita acum {age_h:.1f} h"
        run.problem(IntegrityKind.SURICATA_RULES_STALE, "Regulile Suricata nu se mai actualizeaza",
                    f"{shown} (prag {SURICATA_RULES_MAX_AGE_H:.0f} h). Verifica soc-suricata-update.timer "
                    "pe web-prod (iesire spre rules.emergingthreats.net?).", severity="high",
                    host="web-prod", subject="suricata_rules", dedup_minutes=720,
                    age_min=None if age_h is None else round(age_h * 60, 1),
                    threshold_min=SURICATA_RULES_MAX_AGE_H * 60)


def check_canary(es: Elasticsearch, run: Run) -> None:
    r = es.esql.query(query=f"""
        FROM logs-endpoint.events.process-*
        | WHERE host.name == "{CANARY_HOST}" AND process.name == "soc-canary"
        | SORT event.ingested DESC
        | KEEP event.ingested
        | LIMIT 1
    """, format="json")
    if not r["values"]:
        run.problem(IntegrityKind.CANARY_MISSING, "Canar lipsa: telemetrie oprita?",
                    f"Niciun eveniment soc-canary pentru {CANARY_HOST}. Cron-ul ruleaza? Agentul trimite?",
                    severity="critical", host=CANARY_HOST, subject="canary_none", dedup_minutes=30)
        log.warning("canar: niciun eveniment")
        return
    age_min = (run.now - _parse(r["values"][0][0])).total_seconds() / 60
    run.ages["canary"] = round(age_min, 1)
    if age_min > CANARY_MAX_AGE_MIN:
        run.problem(IntegrityKind.CANARY_MISSING, "Telemetrie oprita (canar vechi)",
                    f"Ultimul soc-canary acum {age_min:.0f} min (prag {CANARY_MAX_AGE_MIN:.0f} min). "
                    f"Elastic Agent de pe {CANARY_HOST} raporteaza HEALTHY dar nu trimite evenimente?",
                    severity="critical", host=CANARY_HOST, subject="canary", dedup_minutes=30,
                    age_min=round(age_min, 1), threshold_min=CANARY_MAX_AGE_MIN)
        log.warning("canar vechi: %.0f min", age_min)
    else:
        log.info("canar OK: acum %.1f min", age_min)


def stream_age_min(es: Elasticsearch, index: str, field: str, host: str,
                   now: datetime) -> float | None:
    """Varsta ultimului eveniment al hostului pe flux, in minute; None = nimic in 24 h.
    Hostul intra ca valoare intr-un term (R7), nu concatenat intr-o interogare."""
    r = es.search(index=index, size=0, query={"bool": {"filter": [
        {"term": {field: host}},
        # lte now+5m: un eveniment cu ceasul stricat in viitor nu ascunde tacerea
        {"range": {"@timestamp": {"gte": "now-24h", "lte": "now+5m"}}}]}},
        aggs={"last": {"max": {"field": "@timestamp"}}})
    last = (r.get("aggregations") or {}).get("last", {}).get("value_as_string")
    if not last:
        return None
    return max(0.0, (now - _parse(last)).total_seconds() / 60)


def check_streams(es: Elasticsearch, run: Run, host: str = CANARY_HOST) -> None:
    silent: list[str] = []
    for name, index, field, limit in STREAMS:
        try:
            age = stream_age_min(es, index, field, host, run.now)
        except Exception as e:
            run.problem(IntegrityKind.CHECK_FAILED, f"Absence-check: fluxul `{name}` nu poate fi citit",
                        f"Interogare ES esuata: {type(e).__name__}", severity="high",
                        host="es-node-1", subject=f"stream_{name}", dedup_minutes=30)
            run.failed = True
            continue
        run.ages[name] = None if age is None else round(age, 1)
        if age is None or age > limit:
            silent.append(name)
            shown = "nimic in 24 h" if age is None else f"ultimul eveniment acum {age:.0f} min"
            run.problem(IntegrityKind.TELEMETRY_SILENCE, f"Telemetrie tacuta: {name} ({host})",
                        f"Fluxul {index} pentru {host}: {shown} (prag {limit:.0f} min). "
                        "Integrarea poate fi cazuta desi agentul apare Healthy in Fleet.",
                        severity="high", host=host, subject=name, dedup_minutes=30,
                        age_min=None if age is None else round(age, 1), threshold_min=limit)
            log.warning("flux %s tacut: %s", name, shown)
        else:
            log.info("flux %s OK: acum %.1f min", name, age)
    if silent and len(silent) == len(STREAMS):
        run.problem(IntegrityKind.TELEMETRY_SILENCE, f"{host} tace complet",
                    f"Niciun flux de telemetrie nu mai vine de la {host}: agent oprit, host cazut "
                    "sau retea taiata spre Fleet.", severity="critical", host=host,
                    subject="all_streams", dedup_minutes=30)


def check_fleet_server(run: Run) -> None:
    try:
        r = requests.get(FLEET_STATUS_URL, timeout=5)
        status = r.json().get("status") if r.ok else f"HTTP {r.status_code}"
    except Exception as e:
        status = f"de neatins ({type(e).__name__})"
    if status != "HEALTHY":
        run.problem(IntegrityKind.FLEET_DOWN, "Fleet Server nu e HEALTHY",
                    f"{FLEET_STATUS_URL} -> {str(status)[:80]}. Agentii nu mai primesc politici "
                    "si nu mai raporteaza starea.", severity="critical", host="es-node-1",
                    subject="fleet_server", dedup_minutes=30)
        log.warning("fleet-server: %s", status)
    else:
        log.info("fleet-server: HEALTHY")


def check_services(run: Run) -> None:
    for svc in (s.strip() for s in SERVICES if s.strip()):
        try:
            out = subprocess.run(["systemctl", "is-active", svc],
                                 capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception as e:
            out = f"eroare: {e}"
        if out != "active":
            run.problem(IntegrityKind.SERVICE_DOWN, f"Serviciu cazut: {svc}",
                        f"`systemctl is-active {svc}` = {out}. Creierul SOC sau tunelul LLM nu mai ruleaza.",
                        severity="critical", host="es-node-1", subject=svc, dedup_minutes=30)
            log.warning("serviciu %s: %s", svc, out)
        else:
            log.info("serviciu %s: active", svc)


def _read_ref(path: str) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as f:
            return reader.parse_sha256sum(f.read())
    except OSError:
        return {}


def hash_diff(ref: dict[str, str], now: dict[str, str]) -> dict[str, list[str]]:
    """{added, removed, changed}: caile care difera intre doua stari {cale: sha256}. Pur."""
    return {"added": sorted(set(now) - set(ref)), "removed": sorted(set(ref) - set(now)),
            "changed": sorted(k for k in set(ref) & set(now) if ref[k] != now[k])}


def check_canary_hash(run: Run) -> None:
    """Canarul (binar + cron) == referinta scrisa de om. Un canar modificat poate raporta
    „viu” in timp ce atacatorul il controleaza: critic. Referinta lipsa = nu pot verifica (R9)."""
    ref = _read_ref(CANARY_REF)
    if not ref:
        run.problem(IntegrityKind.CHECK_FAILED, "Canar: referinta de hash lipsa",
                    f"{CANARY_REF} lipseste sau e gol: hash-ul canarului nu poate fi verificat.",
                    severity="high", host="es-node-1", subject="canary_ref", dedup_minutes=360)
        run.failed = True
        return
    now = reader.parse_sha256sum(reader.run(reader.ReaderCommand.CANARY_HASH))
    d = hash_diff(ref, now)
    bad = d["changed"] + d["removed"] + d["added"]
    run.ages["canary_hash_ok"] = 0.0 if bad else 1.0
    if bad:
        run.problem(IntegrityKind.CANARY_TAMPERED, "Canar modificat pe web-prod",
                    f"Hash diferit de referinta pentru: {', '.join(bad)[:300]}. Canarul poate fi "
                    "controlat de altcineva; telemetria lui nu mai dovedeste nimic.",
                    severity="critical", host=CANARY_HOST, subject="canary_hash", dedup_minutes=30)
        log.warning("canar modificat: %s", d)
    else:
        log.info("canar hash OK")


def check_cron_hash(run: Run) -> None:
    """Fisierele cron vs ultima stare vazuta. Prima rulare invata starea; apoi orice fisier
    nou/sters/modificat se raporteaza O DATA si devine noua stare (persistenta, T1053.003)."""
    now = reader.parse_sha256sum(reader.run(reader.ReaderCommand.CRON_HASH))
    if not now:
        raise reader.ReaderError("raspuns sha256sum gol sau neparsabil")
    ref = _read_ref(CRON_STATE)
    if ref:
        d = hash_diff(ref, now)
        bad = d["added"] + d["removed"] + d["changed"]
        if bad:
            run.problem(IntegrityKind.CRON_CHANGED, "Cron schimbat pe web-prod",
                        f"adaugate: {d['added']} sterse: {d['removed']} modificate: {d['changed']}"[:480],
                        severity="high", host=CANARY_HOST, subject="cron", dedup_minutes=30)
            log.warning("cron schimbat: %s", d)
        else:
            log.info("cron hash OK (%d fisiere)", len(now))
    else:
        log.info("cron: stare initiala invatata (%d fisiere)", len(now))
    tmp = CRON_STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("".join(f"{h}  {p}\n" for p, h in sorted(now.items())))
    os.replace(tmp, CRON_STATE)


def _last_age_min(es: Elasticsearch, type_: str, now: datetime) -> float | None:
    r = es.search(index=METRICS_IDX, size=0, query={"term": {"type.keyword": type_}},
                  aggs={"last": {"max": {"field": "@timestamp"}}})
    last = r["aggregations"]["last"].get("value_as_string")
    return None if not last else (now - _parse(last)).total_seconds() / 60


def check_orchestrator_cycles(es: Elasticsearch, run: Run) -> None:
    age = _last_age_min(es, "cycle", run.now)
    run.ages["orchestrator_cycle"] = None if age is None else round(age, 1)
    if age is None or age > CYCLE_MAX_AGE_MIN:
        shown = "niciun ciclu inregistrat" if age is None else f"ultimul ciclu acum {age:.0f} min"
        run.problem(IntegrityKind.ORCHESTRATOR_STALLED, "Orchestratorul nu mai termina cicluri",
                    f"{shown} (prag {CYCLE_MAX_AGE_MIN:.0f} min; ciclurile lungi masurate: pana la "
                    f"~12 min sub harness). Serviciul poate fi 'active' cu bucla blocata.",
                    severity="critical", host="es-node-1", subject="soc-orchestrator",
                    dedup_minutes=30, age_min=age, threshold_min=CYCLE_MAX_AGE_MIN)
        return
    r = es.search(index=METRICS_IDX, size=0, query={"bool": {"filter": [
        {"term": {"type.keyword": "cycle"}},
        {"range": {"@timestamp": {"gte": "now-10m"}}},
        {"range": {"duration_s": {"gt": SLOW_CYCLE_S}}}]}}, track_total_hits=True)
    slow = r["hits"]["total"]["value"]
    if slow >= SLOW_COUNT:
        run.problem(IntegrityKind.ORCHESTRATOR_SLOW, "Orchestratorul e lent",
                    f"{slow} cicluri peste {SLOW_CYCLE_S:.0f} s in 10 min (intervalul e 120 s): "
                    "restanta creste. Model lent? Prea multe investigatii Tier 2?",
                    severity="high", host="es-node-1", subject="soc-orchestrator", dedup_minutes=60)
    log.info("orchestrator: ultimul ciclu acum %.1f min, %d lente in 10 min", age, slow)


def check_llm_probe(es: Elasticsearch, run: Run) -> None:
    age = _last_age_min(es, "llm_probe", run.now)
    run.ages["llm_probe"] = None if age is None else round(age, 1)
    if age is None or age > PROBE_MAX_AGE_MIN:
        shown = "nicio sonda" if age is None else f"ultima sonda acum {age:.0f} min"
        run.problem(IntegrityKind.PROBE_MISSING, "Sonda LLM nu mai raporteaza",
                    f"{shown} (prag {PROBE_MAX_AGE_MIN:.0f} min). Verifica soc-llm-probe.timer.",
                    severity="high", host="es-node-1", subject="soc-llm-probe", dedup_minutes=60,
                    age_min=age, threshold_min=PROBE_MAX_AGE_MIN)


def es_health_problems(health: dict, nodes: dict) -> list[tuple[str, str, float | None]]:
    """(tip, detaliu, valoare) din _cluster/health si _nodes/stats/fs,jvm. Galben e normal pe un
    singur nod (replici nealocate). Pur."""
    out = []
    if health.get("status") == "red":
        out.append(("es_red", f"cluster rosu: {health.get('unassigned_shards')} shard-uri nealocate", None))
    for n in (nodes.get("nodes") or {}).values():
        tot = ((n.get("fs") or {}).get("total") or {})
        if tot.get("total_in_bytes"):
            pct = 100 * (1 - tot.get("available_in_bytes", 0) / tot["total_in_bytes"])
            if pct > ES_DISK_MAX_PCT:
                out.append(("es_disk", f"disc {pct:.0f}% ocupat pe {n.get('name')}", round(pct, 1)))
        heap = ((n.get("jvm") or {}).get("mem") or {}).get("heap_used_percent")
        if heap is not None and heap > ES_HEAP_MAX_PCT:
            out.append(("es_heap", f"heap JVM {heap}% pe {n.get('name')}", float(heap)))
    return out


def check_es_health(es: Elasticsearch, run: Run) -> None:
    health = es.cluster.health()
    nodes = es.nodes.stats(metric="fs,jvm")
    kinds = {"es_red": (IntegrityKind.ES_RED, "critical"), "es_disk": (IntegrityKind.ES_DISK, "critical"),
             "es_heap": (IntegrityKind.ES_HEAP, "high")}
    for kind, detail, _v in es_health_problems(dict(health), dict(nodes)):
        k, sev = kinds[kind]
        run.problem(k, f"Elasticsearch: {kind}", detail, severity=sev, host="es-node-1",
                    subject="es01", dedup_minutes=60)
    log.info("es: status=%s", health.get("status"))


def write_heartbeat(metrics: Elasticsearch | None, run: Run) -> None:
    """Pulsul din soc-metrics: orchestratorul pagineaza daca lipseste (paznicul paznicului)."""
    if metrics is None:
        log.error("ES_METRICS_WRITER_API_KEY lipsa: puls integrity_check nescris")
        run.failed = True
        return
    try:
        metrics.index(index=METRICS_IDX, document={
            "@timestamp": run.now.isoformat(), "type": "integrity_check",
            "result": "alert" if run.kinds else "ok", "kinds": run.kinds,
            "ages_min": run.ages})
    except Exception as e:
        log.error("puls integrity_check nescris: %s", e)
        run.failed = True


def main() -> int:
    run = Run(datetime.now(timezone.utc), _client("ES_INCIDENTS_WRITER_API_KEY", False))
    # Verificarile locale ruleaza mereu, chiar daca ES e cazut.
    check_services(run)
    check_fleet_server(run)
    try:
        es = _es()
    except Exception as e:
        notify.notify_human("Absence-check: Elasticsearch de neatins",
                            f"Nu pot initializa clientul ES: {e}",
                            severity="high", dedup_key="absence:es_init", dedup_minutes=30,
                            host="es-node-1")
        log.error("ES init esuat: %s", e)
        return 1
    for name, fn in (("backup", check_backup), ("canar", check_canary), ("fluxuri", check_streams),
                     ("reguli_suricata", check_suricata_rules)):
        try:
            fn(es, run)
        except Exception as e:
            run.problem(IntegrityKind.CHECK_FAILED, f"Absence-check: verificarea `{name}` a esuat",
                        f"Interogare ES esuata: {e}", severity="high", host="es-node-1",
                        subject=f"check_{name}", dedup_minutes=30)
            log.error("verificarea %s a esuat: %s", name, e)
            run.failed = True
    # Hash-urile de pe web-prod (prin soc-reader) doar la fiecare HASH_EVERY_MIN minute.
    if HASH_EVERY_MIN > 0 and run.now.minute % HASH_EVERY_MIN == 0:
        for name, fn in (("canar_hash", check_canary_hash), ("cron_hash", check_cron_hash)):
            try:
                fn(run)
            except Exception as e:
                run.problem(IntegrityKind.CHECK_FAILED, f"Absence-check: verificarea `{name}` a esuat",
                            f"soc-reader: {type(e).__name__}: {str(e)[:200]}", severity="high",
                            host="es-node-1", subject=f"check_{name}", dedup_minutes=30)
                log.error("verificarea %s a esuat: %s", name, e)
                run.failed = True
    # Pasul 7: orchestratorul si sonda LLM, citite din soc-metrics (doar ES_READER are drept).
    reader_es = _client("ES_READER_API_KEY", False)
    if reader_es is None:
        log.error("ES_READER_API_KEY lipsa: verificarile orchestrator/sonda sarite")
        run.failed = True
    else:
        for name, fn in (("orchestrator", check_orchestrator_cycles), ("sonda_llm", check_llm_probe)):
            try:
                fn(reader_es, run)
            except Exception as e:
                run.problem(IntegrityKind.CHECK_FAILED, f"Absence-check: verificarea `{name}` a esuat",
                            f"Interogare ES esuata: {e}", severity="high", host="es-node-1",
                            subject=f"check_{name}", dedup_minutes=30)
                log.error("verificarea %s a esuat: %s", name, e)
                run.failed = True
    # Pasul 11: sanatatea clusterului, cu cheia soc-monitor (cluster:monitor si nimic altceva).
    mon = _client("ES_MONITOR_API_KEY", False)
    if mon is not None:
        try:
            check_es_health(mon, run)
        except Exception as e:
            run.problem(IntegrityKind.CHECK_FAILED, "Absence-check: verificarea `es_health` a esuat",
                        f"{type(e).__name__}: {str(e)[:200]}", severity="high", host="es-node-1",
                        subject="check_es_health", dedup_minutes=30)
            run.failed = True
    write_heartbeat(_client("ES_METRICS_WRITER_API_KEY", False), run)
    return 1 if run.failed else 0


if __name__ == "__main__":
    sys.exit(main())

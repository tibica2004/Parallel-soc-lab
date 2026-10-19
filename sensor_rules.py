"""
REGULI DE SENZOR (faza 12): detectii ale senzorilor nostri (deocamdata YARA pe
webroot) transformate in alerte Kibana, ca sa intre pe calea rapida.

Spre deosebire de honeytokens, o potrivire YARA poate fi fals pozitiva (o
biblioteca PHP legitima cu eval). De aceea nu exista podea spre suspicious: doar
motivul de escaladare SENSOR_DETECTION, ca Tier 1 sa nu inchida singur cazul
(ca la detectiile native ale EDR-ului). Recunoasterea e dupa rule_id, multime
inchisa, nu dupa nume.

Alerta vine dintr-un rand de jurnal scris de /usr/local/sbin/soc-yara-scan pe
web-prod: procesul din alerta e scannerul (root), nu cel care a scris fisierul.
Faptele utile (regula, cale, sha256) se extrag din mesaj, validate.
"""

from __future__ import annotations

import json
import re

import honeytokens

TAG = "soc-sensor"
YARA_TAG = "soc-yara"                 # identificatorul din jurnal (syslog) al scannerului
YARA_PROC = "soc-yara-scan"           # numele procesului (scriptul din /usr/local/sbin)

RULES: dict[str, dict] = {
    "soc-yara-webshell": {
        "name": "YARA: webshell gasit in webroot",
        "description": "Scanarea YARA a /var/www (soc-yara-scan pe host) a gasit un fisier care se "
                       "potriveste cu o regula de webshell. Calea si regula sunt in mesaj.",
        "type": "query",
        "language": "kuery",
        "index": ["logs-system.syslog-*"],
        # Integrarea System (journald): eticheta syslog e in log.syslog.appname, iar
        # process.name e numele procesului (scriptul). Ambele trebuie sa se potriveasca.
        "query": f'log.syslog.appname : "{YARA_TAG}" and process.name : "{YARA_PROC}" '
                 f'and message : "yara_match"',
        "threat_technique": ("T1505.003", "Web Shell"),
    },
}

RULE_RE = re.compile(r"^[a-z0-9_]{1,64}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def is_sensor_alert(alert: dict) -> bool:
    return honeytokens.rule_id_of(alert) in RULES


def yara_facts(alert: dict) -> dict | None:
    """{rule, path, sha256} din mesajul JSON al scannerului; None daca nu se valideaza.
    Calea o alege atacatorul (nume de fisier): scurtata, ajunge la model ca DATE."""
    if not is_sensor_alert(alert):
        return None
    msg = alert.get("message")
    try:
        d = json.loads(msg) if isinstance(msg, str) else None
    except (TypeError, ValueError):
        return None
    if not isinstance(d, dict) or d.get("event") != "yara_match":
        return None
    rule, path, h = d.get("rule"), d.get("path"), d.get("sha256")
    if not (isinstance(rule, str) and RULE_RE.match(rule) and isinstance(path, str)
            and path.startswith("/") and isinstance(h, str) and SHA_RE.match(h)):
        return None
    return {"sensor": "yara", "rule": rule, "path": path[:200], "sha256": h}


def kibana_payload(rule_id: str) -> dict:
    return honeytokens.kibana_payload(rule_id, rules=RULES, severity="high", risk=80, tag=TAG)

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

import ipaddress
import json
import re

import honeytokens

TAG = "soc-sensor"
YARA_TAG = "soc-yara"                 # identificatorul din jurnal (syslog) al scannerului
YARA_PROC = "soc-yara-scan"           # numele procesului (scriptul din /usr/local/sbin)
SURICATA_IDX = "logs-suricata.eve-*"  # indicele Suricata (local, ca sa nu importam elastic_tools)
APACHE_IDX = "logs-apache.*"          # logurile de acces Apache ale serverului web
AUTH_IDX = "logs-system.auth-*"       # jurnalul de autentificare al sistemului (sshd)

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
    "soc-suricata-webattack": {
        "name": "Suricata: tentativa de atac web (IDS)",
        "description": "Suricata (ET Open) a potrivit o semnatura de atac web asupra traficului "
                       "catre serverul web. Semnatura si categoria sunt in alerta; source.ip e "
                       "originea. Senzor de retea: nu exista proces. Poate fi fals pozitiv.",
        "type": "query",
        "language": "kuery",
        "index": [SURICATA_IDX],
        # Suricata (ECS): alerta e event.kind="alert", semnatura in rule.name, clasa in
        # rule.category. Restrangem la categoriile de atac web (set ET), ca sa nu ridicam
        # orice semnatura IDS. Categoriile sunt constante ale setului de reguli, nu telemetrie.
        "query": 'event.kind : "alert" and rule.category : '
                 '("Web Application Attack" or "Attempted Administrator Privilege Gain" '
                 'or "Attempted User Privilege Gain")',
        "threat_technique": ("T1190", "Exploit Public-Facing Application"),
    },
    # Enumerare de continut (brute-force de directoare/fisiere: ffuf, feroxbuster, dirb,
    # wpscan). Semnatura Suricata nu prinde cererile GET "benigne"; semnalul e VOLUMUL de
    # raspunsuri 4xx de la un singur source.ip. Regula de prag numara pe source.ip intr-o
    # fereastra scurta. Caile cerute sunt alese de atacator = DATE; nu intra in interogare.
    "soc-web-content-enum": {
        "name": "Enumerare continut web (scanare directoare/fisiere)",
        "description": "Un singur source.ip a generat multe raspunsuri 4xx pe serverul web intr-o "
                       "fereastra scurta - tipic brute-force de continut (ffuf, feroxbuster, dirb, "
                       "wpscan). Pragul e pe source.ip; caile cerute sunt date, nu in interogare.",
        "type": "threshold",
        "language": "kuery",
        "index": [APACHE_IDX],
        "query": "http.response.status_code >= 400",
        "threshold": {"field": ["source.ip"], "value": 40},
        "interval": "1m",
        "from": "now-6m",
        "threat_technique": ("T1595", "Active Scanning"),
    },
    # Brute-force pe autentificarea web (hydra, wpscan --password-attack, patator). Semnalul
    # e volumul de cereri POST catre pagina de login de la un singur source.ip. Suricata vede
    # doar "cleartext login" (ET INFO, nepromovat); aici prindem volumul direct din Apache.
    "soc-http-auth-bruteforce": {
        "name": "Brute-force autentificare web (login WordPress)",
        "description": "Un singur source.ip a trimis multe cereri POST catre pagina de "
                       "autentificare (/wp-login.php) intr-o fereastra scurta - tipic brute-force "
                       "de parole (hydra, wpscan, patator). Pragul e pe source.ip.",
        "type": "threshold",
        "language": "kuery",
        "index": [APACHE_IDX],
        "query": 'http.request.method : "POST" and url.path : "/wp-login.php"',
        "threshold": {"field": ["source.ip"], "value": 10},
        "interval": "1m",
        "from": "now-6m",
        "threat_technique": ("T1110", "Brute Force"),
    },
    # Brute-force SSH (hydra, medusa, patator). Esecurile de auth sunt in jurnalul de
    # sistem (Integrarea System): system.auth.ssh.event="Failed", cu source.ip. Prag pe
    # source.ip intr-o fereastra scurta. SSH e criptat, deci Suricata nu vede esecurile.
    "soc-ssh-bruteforce": {
        "name": "Brute-force SSH (esecuri de autentificare)",
        "description": "Un singur source.ip a produs multe esecuri de autentificare SSH intr-o "
                       "fereastra scurta - tipic brute-force de parole (hydra, medusa, patator). "
                       "Pragul e pe source.ip; numele de utilizator incercat ramane date.",
        "type": "threshold",
        "language": "kuery",
        "index": [AUTH_IDX],
        "query": 'system.auth.ssh.event : "Failed"',
        "threshold": {"field": ["source.ip"], "value": 10},
        "interval": "1m",
        "from": "now-6m",
        "threat_technique": ("T1110", "Brute Force"),
    },
    # Tentativa de SQL injection: payload-urile apar in url.original (encodate URL).
    # Semnatura dupa tokeni SQLi puternici (constante in regula, nu din telemetrie); e
    # posibil fals pozitiv, de aceea doar escaladeaza (ca Suricata), nu pune podea. sqlmap
    # pe un parametru neinjectabil tot e vizibil: tentativa conteaza pentru avertizare.
    "soc-web-sqli-attempt": {
        "name": "Tentativa de SQL injection (web)",
        "description": "Cereri catre serverul web cu tokeni tipici de SQL injection in URL "
                       "(UNION, ORDER BY, SLEEP, information_schema, EXTRACTVALUE) - tipic sqlmap "
                       "sau injectie manuala. Poate fi fals pozitiv; source.ip e originea.",
        "type": "query",
        "language": "kuery",
        "index": [APACHE_IDX],
        # Tokenii apar encodati URL in url.original (%20=spatiu, %27='  %28=( ). Multime
        # inchisa de tipare puternice, ca sa limitam fals pozitivele pe continut legitim.
        "query": ('url.original : (*UNION* or *union%20select* or *ORDER%20BY* or *order%20by* '
                  'or *information_schema* or *SLEEP%28* or *sleep%28* or *EXTRACTVALUE* '
                  'or *UPDATEXML* or *%20AND%201%3D1* or *%20OR%201%3D1* or *%27%20OR%20%27*)'),
        "threat_technique": ("T1190", "Exploit Public-Facing Application"),
    },
}

SURICATA_RULE_ID = "soc-suricata-webattack"
# Categoriile ET considerate atac web; si poarta de validare a faptelor (multime inchisa).
WEB_ATTACK_CATEGORIES = ("Web Application Attack",
                         "Attempted Administrator Privilege Gain",
                         "Attempted User Privilege Gain")

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


def _field(alert: dict, key: str):
    """Camp plat ('a.b') sau imbricat, ca la honeytokens.rule_id_of; None daca lipseste."""
    if key in alert:
        return alert[key]
    cur = alert
    for part in key.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _is_ip(v) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except (TypeError, ValueError):
        return False


def suricata_facts(alert: dict) -> dict | None:
    """{sensor, signature, category, source_ip, destination_ip} dintr-o alerta IDS de
    atac web, sau None daca nu se valideaza. Semnatura si categoria vin din setul ET
    (nu din telemetrie), dar le tratam ca DATE in prompt. Categoria trebuie sa fie din
    multimea de atac web (altfel regula a prins altceva); source.ip e validat ca IP."""
    if honeytokens.rule_id_of(alert) != SURICATA_RULE_ID:
        return None
    sig, cat = _field(alert, "rule.name"), _field(alert, "rule.category")
    sip, dip = _field(alert, "source.ip"), _field(alert, "destination.ip")
    if not (isinstance(sig, str) and sig and cat in WEB_ATTACK_CATEGORIES and _is_ip(sip)):
        return None
    return {"sensor": "suricata", "signature": sig[:200], "category": cat,
            "source_ip": sip, "destination_ip": dip if _is_ip(dip) else None}


def sensor_facts(alert: dict) -> dict | None:
    """Faptele senzorului care a produs alerta: YARA (fisier din webroot) sau Suricata
    (semnatura de atac web pe retea). Fiecare se recunoaste dupa rule_id-ul propriu."""
    return yara_facts(alert) or suricata_facts(alert)


def kibana_payload(rule_id: str) -> dict:
    return honeytokens.kibana_payload(rule_id, rules=RULES, severity="high", risk=80, tag=TAG)

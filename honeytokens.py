"""
HONEYTOKENS — momeli plantate pe web-prod. Nimic legitim nu le atinge, deci o
atingere inseamna ca cineva exploreaza (post-exploatare), fara baseline si fara
model. Nu au conducta proprie: sunt reguli obisnuite in Kibana, iar alertele lor
intra pe calea rapida ca oricare alta.

Ce face codul diferit pentru ele (principiul 1, codul decide):
  - is_honeytoken(alert): dupa rule_id, dintr-o multime INCHISA definita aici
    (nu dupa nume sau etichete, pe care le poate schimba oricine din interfata);
  - should_escalate adauga motivul HONEYTOKEN: escaladare MEREU, oricat de sigur
    ar fi modelul ca e benign;
  - podea pe ambele niveluri: un benign pe honeytoken devine suspicious.

Momelile (plantate de om pe web-prod, vezi deploy/web-prod/README.md):
  1. DECOY_FILE: un .env.bak in webroot cu credentiale false (inclusiv DECOY_USER);
     servit si prin HTTP, ca momeala pentru cine scaneaza dupa .env.
  2. DECOY_URLS: cai web care nu exista in aplicatie.
  3. DECOY_USER: utilizator inexistent pe host, prezent doar in .env.bak. Folosirea
     lui la SSH inseamna ca cineva a citit fisierul si incearca credentialele.
  4. Pasul 3.C (WordPress/MySQL): constante DB_BACKUP_* false in wp-config.php (citire
     auditd + utilizator MySQL inexistent), backup.sql momeala cu un cont WordPress
     inexistent (logat de mu-plugin-ul soc-honey.php), cai-capcana in robots.txt.

Momeala atinsa de pe un IP propriu sau al generatorului benign (G3) nu e intruziune:
escaladeaza tot la om, dar cu motivul HONEYTOKEN_CONFIG_ERROR (escalation_reason).

Elastic Defend pe Linux nu logheaza citirile de fisiere: un `cat .env.bak` se
vede (calea e in argumente), un `grep -r pass /var/www` sau un file_get_contents()
dintr-un webshell nu. Le vede auditd (deploy/web-prod/auditd-fim.md), cu conditia
ca procesul sa fi pornit dupa activarea auditului: de aici audit=1 la boot.
"""

from __future__ import annotations

import ipaddress
import os

DECOY_FILE = "/var/www/html/.env.bak"
DECOY_URLS = ("/.env.bak", "/admin.old.php")
DECOY_USER = "svc_deploy"
AUDIT_KEY = "soc_honeytoken"     # cheia regulii auditd: -w DECOY_FILE -p r -k soc_honeytoken

# Pasul 3.C — momelile WordPress/MySQL (plantate de deploy/web-prod/honeytokens-wp.sh).
# Ca svc_deploy: NICIUN cont real nu se creeaza. Un cont MySQL fara GRANT se poate totusi
# autentifica (USAGE), iar autentificarea reusita nu apare in jurnalul de erori: momeala ar
# fi oarba exact la atacul vizat. Fara cont, orice incercare esueaza si se logheaza.
WP_CONFIG = "/var/www/html/wp-config.php"
WP_DECOY_DB_USER = "wp_backup"        # constanta DB_BACKUP_USER din wp-config.php
WP_DECOY_LOGIN = "backup_admin"       # apare doar in backup.sql; logat de mu-plugin
DECOY_SQL = "/var/www/html/backup.sql"
ROBOTS_TRAPS = ("/wp-admin-old", "/db-backup")    # Disallow din robots.txt, nelegate de nicaieri
WPCONFIG_KEY = "soc_honey_wpconfig"
SQL_KEY = "soc_honey_sql"

# Binarele care citesc wp-config.php legitim, la fiecare cerere sau rulare wp-cli. Caile
# reale se confirma pe host cu readlink -f inainte de lipirea regulilor in Fleet.
# web-prod (2026-10-30): mod_php in apache2, fara php-fpm; wp-cli ruleaza prin php8.3.
WPCONFIG_LEGIT_EXE = ("/usr/sbin/apache2", "/usr/bin/php8.3")

# Regulile auditd pentru politica auditd_manager (Fleet), sursa unica pentru documentatie si
# teste. A4: kernelul accepta UN singur camp exe per regula, deci excluderile sunt reguli
# "never" puse INAINTEA regulii "always" (prima potrivire castiga). tar ruleaza ca root in
# backup-ul de noapte (soc-backup.sh); un tar al atacatorului ca root ramane nevazut aici,
# dar nu si de Defend (calea apare in argumente).
AUDITD_RULES: tuple[str, ...] = (
    *(f"-a never,exit -F arch=b64 -F path={WP_CONFIG} -F perm=r -F exe={exe}" for exe in WPCONFIG_LEGIT_EXE),
    f"-a never,exit -F arch=b64 -F path={WP_CONFIG} -F perm=r -F exe=/usr/bin/tar -F uid=0",
    f"-a always,exit -F arch=b64 -F path={WP_CONFIG} -F perm=r -k {WPCONFIG_KEY}",
    f"-w {DECOY_SQL} -p r -k {SQL_KEY}",
)

TAG = "soc-honeytoken"
SEVERITY = "critical"          # in restanta, alertele critical escaladeaza fara model
RISK = 99

# rule_id fix -> definitia regulii. Multimea cheilor e lista INCHISA de honeytokens.
RULES: dict[str, dict] = {
    "soc-honeytoken-host": {
        "name": "Honeytoken: fisier momeala atins pe host",
        "description": "Un proces a primit ca argument fisierul momeala sau utilizatorul momeala, "
                       "ori fisierul momeala a fost modificat, mutat sau sters. Nimic legitim nu face asta.",
        "type": "eql",
        "language": "eql",
        "index": ["logs-endpoint.events.process-*", "logs-endpoint.events.file-*"],
        "query": (
            'any where host.os.type == "linux" and (\n'
            '  (event.category == "process" and event.type == "start" and\n'
            '     process.command_line : ("*.env.bak*", "*' + DECOY_USER + '*")) or\n'
            '  (event.category == "file" and file.path == "' + DECOY_FILE + '" and\n'
            '     event.type in ("change", "deletion"))\n'
            ')'
        ),
        "threat_technique": ("T1552.001", "Credentials In Files"),
    },
    "soc-honeytoken-read": {
        "name": "Honeytoken: fisier momeala citit (auditd)",
        "description": "Kernelul (auditd, cheia soc_honeytoken) a vazut un proces deschizand fisierul momeala "
                       "pentru citire: grep, un webshell PHP, orice. Defend nu vede citirile.",
        "type": "query",
        "language": "kuery",
        "index": ["logs-auditd_manager.auditd-*"],
        # Agentul Elastic nu e un atacator (o eventuala integrare FIM ar citi fisierele).
        "query": f'tags : "{AUDIT_KEY}" and not process.executable : /opt/Elastic/*',
        "threat_technique": ("T1552.001", "Credentials In Files"),
    },
    "soc-honeytoken-http": {
        "name": "Honeytoken: cerere web catre o cale momeala",
        "description": "Cerere HTTP catre o cale care nu exista in aplicatie si nu e legata de nicaieri.",
        "type": "query",
        "language": "kuery",
        "index": ["logs-apache.access-*"],
        "query": " or ".join(f'url.path : "{u}"' for u in DECOY_URLS),
        "threat_technique": ("T1083", "File and Directory Discovery"),
    },
    "soc-honeytoken-user": {
        "name": "Honeytoken: autentificare cu utilizatorul momeala",
        "description": "Cineva incearca utilizatorul momeala, care exista doar in fisierul .env.bak.",
        "type": "query",
        "language": "kuery",
        "index": ["logs-system.auth-*"],
        # user.name vine uneori cu spatiu in fata din parsare; message prinde si
        # 'Invalid user ...' (utilizatorul nu exista pe host).
        "query": f'user.name : "{DECOY_USER}" or message : "{DECOY_USER}"',
        "threat_technique": ("T1078", "Valid Accounts"),
    },
    # ---- pasul 3.C: WordPress / MySQL ----
    "soc-honey-wpconfig-read": {
        "name": "Honeytoken: wp-config.php citit de un proces neasteptat (auditd)",
        "description": "Kernelul (auditd, cheia soc_honey_wpconfig) a vazut wp-config.php deschis pentru "
                       "citire de alt proces decat apache2 (mod_php) sau php8.3 (wp-cli) (exclusi in regula auditd). Tipic "
                       "cat/grep dintr-un shell obtinut prin exploatare, dupa credentiale.",
        "type": "query",
        "language": "kuery",
        "index": ["logs-auditd_manager.auditd-*"],
        # yara (la 10 min) si aide (zilnic, 3.E) citesc wp-config.php intentionat (webshell
        # injectat / integritate). Excludere aici, nu in kernel: regulile auditd sunt blocate
        # (immutable) pana la reboot.
        "query": (f'tags : "{WPCONFIG_KEY}" and not process.executable : /opt/Elastic/* '
                  'and not process.executable : ("/usr/bin/yara" or "/usr/bin/aide")'),
        "threat_technique": ("T1552.001", "Credentials In Files"),
    },
    "soc-honey-mysql-user": {
        "name": "Honeytoken: autentificare MySQL cu utilizatorul momeala",
        "description": "Cineva a incercat utilizatorul MySQL momeala, care exista doar ca constanta in "
                       "wp-config.php (contul nu exista in baza). Inseamna ca wp-config.php a fost citit.",
        "type": "query",
        "language": "kuery",
        # MariaDB scrie in jurnalul de erori (integrare mysql) sau, implicit pe Ubuntu, in
        # journald -> syslog (integrarea system). Ambele, ca regula sa nu depinda de unde ajunge.
        "index": ["logs-mysql.error-*", "logs-system.syslog-*"],
        "query": f'message : "Access denied for user" and message : "{WP_DECOY_DB_USER}"',
        "threat_technique": ("T1078", "Valid Accounts"),
    },
    "soc-honey-wp-login": {
        "name": "Honeytoken: autentificare WordPress cu contul momeala",
        "description": "mu-plugin-ul soc-honey.php a logat o incercare de login cu backup_admin, cont "
                       "care apare doar in backup.sql (momeala). Cine il incearca a descarcat backup-ul.",
        "type": "query",
        "language": "kuery",
        "index": ["logs-apache.error-*"],
        "query": 'message : "SOC_HONEY"',
        "threat_technique": ("T1078", "Valid Accounts"),
    },
    "soc-honey-backup-sql-http": {
        "name": "Honeytoken: backup.sql momeala descarcat prin HTTP",
        "description": "Cerere reusita catre /backup.sql, un fisier momeala nelegat de nicaieri.",
        "type": "query",
        "language": "kuery",
        "index": ["logs-apache.access-*"],
        "query": 'url.path : "/backup.sql" and http.response.status_code : (200 or 206 or 304)',
        "threat_technique": ("T1083", "File and Directory Discovery"),
    },
    "soc-honey-backup-sql-read": {
        "name": "Honeytoken: backup.sql momeala citit pe host (auditd)",
        "description": "Kernelul (auditd, cheia soc_honey_sql) a vazut backup.sql deschis pentru citire. "
                       "Include servirea prin HTTP (apache2) si orice citire locala dintr-un shell.",
        "type": "query",
        "language": "kuery",
        "index": ["logs-auditd_manager.auditd-*"],
        "query": f'tags : "{SQL_KEY}" and not process.executable : /opt/Elastic/*',
        "threat_technique": ("T1552.001", "Credentials In Files"),
    },
    "soc-honey-robots-trap": {
        "name": "Honeytoken: cerere catre o cale-capcana din robots.txt",
        "description": "Cerere catre o cale care apare doar ca Disallow in robots.txt. Crawlerele "
                       "legitime o ocolesc; cine o cere citeste robots.txt ca harta de atac.",
        "type": "query",
        "language": "kuery",
        "index": ["logs-apache.access-*"],
        "query": " or ".join(f"url.path : {t}*" for t in ROBOTS_TRAPS),
        "threat_technique": ("T1595", "Active Scanning"),
    },
}

PARENT_NAME = {"T1552": "Unsecured Credentials", "T1505": "Server Software Component",
               # folosite si de behavioral_rules (pasul 3.A), acelasi builder
               "T1059": "Command and Scripting Interpreter", "T1003": "OS Credential Dumping",
               "T1021": "Remote Services"}
TACTIC = {"T1552.001": ("TA0006", "Credential Access"), "T1083": ("TA0007", "Discovery"),
          "T1078": ("TA0001", "Initial Access"), "T1505.003": ("TA0003", "Persistence"),
          "T1190": ("TA0001", "Initial Access"), "T1595": ("TA0043", "Reconnaissance"),
          "T1110": ("TA0006", "Credential Access"),
          # tehnici comportamentale (behavioral_rules.py, pasul 3.A)
          "T1059.004": ("TA0002", "Execution"), "T1059": ("TA0002", "Execution"),
          "T1071": ("TA0011", "Command and Control"), "T1105": ("TA0011", "Command and Control"),
          "T1003.008": ("TA0006", "Credential Access"),
          # AIDE (sensor_rules, pasul 3.E)
          "T1554": ("TA0003", "Persistence"),
          # gate-ul soc-reader (sensor_rules, pasul 1b)
          "T1021.004": ("TA0008", "Lateral Movement")}


def rule_id_of(alert: dict) -> str | None:
    """rule_id-ul regulii care a produs alerta (camp plat sau imbricat), sau None."""
    rid = alert.get("kibana.alert.rule.rule_id")
    if rid is None:
        rid = (((alert.get("kibana") or {}).get("alert") or {}).get("rule") or {}).get("rule_id")
    return rid if isinstance(rid, str) else None


def is_honeytoken(alert: dict) -> bool:
    """Doar dupa rule_id; alerta vine din Elasticsearch, deci campul poate lipsi."""
    return rule_id_of(alert) in RULES


def _ip_set(var: str, default: str) -> frozenset:
    out = set()
    for x in os.environ.get(var, default).split(","):
        try:
            out.add(ipaddress.ip_address(x.strip()))
        except ValueError:
            continue
    return frozenset(out)


def known_own_ips() -> frozenset:
    """IP-urile proprii (web-prod insusi) si ale generatorului benign (G3). Citite la
    fiecare apel, ca o schimbare in soc.env sa nu ceara alt cod."""
    return (_ip_set("WP_SELF_IPS", "192.168.10.138,172.30.6.249,127.0.0.1,::1")
            | _ip_set("BENIGN_GEN_IPS", "192.168.10.150"))


def source_ip_of(alert: dict):
    """source.ip al alertei (plat sau imbricat), ca ipaddress, sau None."""
    ip = alert.get("source.ip")
    if ip is None:
        ip = (alert.get("source") or {}).get("ip")
    if not isinstance(ip, str):
        return None
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def is_config_error(alert: dict) -> bool:
    """Momeala atinsa de pe IP-ul propriu sau al generatorului benign: nu e atac, e o
    configurare gresita (un test, un crawler propriu, o lista alba lipsa). Escaladeaza tot
    la om, dar cu alt motiv, ca sa nu pagineze ca intruziune si sa nu polueze verdictele."""
    if not is_honeytoken(alert):
        return False
    ip = source_ip_of(alert)
    return ip is not None and ip in known_own_ips()


def escalation_reason(alert: dict):
    """Motivul de escaladare (schemas.EscalationReason) decis de cod pentru o alerta de
    momeala, sau None. schemas se importa lenes: modulul ramane fara dependente (pydantic)."""
    from schemas import EscalationReason
    if not is_honeytoken(alert):
        return None
    if is_config_error(alert):
        return EscalationReason.HONEYTOKEN_CONFIG_ERROR
    return EscalationReason.HONEYTOKEN


def kibana_payload(rule_id: str, rules: dict | None = None, severity: str = SEVERITY,
                   risk: int = RISK, tag: str = TAG) -> dict:
    """Corpul pentru POST /api/detection_engine/rules (spatiul default, al omului).
    Folosit si de sensor_rules (aceeasi forma, alta severitate si eticheta)."""
    r = (rules or RULES)[rule_id]
    tech, tech_name = r["threat_technique"]
    tac, tac_name = TACTIC[tech]
    base = tech.split(".")[0]
    technique = {"id": base, "name": tech_name, "reference": f"https://attack.mitre.org/techniques/{base}/"}
    if "." in tech:
        technique = {"id": base, "name": PARENT_NAME[base], "reference": technique["reference"],
                     "subtechnique": [{"id": tech, "name": tech_name,
                                       "reference": f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"}]}
    payload = {
        "rule_id": rule_id, "name": r["name"], "description": r["description"],
        "type": r["type"], "language": r["language"], "index": r["index"], "query": r["query"],
        "severity": severity, "risk_score": risk, "tags": [tag],
        "interval": r.get("interval", "1m"), "from": r.get("from", "now-2m"),
        "max_signals": 100, "enabled": True,
        "threat": [{"framework": "MITRE ATT&CK",
                    "tactic": {"id": tac, "name": tac_name,
                               "reference": f"https://attack.mitre.org/tactics/{tac}/"},
                    "technique": [technique]}],
    }
    # Regulile de tip threshold (brute-force, enumerare) numara evenimente pe un camp
    # (de obicei source.ip): corpul lor cere cheia "threshold". O lasam pass-through din
    # definitie; regulile query (honeytoken, YARA, suricata) nu o au, deci nu sunt atinse.
    if r.get("type") == "threshold":
        payload["threshold"] = r["threshold"]
    return payload

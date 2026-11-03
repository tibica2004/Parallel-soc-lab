"""
REGULI COMPORTAMENTALE (pasul 3.A): detectie de exploatare FARA semnatura. Prind
LANTUL de actiuni al unui atac (serverul web naste un shell, un fisier PHP apare in
webroot, www-data executa ceva nevazut, web-prod deschide o conexiune noua), nu
continutul payload-ului. Un 0-day care evadeaza YARA/Suricata tot trebuie, la un
moment dat, sa execute o comanda sau sa scrie un fisier — aici il prindem.

Acopera DOAR golurile web-centrice pe care Defend native + hunt.py NU le prind in
timp real. Restul tehnicilor (cron, ssh_key, identity, tmp_exec, setuid, shell_network,
shadow_read generic, credential_grep) raman vanatori Tier-2 in hunt.py — nu le dublam.

Ca honeytokens/sensor: reguli obisnuite in Kibana (spatiul default), importate de om cu
deploy/kibana/honeytoken_rules.py; recunoastere dupa rule_id (multime INCHISA), nu dupa
nume. Tag `soc-behavioral` + `shadow-review` (7 zile calibrare inainte de promovare).

Listele albe (regulile c, d) NU sunt scrise de mana: se genereaza din baseline-ul real
de 7 zile cu build_whitelists.py -> data/behavioral-whitelists.json. Pana atunci, un set
minim sigur, ca regula c sa nu alerteze pe apache2/php-fpm insusi.

A3: Elastic Defend (eBPF) NU emite evenimente de citire -> regula f (citire /etc/shadow)
e pe logs-auditd_manager.*, alimentata de o regula auditd (-k soc_shadow_read). Celelalte
sunt pe logs-endpoint.events.* (process/file/network).
"""

from __future__ import annotations

import json
from pathlib import Path

import honeytokens

TAG = "soc-behavioral"
SHADOW_TAG = "shadow-review"          # calibrare 7 zile inainte de promovare (pasul 3.5)
SHADOW_READ_KEY = "soc_shadow_read"   # cheia regulii auditd pentru regula f

PROC_IDX = ["logs-endpoint.events.process-*"]
FILE_IDX = ["logs-endpoint.events.file-*"]
NET_IDX = ["logs-endpoint.events.network-*"]
AUDITD_IDX = ["logs-auditd_manager.auditd-*"]

# Procese-shell/transfer pe care serverul web nu are de ce sa le nasca in operare normala.
WEB_PARENTS = ("apache2", "php-fpm8.3", "php-fpm", "php", "php8.3")
SHELL_CHILDREN = ("sh", "bash", "dash", "zsh", "python3", "python", "perl", "ruby",
                  "curl", "wget", "nc", "ncat", "socat", "base64", "busybox")
PHP_EXT = ("php", "phtml", "phar", "php5", "php7", "php8", "phps", "inc")

# Lista alba minima sigura pentru regula c, folosita doar daca nu exista baseline generat.
# build_whitelists.py o inlocuieste cu executabilele reale vazute la www-data in 7 zile.
DEFAULT_WWWDATA_EXEC = (
    "/usr/sbin/apache2", "/usr/sbin/php-fpm8.3", "/usr/bin/php8.3", "/usr/bin/php",
    "/usr/local/bin/wp", "/bin/sh", "/usr/bin/dash",
)

WHITELIST_FILE = Path(__file__).resolve().parent / "data" / "behavioral-whitelists.json"

# WordPress/PHP trimite mail prin `sh -c -- /usr/sbin/sendmail -t -i`: shell legitim, nu webshell.
# Il excludem DOAR cand e strict apelul MTA, fara metacaractere de inlantuire (; | & backtick $(),
# prin care un atacator ar lipi comenzi dupa sendmail — atunci regula declanseaza din nou. Gasit la
# auto-atacul de masurare (nuclei a lovit formularele WP -> WordPress a trimis mail). Sirurile sunt
# statice (nu vin din telemetrie), deci like~ cu literal e permis (principiul 3).
SENDMAIL_EXCEPTION = (
    '\n  and not (\n'
    '    process.name in ("sh", "dash", "bash") and\n'
    '    process.command_line like~ "*/usr/sbin/sendmail *" and\n'
    '    not process.command_line like~ ("*;*", "*|*", "*&*", "*`*", "*$*")\n'
    '  )'
)

# Severitate per regula: a/b/f sunt de incredere mare (web->shell, PHP in webroot, citire
# shadow); c/d/e sunt mai predispuse la fals pozitiv pana la calibrare -> high, nu critical.
SEVERITY = {
    "soc-web-spawns-shell": ("critical", 90),
    "soc-php-written-in-webroot": ("critical", 90),
    "soc-apache-reads-shadow": ("critical", 90),
    "soc-wwwdata-unexpected-exec": ("high", 75),
    "soc-webprod-new-outbound": ("high", 75),
    "soc-wwwdata-writes-outside-webroot": ("high", 75),
}


def _load_whitelists() -> dict:
    """Listele albe generate din baseline (build_whitelists.py). Lipsa -> implicite sigure.
    Valorile sunt DATE (nume de executabile, IP-uri), nu se interpoleaza in query_string:
    intra ca liste EQL de siruri citate, exact ca in honeytokens."""
    try:
        d = json.loads(WHITELIST_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        d = {}
    execs = d.get("wwwdata_exec") or list(DEFAULT_WWWDATA_EXEC)
    egress = d.get("egress_ip") or []
    # pastram doar siruri simple (fara ghilimele/paranteze), ca sa nu putem construi EQL rau
    execs = [e for e in execs if isinstance(e, str) and '"' not in e and e.startswith("/")]
    egress = [ip for ip in egress if isinstance(ip, str) and all(c in "0123456789.:" for c in ip)]
    return {"wwwdata_exec": execs or list(DEFAULT_WWWDATA_EXEC), "egress_ip": egress}


def _eql_list(values) -> str:
    """Lista EQL de siruri: ("a", "b"). Valorile sunt deja filtrate in _load_whitelists."""
    return "(" + ", ".join(f'"{v}"' for v in values) + ")"


def build_rules() -> dict[str, dict]:
    """Definitiile regulilor, cu listele albe injectate din baseline. Functie (nu constanta)
    ca sa reflecte fisierul de whitelist la fiecare import."""
    wl = _load_whitelists()
    rules: dict[str, dict] = {
        "soc-web-spawns-shell": {
            "name": "Comportament: serverul web a nascut un shell",
            "description": "apache2/php-fpm a pornit un shell sau un instrument de retea "
                           "(sh, bash, python, curl, nc...). In operare normala serverul web nu "
                           "face asta: tipic RCE/webshell, indiferent de continutul payload-ului.",
            "type": "eql", "language": "eql", "index": PROC_IDX,
            "query": (
                'process where host.os.type == "linux" and event.type == "start" and\n'
                f'  process.parent.name in {_eql_list(WEB_PARENTS)} and\n'
                f'  process.name in {_eql_list(SHELL_CHILDREN)}'
                + SENDMAIL_EXCEPTION
            ),
            "threat_technique": ("T1059.004", "Unix Shell"),
        },
        "soc-php-written-in-webroot": {
            "name": "Comportament: fisier PHP scris in webroot",
            "description": "Un fisier .php/.phar/.inc a aparut sau s-a schimbat in /var/www de "
                           "catre un proces care nu e php/wp/rsync/apt/dpkg. Tipic plantare de "
                           "webshell. (mu-plugin-ul SOC declanseaza asta la creare - benign o data.)",
            "type": "eql", "language": "eql", "index": FILE_IDX,
            "query": (
                'file where host.os.type == "linux" and\n'
                '  event.type in ("creation", "change", "rename") and\n'
                '  file.path like~ "/var/www/*" and\n'
                f'  file.extension in {_eql_list(PHP_EXT)} and\n'
                '  not process.name in ("php", "wp", "rsync", "apt", "dpkg") and\n'
                '  not process.executable like~ "/usr/bin/php*"'
            ),
            "threat_technique": ("T1505.003", "Web Shell"),
        },
        "soc-wwwdata-unexpected-exec": {
            "name": "Comportament: www-data a executat un binar nevazut",
            "description": "Contul de serviciu web a pornit un executabil absent din baseline-ul "
                           "de 7 zile. Lista alba se recalibreaza din baseline (build_whitelists.py).",
            "type": "eql", "language": "eql", "index": PROC_IDX,
            "query": (
                'process where host.os.type == "linux" and event.type == "start" and\n'
                '  user.name == "www-data" and\n'
                f'  not process.executable in {_eql_list(wl["wwwdata_exec"])}'
            ),
            "threat_technique": ("T1059", "Command and Scripting Interpreter"),
        },
        "soc-webprod-new-outbound": {
            "name": "Comportament: web-prod a deschis o conexiune outbound noua",
            "description": "web-prod a incercat o conexiune de iesire catre o destinatie din afara "
                           "retelei interne (altele decat DNS/NTP). Tipic beacon C2 sau exfiltrare "
                           "dupa compromitere. Lista alba de destinatii din baseline.",
            "type": "eql", "language": "eql", "index": NET_IDX,
            "query": (
                'network where host.name == "web-prod" and\n'
                '  event.type == "connection_attempted" and network.direction == "egress" and\n'
                '  not cidrmatch(destination.ip, "192.168.10.0/24") and\n'
                '  not destination.port in (53, 123)'
                + (f' and\n  not destination.ip in {_eql_list(wl["egress_ip"])}'
                   if wl["egress_ip"] else "")
            ),
            "threat_technique": ("T1071", "Application Layer Protocol"),
        },
        "soc-wwwdata-writes-outside-webroot": {
            "name": "Comportament: www-data a scris in afara webroot",
            "description": "Contul de serviciu web a creat/modificat un fisier in afara /var/www "
                           "(si nu in /tmp sau sesiunile PHP). Tipic drop de instrument sau "
                           "persistenta dupa compromitere.",
            "type": "eql", "language": "eql", "index": FILE_IDX,
            "query": (
                'file where host.os.type == "linux" and\n'
                '  event.type in ("creation", "change") and user.name == "www-data" and\n'
                '  not file.path like~ "/var/www/*" and\n'
                '  not file.path like~ "/tmp/*" and\n'
                '  not file.path like~ "/var/lib/php/sessions/*"'
            ),
            "threat_technique": ("T1105", "Ingress Tool Transfer"),
        },
        "soc-apache-reads-shadow": {
            "name": "Comportament: www-data a citit /etc/shadow (auditd)",
            "description": "Kernelul (auditd, cheia soc_shadow_read) a vazut contul de serviciu web "
                           "deschizand /etc/shadow pentru citire. Defend nu vede citirile (A3). "
                           "Nicio operare web normala nu citeste shadow: furt de credentiale.",
            "type": "query", "language": "kuery", "index": AUDITD_IDX,
            # cheia auditd devine tag; excludem agentul Elastic ca la honeytoken-read
            "query": f'tags : "{SHADOW_READ_KEY}" and not process.executable : /opt/Elastic/*',
            "threat_technique": ("T1003.008", "/etc/passwd and /etc/shadow"),
        },
    }
    return rules


RULES = build_rules()


def is_behavioral(alert: dict) -> bool:
    """Doar dupa rule_id, multime inchisa (ca honeytokens/sensor)."""
    return honeytokens.rule_id_of(alert) in RULES


def kibana_payload(rule_id: str, rules: dict | None = None) -> dict:
    """Corpul pentru POST /api/detection_engine/rules. Reutilizeaza builder-ul comun din
    honeytokens, cu severitatea per regula, apoi adauga tag-ul shadow-review (calibrare 7z)."""
    sev, risk = SEVERITY[rule_id]
    payload = honeytokens.kibana_payload(rule_id, rules=rules or RULES, severity=sev,
                                         risk=risk, tag=TAG)
    payload["tags"] = [TAG, SHADOW_TAG]
    return payload

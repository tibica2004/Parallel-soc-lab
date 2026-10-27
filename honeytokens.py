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

Elastic Defend pe Linux nu logheaza citirile de fisiere: un `cat .env.bak` se
vede (calea e in argumente), un `grep -r pass /var/www` sau un file_get_contents()
dintr-un webshell nu. Le vede auditd (deploy/web-prod/auditd-fim.md), cu conditia
ca procesul sa fi pornit dupa activarea auditului: de aici audit=1 la boot.
"""

from __future__ import annotations

DECOY_FILE = "/var/www/html/.env.bak"
DECOY_URLS = ("/.env.bak", "/admin.old.php")
DECOY_USER = "svc_deploy"
AUDIT_KEY = "soc_honeytoken"     # cheia regulii auditd: -w DECOY_FILE -p r -k soc_honeytoken

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
}

PARENT_NAME = {"T1552": "Unsecured Credentials", "T1505": "Server Software Component"}
TACTIC = {"T1552.001": ("TA0006", "Credential Access"), "T1083": ("TA0007", "Discovery"),
          "T1078": ("TA0001", "Initial Access"), "T1505.003": ("TA0003", "Persistence"),
          "T1190": ("TA0001", "Initial Access"), "T1595": ("TA0043", "Reconnaissance"),
          "T1110": ("TA0006", "Credential Access")}


def rule_id_of(alert: dict) -> str | None:
    """rule_id-ul regulii care a produs alerta (camp plat sau imbricat), sau None."""
    rid = alert.get("kibana.alert.rule.rule_id")
    if rid is None:
        rid = (((alert.get("kibana") or {}).get("alert") or {}).get("rule") or {}).get("rule_id")
    return rid if isinstance(rid, str) else None


def is_honeytoken(alert: dict) -> bool:
    """Doar dupa rule_id; alerta vine din Elasticsearch, deci campul poate lipsi."""
    return rule_id_of(alert) in RULES


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

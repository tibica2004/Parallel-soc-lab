"""
TIER 3 — VANATOARE PE IPOTEZE ATT&CK (faza 11c).

Tier 1 si Tier 2 reactioneaza la alerte si la raritate. Vanatoarea cauta ce n-a
declansat nimic, tehnica cu tehnica, si tine minte si ce N-A gasit: "am cautat
T1053.003 pe 24 h si n-am gasit nimic" e acoperire; "n-am cautat" e noroc.

Impartirea muncii (principiul 1):
  - CODUL alege tehnicile (cele vanate cel mai demult, nevanatele primele),
    ruleaza DOAR sabloanele ES|QL de mai jos (scrise de om), decide gasit/negasit
    si trimite cazurile la Tier 2 cu buget.
  - MODELUL (H1) scrie ipoteza (doar in audit) si alege, dintr-o lista inchisa,
    sablonul tehnicii si fereastra. HuntPlan (extra=forbid) valideaza; orice
    abatere sau cadere -> planul implicit, vanatoarea ruleaza oricum.

Sabloanele: text fix, fara valori din telemetrie; singurul lucru variabil e
fereastra (intreg din WINDOWS). Toate intorc aceeasi forma (vezi COLS), ca un
rezultat sa devina uniform un Case origin=tier3_hunt.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

WINDOWS = (24, 72, 168)
DEFAULT_WINDOW = 24
PER_RUN = 2                 # tehnici pe rulare (timer orar; aprobat 2026-10-16)
TIER2_BUDGET = 3            # cazuri trimise la Tier 2 pe rulare
MAX_CASES_PER_HUNT = 5      # grupuri distincte retinute dintr-un sablon
# Forma comuna a rezultatelor; coloanele lipsa dintr-o sursa (ex. parent la auditd) -> None.
COLS = ("host", "what", "proc", "parent", "entity", "who", "cnt", "t_first", "t_last")

AUDIT_IDX = "logs-auditd_manager.auditd-*"
PROC_IDX = "logs-endpoint.events.process-*"
NET_IDX = "logs-endpoint.events.network-*"
FILE_IDX = "logs-endpoint.events.file-*"
SURICATA_IDX = "logs-suricata.eve-*"

# Calea completa din auditd: file.path e uneori relativ la directorul de lucru.
_AUDIT_PATH = """
| EVAL path = CASE(STARTS_WITH(file.path, "/"), file.path,
                   CONCAT(COALESCE(process.working_directory, ""), "/", COALESCE(file.path, "")))"""

# auditd n-are process.parent.name / process.entity_id: doar executabilul si utilizatorul.
_AUDIT_TAIL = """
| WHERE process.executable IS NOT NULL AND NOT STARTS_WITH(process.executable, "/opt/Elastic/")
| STATS cnt = COUNT(*), t_first = MIN(@timestamp), t_last = MAX(@timestamp), who = MAX(user.name)
        BY host = host.name, what = path, proc = process.executable
| LIMIT 200"""


def _audit(key: str, path_cond: str) -> str:
    return (f"FROM {AUDIT_IDX}\n| WHERE {{w}}\n| MV_EXPAND tags\n| WHERE tags == \"{key}\""
            + _AUDIT_PATH + f"\n| WHERE {path_cond}" + _AUDIT_TAIL)


_PROC_TAIL = """
| STATS cnt = COUNT(*), t_first = MIN(@timestamp), t_last = MAX(@timestamp),
        parent = MAX(process.parent.name), entity = MAX(process.entity_id), who = MAX(user.name)
        BY host = host.name, what = process.command_line, proc = process.executable
| LIMIT 200"""


# chmod cu setuid/setgid: mod simbolic cu "s" (u+s, g+xs, a=rwxs, +s) sau octal cu
# primul din patru cifre 2-7 (4755, 2755; 1777 = doar sticky). Regex Lucene: ancorat
# implicit pe tot sirul si FARA prescurtari ca \s (gasit cu Atomic Red Team T1548.001:
# varianta veche rata "chmod u+xs" si, din cauza lui \s, orice mod octal).
SETUID_RX = ".* (([ugoa]*[+=][rwxXst]*s[rwxXst]*)|([2-7][0-7][0-7][0-7]))(( |,).*)?"


@dataclass(frozen=True)
class Template:
    id: str
    technique: str
    name: str
    hypothesis: str          # ipoteza implicita (cand modelul nu raspunde)
    query: str               # ES|QL cu {w} = conditia de fereastra
    proc_is_process: bool = True   # coloana proc e un proces (nu, la Suricata: categoria regulii)


TEMPLATES: dict[str, Template] = {t.id: t for t in [
    Template("cron_write", "T1053.003", "Scriere in cron (auditd)",
             "Un atacator care vrea persistenta adauga o intrare cron: s-ar vedea o scriere in "
             "/etc/cron* sau /var/spool/cron de catre un proces.",
             _audit("soc_persistence",
                    'STARTS_WITH(path, "/etc/cron") OR STARTS_WITH(path, "/var/spool/cron")')),
    Template("systemd_unit_write", "T1543.002", "Unitate systemd scrisa (auditd)",
             "Persistenta prin serviciu systemd: o unitate noua sau modificata in /etc/systemd/system.",
             _audit("soc_persistence", 'STARTS_WITH(path, "/etc/systemd/system")')),
    Template("ssh_key_write", "T1098.004", "Chei SSH modificate (auditd)",
             "Persistenta prin authorized_keys: scriere intr-un director .ssh al unui utilizator.",
             _audit("soc_persistence", 'path LIKE "*/.ssh/*"')),
    Template("identity_write", "T1136.001", "Conturi sau sudoers modificate (auditd)",
             "Un cont nou sau drepturi sudo noi: scriere in /etc/passwd, /etc/shadow sau sudoers.",
             _audit("soc_identity", 'STARTS_WITH(path, "/etc/passwd") OR STARTS_WITH(path, "/etc/shadow") '
                                    'OR STARTS_WITH(path, "/etc/sudoers")')),
    Template("kernel_module_load", "T1547.006", "Modul de kernel incarcat (auditd)",
             "Un rootkit se incarca drept modul de kernel: init_module/finit_module in afara boot-ului.",
             f"FROM {AUDIT_IDX}\n| WHERE {{w}}\n| MV_EXPAND tags\n| WHERE tags == \"soc_kmod\""
             "\n| WHERE event.action == \"loaded-kernel-module\""
             "\n| EVAL path = COALESCE(process.title, process.executable)" + _AUDIT_TAIL),
    Template("tmp_exec", "T1204.002", "Executie din director temporar (Defend)",
             "Un payload descarcat e rulat din /tmp, /var/tmp sau /dev/shm.",
             f"FROM {PROC_IDX}\n| WHERE {{w}}"
             '\n| WHERE STARTS_WITH(process.executable, "/tmp/") OR STARTS_WITH(process.executable, "/var/tmp/")'
             ' OR STARTS_WITH(process.executable, "/dev/shm/")' + _PROC_TAIL),
    Template("shell_network", "T1059.004", "Shell sau interpretor cu conexiune iesita (Defend)",
             "Un reverse shell: un shell sau interpretor deschide el insusi o conexiune in afara.",
             f"FROM {NET_IDX}\n| WHERE {{w}} AND network.direction == \"egress\""
             '\n| WHERE process.name IN ("bash", "sh", "dash", "zsh", "nc", "ncat", "netcat", "socat", "perl", "php")'
             ' OR STARTS_WITH(process.name, "python")'
             "\n| EVAL dst = CONCAT(TO_STRING(destination.ip), \":\", TO_STRING(destination.port))"
             "\n| STATS cnt = COUNT(*), t_first = MIN(@timestamp), t_last = MAX(@timestamp),"
             "\n        entity = MAX(process.entity_id), who = MAX(user.name)"
             "\n        BY host = host.name, what = dst, proc = process.name\n| LIMIT 200"),
    Template("history_tamper", "T1070.003", "Stergerea istoricului de comenzi (Defend)",
             "Un atacator isi sterge urmele: history -c, HISTFILE golit, .bash_history sters.",
             f"FROM {PROC_IDX}\n| WHERE {{w}}"
             '\n| EVAL cl = TO_LOWER(process.command_line)'
             '\n| WHERE cl LIKE "*history -c*" OR cl LIKE "*unset histfile*" OR cl LIKE "*histfile=/dev/null*"'
             ' OR (cl LIKE "*bash_history*" AND (cl LIKE "*rm *" OR cl LIKE "*shred*" OR cl LIKE "*truncate*"))'
             + _PROC_TAIL),
    Template("log_wipe", "T1070.002", "Loguri de sistem sterse sau golite (Defend)",
             "Stergerea logurilor: rm/shred/truncate pe /var/log, sau journalctl --vacuum.",
             f"FROM {PROC_IDX}\n| WHERE {{w}}"
             '\n| EVAL cl = TO_LOWER(process.command_line)'
             '\n| WHERE ((process.name IN ("rm", "shred", "truncate") AND cl LIKE "*/var/log/*")'
             ' OR cl LIKE "*journalctl*--vacuum*" OR cl LIKE "*journalctl*--rotate*")' + _PROC_TAIL),
    Template("setuid_chmod", "T1548.001", "Bit setuid/setgid pus cu chmod (Defend)",
             "Escaladare prin setuid: chmod u+s / g+s / 4xxx pe un binar.",
             f"FROM {PROC_IDX}\n| WHERE {{w}} AND process.name == \"chmod\""
             f'\n| WHERE process.command_line RLIKE "{SETUID_RX}"' + _PROC_TAIL),
    Template("shadow_read", "T1003.008", "/etc/shadow citit de o unealta obisnuita (Defend)",
             "Furtul de hash-uri: cat/cp/grep pe /etc/shadow, nu prin passwd/useradd.",
             f"FROM {PROC_IDX}\n| WHERE {{w}}"
             '\n| WHERE process.command_line LIKE "*/etc/shadow*"'
             '\n| WHERE NOT process.name IN ("passwd", "chpasswd", "useradd", "usermod", "userdel", "unix_chkpwd",'
             ' "pwck", "grpck", "vipw")' + _PROC_TAIL),
    Template("credential_grep", "T1552.001", "Cautare de parole in fisiere (Defend)",
             "Dupa intrare, atacatorul cauta credentiale: grep/find dupa password, secret, cheie privata.",
             f"FROM {PROC_IDX}\n| WHERE {{w}} AND process.name IN (\"grep\", \"egrep\", \"rgrep\", \"find\", \"rg\")"
             '\n| EVAL cl = TO_LOWER(process.command_line)'
             '\n| WHERE cl LIKE "*passw*" OR cl LIKE "*secret*" OR cl LIKE "*api_key*" OR cl LIKE "*private key*"'
             ' OR cl LIKE "*id_rsa*"' + _PROC_TAIL),
    # T1505.003 (webshell / RCE web): CONSECINTA unei exploatari web, deci si a unui N-day sau
    # 0-day in Apache/PHP/WordPress. Aceleasi tipare ca regulile comportamentale de la pasul 3,
    # aici retrospectiv (pana la 168 h), pentru cazurile scapate in timp real.
    Template("web_child_process", "T1505.003", "Proces pornit de serverul web (Defend)",
             "Un webshell sau un RCE in aplicatia web: apache2/php porneste un proces (shell, "
             "interpretor, unealta de retea). Pe web-prod (mod_php) asta nu se intampla legitim.",
             # event.action e multi-valoare in Defend (fork, exec, end): comparatia directa in
             # ES|QL intoarce null si pierde randul (masurat: 0 randuri vs 7 cu MV_EXPAND).
             f"FROM {PROC_IDX}\n| WHERE {{w}}\n| MV_EXPAND event.action\n| WHERE event.action == \"exec\""
             '\n| WHERE process.parent.name IN ("apache2", "php", "php8.3", "php-fpm", "php-fpm8.3")'
             + _PROC_TAIL),
    Template("webroot_php_write", "T1505.003", "Fisier PHP scris in webroot (Defend)",
             "Persistenta prin webshell: un fisier PHP nou sau modificat sub /var/www, in afara "
             "unui update aprobat.",
             f"FROM {FILE_IDX}\n| WHERE {{w}} AND STARTS_WITH(file.path, \"/var/www/\")"
             '\n| WHERE file.extension IN ("php", "phtml", "phar", "php5", "php7", "php8", "inc")'
             ' AND event.action IN ("creation", "modification", "rename")'
             "\n| STATS cnt = COUNT(*), t_first = MIN(@timestamp), t_last = MAX(@timestamp),"
             "\n        entity = MAX(process.entity_id), who = MAX(user.name)"
             "\n        BY host = host.name, what = file.path, proc = process.executable\n| LIMIT 200"),
    Template("ids_high", "T1071", "Alerte Suricata grave nepromovate (Suricata)",
             "Trafic C2 sau exploatare vazut de IDS: alerte de severitate 1-2 pe care nimic nu le-a urmarit.",
             f"FROM {SURICATA_IDX}\n| WHERE {{w}} AND event.kind == \"alert\" AND event.severity <= 2"
             "\n| STATS cnt = COUNT(*), t_first = MIN(@timestamp), t_last = MAX(@timestamp),"
             "\n        who = MAX(TO_STRING(source.ip))"
             "\n        BY host = observer.hostname, what = rule.name, proc = rule.category\n| LIMIT 200",
             proc_is_process=False),
]}

TECHNIQUES: dict[str, list[str]] = {}
for _t in TEMPLATES.values():
    TECHNIQUES.setdefault(_t.technique, []).append(_t.id)


def render(t: Template, window_hours: int) -> str:
    """Singurul punct in care textul sablonului se completeaza: un intreg dintr-o lista inchisa."""
    if window_hours not in WINDOWS:
        raise ValueError(f"fereastra {window_hours} nu e in {WINDOWS}")
    return t.query.replace("{w}", f"@timestamp >= NOW() - {int(window_hours)} hours")


def query_hash(q: str) -> str:
    return hashlib.sha256(q.encode()).hexdigest()[:16]


# ------------------------------------------------------------------------------
# Planul (H1): modelul propune, codul valideaza
# ------------------------------------------------------------------------------

class HuntPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique: str
    template_id: str
    window_hours: int
    hypothesis: str = Field(max_length=600)    # text liber: doar in audit

    @field_validator("window_hours")
    @classmethod
    def _w(cls, v: int) -> int:
        if v not in WINDOWS:
            raise ValueError(f"fereastra trebuie sa fie una din {WINDOWS}")
        return v

    @field_validator("template_id")
    @classmethod
    def _t(cls, v: str, info) -> str:
        tech = info.data.get("technique")
        if v not in TECHNIQUES.get(tech, []):
            raise ValueError(f"sablonul {v!r} nu apartine tehnicii {tech}")
        return v


def default_plan(technique: str) -> HuntPlan:
    tid = TECHNIQUES[technique][0]
    return HuntPlan(technique=technique, template_id=tid, window_hours=DEFAULT_WINDOW,
                    hypothesis=TEMPLATES[tid].hypothesis)


PLAN_PROMPT = """Esti vanator de amenintari (threat hunter) pe un server web Linux (Apache + PHP).
Primesti o tehnica ATT&CK si sabloanele de interogare APROBATE pentru ea. Nu scrii
interogari. Formulezi ipoteza (ce ar lasa tehnica in telemetrie pe acest server) si
alegi sablonul si fereastra.

Raspunde DOAR cu JSON, fara alt text:
{"technique": "<exact tehnica primita>", "template_id": "<unul din id-urile primite>",
 "window_hours": <una din 24, 72, 168>, "hypothesis": "<ipoteza, 1-3 propozitii, in romana>"}

Fereastra: 24 daca tehnica a fost vanata recent fara rezultat; 72 sau 168 daca n-a
mai fost vanata sau a trecut mult de la ultima vanatoare."""


def plan_message(technique: str, last: dict | None) -> str:
    opts = [{"template_id": tid, "name": TEMPLATES[tid].name, "what_it_looks_for": TEMPLATES[tid].hypothesis}
            for tid in TECHNIQUES[technique]]
    return json.dumps({"technique": technique, "templates": opts, "windows": list(WINDOWS),
                       "last_hunt": last}, ensure_ascii=False)


def parse_plan(raw: dict, technique: str) -> HuntPlan:
    """Planul modelului, validat; tehnica impusa de cod (modelul nu o poate schimba)."""
    if not isinstance(raw, dict):
        raise ValueError("planul nu e un obiect JSON")
    return HuntPlan.model_validate({**raw, "technique": technique})


# ------------------------------------------------------------------------------
# Alegerea tehnicilor (cod): cele vanate cel mai demult, nevanatele primele
# ------------------------------------------------------------------------------

def pick_techniques(state: dict, n: int = PER_RUN, priority: tuple[str, ...] = (),
                    now: datetime | None = None) -> list[str]:
    """state: {technique: {"last": iso, ...}}. Ordine stabila la egalitate (ordinea din TEMPLATES).
    priority (pasul 5.4): tehnicile din gap_list (emulate, dar fara alerta) care au sablon si n-au
    fost vanate in ultimele 24 h trec primele."""
    order = list(TECHNIQUES)
    now = now or datetime.now(timezone.utc)

    def stale(t: str) -> bool:
        last = (state.get(t) or {}).get("last")
        try:
            return not last or (now - datetime.fromisoformat(last.replace("Z", "+00:00"))).total_seconds() > 86400
        except ValueError:
            return True
    first = [t for t in order if t in set(priority) and stale(t)]
    rest = sorted((t for t in order if t not in first),
                  key=lambda t: ((state.get(t) or {}).get("last") or "", order.index(t)))
    return (first + rest)[:n]


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    tmp.replace(path)


# ------------------------------------------------------------------------------
# Evaluarea (H3, cod): randuri -> grupuri -> cazuri
# ------------------------------------------------------------------------------

MERGE_MINUTES = 15


def _ts(x: str | None) -> float:
    try:
        return datetime.fromisoformat(str(x).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return 0.0


def groups(rows: list[dict]) -> list[dict]:
    """Randurile sablonului, normalizate la COLS, unite in actiuni, ordonate (cele mai
    recente primele), plafonate. Aceeasi actiune lasa mai multe randuri (crontab -e
    scrie un temporar, directorul, fisierul final): acelasi host + proces + utilizator
    la cel mult MERGE_MINUTES distanta devin o singura potrivire. Valorile din
    telemetrie se scurteaza (ajung la model ca DATE)."""
    norm = []
    for r in rows:
        if not r.get("host"):
            continue
        norm.append({k: (str(r.get(k))[:300] if r.get(k) is not None else None) for k in COLS}
                    | {"cnt": int(r.get("cnt") or 0)})
    norm.sort(key=lambda g: _ts(g.get("t_first")))
    merged: list[dict] = []
    for g in norm:
        last = next((m for m in reversed(merged)
                     if (m["host"], m["proc"], m["who"]) == (g["host"], g["proc"], g["who"])), None)
        if last is not None and _ts(g["t_first"]) - _ts(last["t_last"]) <= MERGE_MINUTES * 60:
            if g["what"] and g["what"] not in last["_whats"]:
                last["_whats"].append(g["what"])
            last["cnt"] += g["cnt"]
            if _ts(g["t_last"]) > _ts(last["t_last"]):
                last["t_last"] = g["t_last"]
            continue
        merged.append(dict(g, _whats=[g["what"]] if g["what"] else []))
    for m in merged:
        ws = m.pop("_whats")
        if len(ws) > 1:
            # Fiecare urma isi pastreaza inceputul: o comanda lunga n-o mai ascunde pe urmatoarea.
            per = max(40, 300 // len(ws) - 2)
            m["what"] = "; ".join(w[:per] for w in ws)[:300]
    merged.sort(key=lambda g: _ts(g.get("t_last")), reverse=True)
    return merged[:MAX_CASES_PER_HUNT]


def coverage_record(plan: HuntPlan, status: str, hits: int, cases: int, q: str,
                    started: datetime, finished: datetime, plan_source: str, error: str | None = None) -> dict:
    """Ce se scrie in soc-hunts: si rezultatele negative. Ipoteza e text liber, doar aici."""
    t = TEMPLATES[plan.template_id]
    return {"@timestamp": finished.isoformat(), "technique": plan.technique, "template_id": t.id,
            "template_name": t.name, "window_hours": plan.window_hours, "status": status,
            "hits": hits, "cases": cases, "query_hash": query_hash(q), "plan_source": plan_source,
            "hypothesis": plan.hypothesis[:600], "started_at": started.isoformat(),
            "duration_ms": int((finished - started).total_seconds() * 1000),
            "error": (error or "")[:300] or None}


def now() -> datetime:
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------------------
# Cazuri pentru Tier 2 si registrul potrivirilor deja trimise
# ------------------------------------------------------------------------------

SEEN_DAYS = 14


def match_key(template_id: str, g: dict) -> str:
    """Aceeasi urma gasita din nou (fereastra se suprapune) nu se reinvestigheaza."""
    raw = "|".join(str(g.get(k)) for k in ("host", "what", "proc", "t_first"))
    return f"{template_id}|{hashlib.sha256(raw.encode()).hexdigest()[:20]}"


def prune_seen(seen: dict, at: datetime) -> dict:
    lim = at.timestamp() - SEEN_DAYS * 86400
    return {k: v for k, v in seen.items() if v >= lim}


def make_case(plan: HuntPlan, g: dict, chain_id: str):
    """Grupul -> Case origin=tier3_hunt. ValueError daca faptele nu trec validarea."""
    from schemas import ENTITY_ID_RE, Case, EscalationReason, HuntMatch
    t = TEMPLATES[plan.template_id]
    proc = g.get("proc")
    child = (proc.rsplit("/", 1)[-1] or None) if (proc and t.proc_is_process) else None
    ent = g.get("entity")
    return Case(chain_id=chain_id, origin="tier3_hunt", host=g["host"],
                entity_id=ent if ent and ENTITY_ID_RE.match(ent) else None,
                parent=g.get("parent"), child=child,
                rule_name=f"Vanatoare {t.technique}: {t.name}"[:256],
                escalation_reasons=[EscalationReason.HUNT_MATCH],
                hunt_match=HuntMatch(technique=t.technique, template_id=t.id, what=g.get("what"),
                                     who=(g.get("who") or None) and str(g["who"])[:100],
                                     count=g.get("cnt") or 0, first_seen=g.get("t_first"),
                                     last_seen=g.get("t_last")))

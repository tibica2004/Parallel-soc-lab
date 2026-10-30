"""
SOC-READER (pasul 1b / 6.2): singurul drum prin care codul SOC-ului citeste ceva direct de pe
web-prod. Cheie SSH dedicata (~/.ssh/soc-reader), cont read-only pe web-prod, iar acolo
soc-reader-gate executa DOAR comenzile din ReaderCommand (lista alba exacta, aceeasi ca in
deploy/web-prod/soc-reader/soc-reader-gate; un test verifica identitatea).

Nicio valoare din telemetrie nu intra intr-o comanda: comanda e membrul enumerarii, nimic
altceva (R6/R7). Esecul (timeout, cheie lipsa, DENIED) ridica ReaderError: apelantul il
trateaza ca esec de verificare (R9), nu ca „totul e bine”.

Mediu: SOC_READER_TARGET (implicit soc-reader@192.168.10.138), SOC_READER_KEY (implicit
~/.ssh/soc-reader). Cheia hostului web-prod trebuie sa fie deja in known_hosts
(StrictHostKeyChecking=yes: nu acceptam o cheie noua tacut).
"""
from __future__ import annotations

import os
import re
import subprocess
from enum import Enum
from pathlib import Path

TARGET = os.environ.get("SOC_READER_TARGET", "soc-reader@192.168.10.138")
KEY = os.environ.get("SOC_READER_KEY", str(Path.home() / ".ssh" / "soc-reader"))
TIMEOUT_S = 20


class ReaderCommand(str, Enum):
    """Comenzile permise de gate, textul exact. Adaugarea uneia cere si gate-ul (si deploy)."""
    PROCESSES = "ps -eo pid,ppid,user,etimes,cmd"
    LISTENING = "ss -tlnp"
    CANARY_HASH = "sha256sum /usr/local/bin/soc-canary /etc/cron.d/soc-canary"
    CRON_HASH = "sha256sum /etc/crontab /etc/cron.d/*"
    PASSWD = "cat /etc/passwd"
    LS_WEBROOT = "ls -la /var/www/html"
    LS_PLUGINS = "ls -la /var/www/html/wp-content/plugins"
    STAT_WPCONFIG = "stat /var/www/html/wp-config.php"
    STAT_HTACCESS = "stat /var/www/html/.htaccess"
    STAT_BACKUP_SQL = "stat /var/www/html/backup.sql"
    STAT_ROBOTS = "stat /var/www/html/robots.txt"


class ReaderError(RuntimeError):
    pass


def ssh_argv(cmd: ReaderCommand) -> list[str]:
    """Argumentele ssh, fara shell local. Pur (testabil)."""
    if not isinstance(cmd, ReaderCommand):
        raise TypeError("doar ReaderCommand")
    return ["ssh", "-i", KEY, "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"ConnectTimeout={TIMEOUT_S // 2}",
            "-T", TARGET, cmd.value]


def run(cmd: ReaderCommand) -> str:
    """Ruleaza comanda pe web-prod prin gate si intoarce stdout. Esec -> ReaderError."""
    try:
        r = subprocess.run(ssh_argv(cmd), capture_output=True, text=True, timeout=TIMEOUT_S)
    except subprocess.TimeoutExpired as e:
        raise ReaderError(f"timeout {TIMEOUT_S}s: {cmd.name}") from e
    if r.returncode != 0:
        why = "DENIED de gate" if "DENIED" in r.stderr else f"rc={r.returncode}"
        raise ReaderError(f"{cmd.name}: {why}: {r.stderr.strip()[:200]}")
    return r.stdout


_SHA_LINE = re.compile(r"^([0-9a-f]{64})  (/\S.*)$")


def parse_sha256sum(text: str) -> dict[str, str]:
    """Iesirea sha256sum -> {cale: hash}. Liniile care nu se potrivesc sunt ignorate. Pur."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        m = _SHA_LINE.match(line.strip())
        if m:
            out[m.group(2)] = m.group(1)
    return out

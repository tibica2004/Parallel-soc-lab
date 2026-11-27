"""Constante de domeniu folosite de ambele cai de verdict (faza 24 Arcanna, regula de importuri).

Mutate NESCHIMBATE din tier2/hunt_path.py, ca tier1.fast_path sa nu mai importe din tier2
(incalcarea listata in docs/faza-24-importuri.md). hunt_path si fast_path le importa de aici sub
aceleasi nume; valorile si deci faptele calculate sunt identice.
"""
from __future__ import annotations

import os
from collections.abc import Mapping

from pathlib import Path as _Path

from elasticlab.paths import REPO_ROOT

# Implicit: detections/ din repo (langa acest fisier), nu ~/lab/detections; o clona in alt
# director (sau pe alt host) gaseste ghidurile fara configurare. GUIDES_DIR din mediu ramane.
def guides_dir(env: Mapping[str, str]) -> _Path:
    """Directorul ghidurilor de investigatie. Pur (primeste mediul ca argument)."""
    return _Path(env.get("GUIDES_DIR") or REPO_ROOT / "detections")


GUIDES_DIR = guides_dir(os.environ)


WEB_SVC_USERS = {"www-data", "apache", "nginx", "httpd"}
TEMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")

# Actiuni sensibile prin CE face procesul, nu prin CINE il ruleaza. Un admin cu
# credentiale furate ruleaza exact aceste comenzi — deci identitatea nu are voie
# sa le anuleze. Faptul de admin coboara suspiciunea la comenzi banale, NU la astea.
SENSITIVE_CHILD = {
    "crontab", "at", "nc", "ncat", "socat",
    "useradd", "usermod", "passwd", "visudo", "chattr",
}
SENSITIVE_CMD = (
    "/dev/tcp", "/dev/udp", "-i >&", "bash -i", "crontab -",
    "/etc/cron", "/etc/systemd", "authorized_keys", "/dev/shm",
    "ld.so.preload", "base64 -d", "chmod +s", "setcap",
    "systemctl enable", "systemctl link", "daemon-reload",
    "socket.socket", "pty.spawn", "os.dup2", "fsockopen", "tcpsocket",
)

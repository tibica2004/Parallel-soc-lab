"""
Watchdog systemd (pasul 7, G7) fara dependente: un datagram pe NOTIFY_SOCKET.

Orchestratorul trimite WATCHDOG=1 dupa fiecare alerta procesata, dupa fiecare investigatie
si la sfarsitul fiecarui ciclu. Daca bucla se blocheaza (model agatat fara timeout, ES care
nu raspunde), systemd nu mai primeste semnalul in WatchdogSec si reporneste serviciul
(Restart=on-failure). Ciclurile lungi sunt normale (masurat: pana la 716 s sub harness),
de aceea pingul e per alerta, nu doar per ciclu.

Fara NOTIFY_SOCKET (rulare manuala, harness, teste) totul e no-op.
"""
from __future__ import annotations

import os
import socket


def _send(msg: str) -> bool:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    if addr.startswith("@"):            # socket abstract
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(msg.encode())
        return True
    except OSError:
        return False                     # watchdog-ul nu are voie sa opreasca bucla


def ready() -> bool:
    return _send("READY=1")


def watchdog() -> bool:
    return _send("WATCHDOG=1")

#!/usr/bin/env python3
"""Starea auditului din kernel (echivalentul lui `auditctl -s`), fara pachetul auditd.

Doar citire: trimite AUDIT_GET pe netlink si afiseaza raspunsul. Nu schimba reguli,
nu ia socketul de audit de la auditbeat (instalarea pachetului auditd l-ar lua).
Necesita root:  sudo python3 audit-status.py

enabled: 0 = oprit, 1 = activ, 2 = BLOCAT (imuabil; regulile nu se mai pot schimba
pana la reboot). pid = procesul care primeste evenimentele (auditbeat).
"""
import socket
import struct
import sys

NETLINK_AUDIT = 9
AUDIT_GET = 1000
NLM_F_REQUEST = 1
NLMSG_ERROR = 2

s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)
s.bind((0, 0))
s.send(struct.pack("=IHHII", 16, AUDIT_GET, NLM_F_REQUEST, 1, 0))
data = s.recv(8192)
_len, typ, _flags, _seq, _pid = struct.unpack("=IHHII", data[:16])
if typ == NLMSG_ERROR:
    sys.exit(f"kernelul a refuzat AUDIT_GET (errno {-struct.unpack('=i', data[16:20])[0]}); ruleaza ca root")
mask, enabled, failure, pid, rate_limit, backlog_limit, lost, backlog = struct.unpack("=8I", data[16:48])
state = {0: "oprit", 1: "activ", 2: "BLOCAT (imuabil pana la reboot)"}.get(enabled, "?")
print(f"enabled={enabled} ({state}) failure={failure} pid={pid} "
      f"rate_limit={rate_limit} backlog_limit={backlog_limit} lost={lost} backlog={backlog}")

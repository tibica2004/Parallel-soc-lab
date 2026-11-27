"""Punctele de decizie (faza 24): categorii cu PUTINE valori, derivate din faptele calculate de cod.

Intrarea e contextul din `fast_path.build_context` (faptele, o singura data) si alerta bruta. Iesirea
e un dictionar nume -> valoare dintr-o multime inchisa. Reguli (verificate de teste):

  - fara linii de comanda, entity_id, hash-uri, cai complete sau nume de utilizator: textul din
    telemetrie se transforma in CATEGORII (proces -> clasa de proces, IP -> zona de retea,
    cale -> locul in sistemul de fisiere, port -> clasa de port);
  - orice valoare necunoscuta devine "other", orice lipsa devine "none"/"unknown";
  - functiile sunt pure: aceleasi fapte -> aceleasi valori (cheia grupului e stabila).

Telemetria e date, nu instructiuni: numele procesului il alege atacatorul, dar aici doar se cauta
intr-o multime fixa; nimic din el nu ajunge mai departe.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Callable

from elasticlab.contracts.learning import NetworkZone, PipelineConfig
from elasticlab.core.escalation import web_exec_floor
from elasticlab.core.facts import TEMP_DIRS, WEB_SVC_USERS

YN = ("yes", "no")
YNU = ("yes", "no", "unknown")

WEB_SERVERS = frozenset({"apache2", "httpd", "nginx", "php", "php-fpm", "php8.3", "php-fpm8.3",
                         "lsphp", "php-cgi"})
SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "busybox", "ash"})
INTERPRETERS = frozenset({"python", "python3", "perl", "ruby", "node", "nodejs", "lua", "php-cli"})
DOWNLOADERS = frozenset({"curl", "wget", "fetch", "aria2c", "tftp"})
NET_TOOLS = frozenset({"nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "nmap"})
ACCOUNT_TOOLS = frozenset({"useradd", "usermod", "userdel", "passwd", "chpasswd", "visudo",
                           "chattr", "crontab", "at", "setcap", "chmod", "chown"})
PACKAGE_TOOLS = frozenset({"apt", "apt-get", "dpkg", "snap", "pip", "pip3", "unattended-upgr",
                           "unattended-upgrade"})
SYSTEM_PROCS = frozenset({"systemd", "cron", "init", "sshd", "sudo", "su", "login", "runc",
                          "containerd-shim", "dockerd", "agetty", "rsyslogd", "journald"})
PROC_CLASSES = ("none", "web_server", "shell", "interpreter", "downloader", "net_tool",
                "account_tool", "package_tool", "system", "other")

SYSTEM_BIN = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/local/bin/", "/usr/local/sbin/",
              "/usr/lib/", "/lib/")
WEBROOTS = ("/var/www/",)
HOMES = ("/home/", "/root/")
EXEC_LOCATIONS = ("none", "temp", "webroot", "system_bin", "home", "other")
FILE_LOCATIONS = ("none", "webroot_exec", "webroot_other", "temp", "system_config", "home", "other")
WEB_PORTS = frozenset({80, 443, 8080, 8443})
PORT_CLASSES = ("none", "web", "ssh", "dns", "low_other", "high")
CRITICALITY = ("low", "medium", "high", "critical", "unknown")
SEVERITY = ("low", "medium", "high", "critical", "unknown")
USER_CLASSES = ("none", "web_service", "root", "known_admin", "other")
FIXED_ZONES = ("none", "loopback", "private", "public", "invalid")


def _g(d: dict, path: str) -> Any:
    if not isinstance(d, dict):
        return None
    if path in d:
        return d[path]
    cur: Any = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def _first(v: Any) -> Any:
    return v[0] if isinstance(v, list) and v else v


def _yn(v: Any) -> str:
    return "yes" if v else "no"


def _ynu(v: Any) -> str:
    return "unknown" if v is None else ("yes" if v else "no")


def proc_class(name: Any) -> str:
    """Numele unui proces -> clasa lui. Doar cautare in multimi fixe."""
    if not isinstance(name, str) or not name.strip():
        return "none"
    n = name.strip().rsplit("/", 1)[-1].lower()[:64]
    if n in WEB_SERVERS or n.startswith(("php-fpm", "apache")):
        return "web_server"
    if n in SHELLS:
        return "shell"
    if n in INTERPRETERS or n.startswith(("python", "perl", "ruby")):
        return "interpreter"
    if n in DOWNLOADERS:
        return "downloader"
    if n in NET_TOOLS:
        return "net_tool"
    if n in ACCOUNT_TOOLS:
        return "account_tool"
    if n in PACKAGE_TOOLS:
        return "package_tool"
    if n in SYSTEM_PROCS:
        return "system"
    return "other"


def exec_location(path: Any) -> str:
    if not isinstance(path, str) or not path:
        return "none"
    if path.startswith(TEMP_DIRS):
        return "temp"
    if path.startswith(WEBROOTS):
        return "webroot"
    if path.startswith(SYSTEM_BIN):
        return "system_bin"
    if path.startswith(HOMES):
        return "home"
    return "other"


def file_location(ctx: dict, alert: dict) -> str:
    path = _first(_g(alert, "file.path"))
    if not isinstance(path, str) or not path:
        return "none"
    if ctx.get("webroot_executable_write"):
        return "webroot_exec"
    if path.startswith(WEBROOTS):
        return "webroot_other"
    if path.startswith(TEMP_DIRS):
        return "temp"
    if path.startswith("/etc/"):
        return "system_config"
    if path.startswith(HOMES):
        return "home"
    return "other"


def port_class(port: Any) -> str:
    try:
        p = int(_first(port))
    except (TypeError, ValueError):
        return "none"
    if p in WEB_PORTS:
        return "web"
    if p == 22:
        return "ssh"
    if p == 53:
        return "dns"
    return "high" if p >= 1024 else "low_other"


def ip_zone(ip: Any, zones: list[NetworkZone]) -> str:
    """IP -> zona de retea: prima zona din configurare care il contine, altfel loopback /
    private / public. Adresa insasi nu iese din functie."""
    ip = _first(ip)
    if not isinstance(ip, str) or not ip:
        return "none"
    try:
        a = ipaddress.ip_address(ip.strip())
    except ValueError:
        return "invalid"
    for z in zones:
        for c in z.cidrs:
            try:
                if a in ipaddress.ip_network(c, strict=False):
                    return z.name
            except ValueError:
                continue
    if a.is_loopback:
        return "loopback"
    if a.is_private:
        return "private"
    return "public"


def user_class(ctx: dict) -> str:
    ex = ctx.get("execution") or {}
    user = ex.get("user")
    if not user:
        return "none"
    if user in WEB_SVC_USERS:
        return "web_service"
    if ctx.get("ran_by_known_admin"):
        return "known_admin"
    if user == "root":
        return "root"
    return "other"


def _choice(v: Any, allowed: tuple[str, ...], default: str) -> str:
    v = (str(v).lower() if v is not None else default)
    return v if v in allowed else ("other" if "other" in allowed else default)


class Env:
    """Ce primeste fiecare punct de decizie: faptele, alerta, pipeline-ul si zonele."""

    def __init__(self, ctx: dict, alert: dict, pipeline: PipelineConfig, zones: list[NetworkZone]):
        self.ctx = ctx or {}
        self.alert = alert or {}
        self.pipeline = pipeline
        self.zones = zones


def _rule(e: Env) -> str:
    name = e.ctx.get("rule_name") or _g(e.alert, "kibana.alert.rule.name")
    try:
        return f"r{e.pipeline.rules.index(name)}"
    except ValueError:
        return "other"


def _web_exec(e: Env) -> str:
    ex = e.ctx.get("execution") or {}
    return _yn(web_exec_floor(e.ctx.get("ran_by_web_service_account"), ex.get("parent"),
                              ex.get("sudo_invoked_by")))


# nume -> (valori permise sau None = zona din configurare, functie)
CATALOG: dict[str, tuple[tuple[str, ...] | None, Callable[[Env], str]]] = {
    "rule": (tuple(f"r{i}" for i in range(50)) + ("other",), _rule),
    "web_service_account": (YN, lambda e: _yn(e.ctx.get("ran_by_web_service_account"))),
    "known_admin": (YN, lambda e: _yn(e.ctx.get("ran_by_known_admin"))),
    "temp_dir": (YN, lambda e: _yn(e.ctx.get("ran_from_temp_dir"))),
    "sensitive_action": (YN, lambda e: _yn(e.ctx.get("sensitive_action"))),
    "webroot_write": (YN, lambda e: _yn(e.ctx.get("webroot_executable_write"))),
    "maintenance_window": (YN, lambda e: _yn(e.ctx.get("in_maintenance_window"))),
    "pair_in_baseline": (YNU, lambda e: _ynu(e.ctx.get("pair_in_baseline"))),
    "via_sudo": (YN, lambda e: _yn((e.ctx.get("execution") or {}).get("sudo_invoked_by"))),
    "web_exec": (YN, _web_exec),
    "user_class": (USER_CLASSES, lambda e: user_class(e.ctx)),
    "process_class": (PROC_CLASSES, lambda e: proc_class((e.ctx.get("execution") or {}).get("process"))),
    "parent_class": (PROC_CLASSES, lambda e: proc_class((e.ctx.get("execution") or {}).get("parent"))),
    "exec_location": (EXEC_LOCATIONS, lambda e: exec_location((e.ctx.get("execution") or {}).get("executable"))),
    "file_location": (FILE_LOCATIONS, lambda e: file_location(e.ctx, e.alert)),
    "dest_port_class": (PORT_CLASSES, lambda e: port_class(_g(e.alert, "destination.port"))),
    "source_zone": (None, lambda e: ip_zone(_g(e.alert, "source.ip"), e.zones)),
    "destination_zone": (None, lambda e: ip_zone(_g(e.alert, "destination.ip"), e.zones)),
    "asset_criticality": (CRITICALITY, lambda e: _choice(e.ctx.get("asset_criticality"), CRITICALITY, "unknown")),
    "severity": (SEVERITY, lambda e: _choice(_first(_g(e.alert, "kibana.alert.severity")), SEVERITY, "unknown")),
}


def allowed_values(name: str, zones: list[NetworkZone]) -> tuple[str, ...]:
    allowed, _ = CATALOG[name]
    if allowed is None:
        return FIXED_ZONES + tuple(z.name for z in zones)
    return allowed


def derive(ctx: dict, alert: dict, pipeline: PipelineConfig,
           zones: list[NetworkZone] | None = None) -> dict[str, str]:
    """Valorile punctelor de decizie ale pipeline-ului. O functie care crapa da "error" doar
    pentru ea? Nu: eroarea urca (cascada trece atunci la pasul urmator, L6), ca un grup sa nu se
    formeze pe o valoare falsa."""
    zones = zones or []
    env = Env(ctx, alert, pipeline, zones)
    out: dict[str, str] = {}
    for name in pipeline.decision_points:
        if name not in CATALOG:
            raise KeyError(f"punct de decizie necunoscut: {name}")
        _, fn = CATALOG[name]
        v = fn(env)
        allowed = allowed_values(name, zones)
        out[name] = v if v in allowed else ("other" if "other" in allowed else allowed[-1])
    return out

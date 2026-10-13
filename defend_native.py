"""
ALERTELE NATIVE ELASTIC DEFEND — recunoastere si normalizare inainte de Tier 1.

Alertele produse de Defend (malware, comportament, memorie, ransomware) ajung in
.alerts-security.alerts-* prin regula de promovare "Endpoint Security" (tip query),
cu event.dataset = endpoint.alerts. Structura lor difera de a regulilor EQL proprii:
  - ce stie Defend despre detectie (tipul, regula Elastic, descrierea, ATT&CK,
    risk_score, detect/prevent) sta in event.code, rule.*, threat[], event.*;
  - la alertele de memorie procesul tinta poate fi doar in Target.process.*.

Aici:
  - is_native(alert): codul decide daca alerta e nativa (nu modelul);
  - normalize_fields(alert): completeaza campurile process.* / user.name din
    echivalentele native, DOAR unde lipsesc, ca faptele sa se calculeze la fel;
  - detection(alert): faptele Defend, validate (Pydantic, extra=forbid). Events[]
    brut NU intra: e telemetrie, iar lantul de procese il aduc faptele si uneltele.

Decizia (2026-10-13, Tiberiu): o alerta nativa NU se inchide niciodata pe Tier 1
(motiv de escaladare native_detection, in escalation.py).
"""

from __future__ import annotations

import copy
import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

NATIVE_DATASET = "endpoint.alerts"
MAX_TECHNIQUES = 10
MAX_DESCRIPTION = 600
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTIC_RE = re.compile(r"^TA\d{4}$")


class NativeKind(str, Enum):
    BEHAVIOR = "behavior"
    MALWARE = "malware"
    MEMORY = "memory"
    SHELLCODE = "shellcode"
    RANSOMWARE = "ransomware"
    OTHER = "other"


# event.code -> tipul detectiei; necunoscut -> OTHER (tot nativa, tot escaladeaza)
KIND_BY_CODE = {
    "behavior": NativeKind.BEHAVIOR,
    "malicious_behavior": NativeKind.BEHAVIOR,
    "malicious_file": NativeKind.MALWARE,
    "malware": NativeKind.MALWARE,
    "memory_signature": NativeKind.MEMORY,
    "shellcode_thread": NativeKind.SHELLCODE,
    "ransomware": NativeKind.RANSOMWARE,
}


class NativeMode(str, Enum):
    DETECTED = "detected"     # event.type contine "allowed": doar detectat, nu oprit
    PREVENTED = "prevented"   # event.type contine "denied": Defend a blocat
    UNKNOWN = "unknown"


class NativeDetection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: NativeKind
    mode: NativeMode
    vendor_rule: str = Field(max_length=200)
    description: str = Field(max_length=MAX_DESCRIPTION)
    ruleset: str = Field(max_length=40)
    techniques: list[str] = Field(max_length=MAX_TECHNIQUES)
    tactics: list[str] = Field(max_length=MAX_TECHNIQUES)
    risk_score: int | None = Field(default=None, ge=0, le=100)

    @field_validator("techniques")
    @classmethod
    def _tech(cls, v):
        for t in v:
            if not TECHNIQUE_RE.match(t):
                raise ValueError(f"tehnica ATT&CK invalida: {t!r}")
        return v

    @field_validator("tactics")
    @classmethod
    def _tac(cls, v):
        for t in v:
            if not TACTIC_RE.match(t):
                raise ValueError(f"tactica ATT&CK invalida: {t!r}")
        return v


def _g(d: dict, path: str):
    if path in d:
        return d[path]
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first(v):
    return v[0] if isinstance(v, list) and v else v


def is_native(alert: dict) -> bool:
    """Alerta produsa de Defend (nu de o regula EQL proprie)."""
    return (_first(_g(alert, "event.dataset")) == NATIVE_DATASET
            or _first(_g(alert, "kibana.alert.original_event.dataset")) == NATIVE_DATASET)


# Unde lipseste campul din stanga, il ia din dreapta (in ordine). Doar completare,
# niciodata suprascriere: ce a pus Defend in process.* ramane neatins.
FALLBACKS = {
    "user.name": ("process.user.name", "Target.process.user.name"),
    "process.name": ("Target.process.name",),
    "process.executable": ("Target.process.executable",),
    "process.command_line": ("Target.process.command_line",),
    "process.entity_id": ("Target.process.entity_id",),
    "process.parent.name": ("Target.process.parent.name",),
    "process.parent.entity_id": ("Target.process.parent.entity_id",),
}


def _set(d: dict, path: str, value) -> None:
    if path in d:                       # forma plata
        d[path] = value
        return
    cur = d
    parts = path.split(".")
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def normalize_fields(alert: dict) -> tuple[dict, list[str]]:
    """Copie a alertei cu campurile ECS completate din echivalentele native.
    Intoarce si lista campurilor completate (pentru audit si teste)."""
    out = copy.deepcopy(alert)
    filled = []
    for target, sources in FALLBACKS.items():
        if _g(out, target) not in (None, ""):
            continue
        for src in sources:
            val = _g(out, src)
            if isinstance(val, str) and val:
                _set(out, target, val)
                filled.append(target)
                break
    return out, filled


def _ids(threat, key: str) -> list[str]:
    """ID-urile ATT&CK din threat[] (tehnici + subtehnici sau tactici), unice, in ordine."""
    out = []
    for t in threat if isinstance(threat, list) else []:
        if not isinstance(t, dict):
            continue
        if key == "tactic":
            cands = [_g(t, "tactic.id")]
        else:
            cands = []
            for tech in t.get("technique") or []:
                if isinstance(tech, dict):
                    cands.append(tech.get("id"))
                    cands += [s.get("id") for s in tech.get("subtechnique") or [] if isinstance(s, dict)]
        rx = TACTIC_RE if key == "tactic" else TECHNIQUE_RE
        for c in cands:
            if isinstance(c, str) and rx.match(c) and c not in out:
                out.append(c)
    return out[:MAX_TECHNIQUES]


def _mode(event_type) -> NativeMode:
    types = event_type if isinstance(event_type, list) else [event_type]
    if "denied" in types:
        return NativeMode.PREVENTED
    if "allowed" in types:
        return NativeMode.DETECTED
    return NativeMode.UNKNOWN


def _risk(alert: dict) -> int | None:
    for f in ("event.risk_score", "kibana.alert.original_event.risk_score"):
        v = _g(alert, f)
        if isinstance(v, (int, float)) and 0 <= v <= 100:
            return int(v)
    return None


def _text(v, n: int) -> str:
    return " ".join(str(v or "").split())[:n]


def detection(alert: dict) -> NativeDetection | None:
    """Faptele Defend validate, sau None daca alerta nu e nativa."""
    if not is_native(alert):
        return None
    code = _first(_g(alert, "event.code")) or _first(_g(alert, "kibana.alert.original_event.code"))
    return NativeDetection(
        kind=KIND_BY_CODE.get(str(code or "").lower(), NativeKind.OTHER),
        mode=_mode(_g(alert, "event.type") or _g(alert, "kibana.alert.original_event.type")),
        vendor_rule=_text(_g(alert, "rule.name") or _g(alert, "kibana.alert.rule.name"), 200),
        description=_text(_g(alert, "rule.description"), MAX_DESCRIPTION),
        ruleset=_text(_g(alert, "rule.ruleset"), 40),
        techniques=_ids(_g(alert, "threat"), "technique"),
        tactics=_ids(_g(alert, "threat"), "tactic"),
        risk_score=_risk(alert),
    )

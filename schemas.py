"""
Granita de incredere a sistemului.

Regula centrala: NIMIC din ce a atins continut controlat de atacator nu traverseaza
spre planul de actiune ca text liber. Doar campurile de mai jos trec, si sunt toate
fie enumerari inchise, fie numere, fie referinte opace de document.

Naratiunea in limbaj natural exista — dar merge in artefactul de audit, NU in Verdict.
Artefactul de audit nu alimenteaza niciodata o actiune. Asta e toata smecheria.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class Classification(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNDETERMINED = "undetermined"


class ActionType(str, Enum):
    """Enumerare INCHISA. Un agent nu poate inventa o actiune noua."""

    NONE = "none"
    ENRICH_ONLY = "enrich_only"
    BLOCK_IP_TTL = "block_ip_ttl"          # firewall, expira singur
    FREEZE_PROCESS = "freeze_process"       # cgroup.freeze / SIGSTOP — pastreaza dovada
    QUARANTINE_FILE = "quarantine_file"     # mutare cu backup
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"           # distruge dovada — vezi policy.py
    ROTATE_CREDENTIALS = "rotate_credentials"
    ESCALATE_HUMAN = "escalate_human"


class Reversibility(str, Enum):
    FREE = "free"
    CHEAP = "cheap"            # automatizabil
    EXPENSIVE = "expensive"    # necesita prag inalt
    IRREVERSIBLE = "irreversible"


class EntityType(str, Enum):
    HOST = "host"
    USER = "user"
    PROCESS = "process"
    SOURCE_IP = "source_ip"
    SERVICE = "service"


class EvidenceRef(BaseModel):
    """
    Referinta opaca la un document Elastic. NU contine text din log.

    Daca planul de actiune are nevoie de continut, il re-interogheaza el insusi
    din Elastic — dar atunci raspunde el pentru ce baga in context, nu agentul.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    index: str
    doc_id: str
    timestamp: datetime
    field_path: str | None = Field(
        default=None,
        description="Ce camp a contat, ex. 'process.command_line'. Numele campului, nu valoarea.",
    )


class Verdict(BaseModel):
    """
    Singura structura care traverseaza granita. `extra=forbid` nu e cosmetic:
    e ce impiedica un agent sa strecoare un camp `note` cu instructiuni in el.
    """

    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    source_path: Literal["fast", "hunt", "correlate"]

    entity_type: EntityType
    entity_id: str

    classification: Classification
    confidence: int = Field(ge=0, le=100)
    rarity_score: float = Field(
        ge=0.0, le=1.0, description="1.0 = nevazut niciodata in fereastra de baseline"
    )

    mitre_techniques: list[str] = Field(default_factory=list, max_length=10)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list, max_length=50)

    proposed_action: ActionType = ActionType.NONE
    action_target: str | None = Field(
        default=None,
        description="IP, PID sau host.id. Validat sintactic in policy.py inainte de executie.",
    )

    # Pentru calibrare. Fara astea nu poti masura nimic si pragurile raman inventate.
    model_id: str
    tokens_used: int = 0
    tool_calls_made: int = 0
    critic_agreed: bool | None = None

    # De unde vine increderea pe calea lenta: "not_required" (n-a fost nevoie
    # de al doilea investigator), "agreement" (doi investigatori independenti,
    # dovezi diferite, aceeasi concluzie — increderea creste), "disagreement"
    # (concluzii diferite — increderea e plafonata, actiunea devine escalate_human).
    # E o sursa mai solida decat un scor auto-raportat de un singur agent.
    corroboration_status: Literal["not_required", "agreement", "disagreement", "budget_exhausted"] = "not_required"

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("mitre_techniques")
    @classmethod
    def _valid_mitre(cls, v: list[str]) -> list[str]:
        for t in v:
            if not MITRE_RE.match(t):
                raise ValueError(f"tehnica ATT&CK invalida: {t!r}")
        return v

    @field_validator("entity_id", "action_target")
    @classmethod
    def _no_injection_surface(cls, v: str | None) -> str | None:
        """
        entity_id si action_target ajung in comenzi de sistem. Ingust dinadins.
        Daca ai nevoie de ceva ce nu trece de aici, nu e un identificator.
        """
        if v is None:
            return v
        if len(v) > 253 or not re.match(r"^[A-Za-z0-9_.:\-/]+$", v):
            raise ValueError(f"identificator respins: {v!r}")
        return v


class ContextPack(BaseModel):
    """
    Preadus determinist din Elastic INAINTE ca vreun model sa vada ceva.
    Centrat pe entitate, nu pe amenintare: 'tot ce stim despre X',
    nu 'tot ce e suspect la X'. A doua formulare reintroduce filtrul semantic.
    """

    model_config = ConfigDict(extra="forbid")

    entity_type: EntityType
    entity_id: str

    investigation_guide: str | None = None       # scris de tine, in git, langa regula
    asset_criticality: Literal["low", "medium", "high", "critical"] | None = None
    asset_owner: str | None = None
    exposed_services: list[str] = Field(default_factory=list)
    open_cves: list[str] = Field(default_factory=list)

    # Baseline-ul de entitate, produs de transforms. Vezi elastic_tools.py
    first_seen: datetime | None = None
    events_last_90d: int = 0
    common_parents: list[str] = Field(default_factory=list)
    common_destinations: list[str] = Field(default_factory=list)

    # Bucla de feedback (echivalentul PastCasesByRulenameLookup de la Elastic)
    past_verdicts_same_rule: list[dict] = Field(default_factory=list, max_length=50)
    fp_rate_same_rule: float | None = None


class RarityFinding(BaseModel):
    """Ce scoate sweep-ul programat. Complet agnostic fata de amenintare."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal[
        "new_parent_child",
        "new_destination_asn",
        "new_webroot_write",
        "new_ja4",
        "response_size_outlier",
        "new_listening_port",
    ]
    entity_type: EntityType
    entity_id: str
    detail: dict
    rarity_score: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class AuditRecord(BaseModel):
    """
    UN artefact per investigatie, nu unul per agent.
    Sub NIS2 / DORA cineva trebuie sa poata reconstitui o singura naratiune
    defensabila pentru fiecare decizie autonoma. Daca lasi loguri separate
    pe agent, cineva le compune manual la 3 dimineata.

    Aici POATE sta text liber. Nu alimenteaza niciodata o actiune.
    """

    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    verdict: Verdict
    narrative: str
    hypotheses_considered: list[str] = Field(default_factory=list)
    queries_run: list[str] = Field(default_factory=list)
    critic_objection: str | None = None
    policy_decision: str
    action_executed: ActionType
    action_result: str | None = None
    started_at: datetime
    finished_at: datetime

    # True = actiunea a fost doar logata, nu executata. Implicit True.
    # Se trece manual pe False doar dupa ce metricile din harness trec
    # pragul pentru clasa de reversibilitate respectiva. Vezi graph.py.
    shadow_mode: bool = True

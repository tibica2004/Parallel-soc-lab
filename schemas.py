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

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
# Identificatorul lantului: acelasi caz, prin toate nivelurile (Tier 1 -> 2 -> 3).
# Il genereaza orchestratorul (uuid4); modelul nu-l vede si nu-l poate alege.
CHAIN_ID_RE = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
# process.entity_id din Elastic Defend e base64 (poate contine + / =).
ENTITY_ID_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{1,128}$")
HOST_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,253}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


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


class EscalationReason(str, Enum):
    """
    De ce a escaladat Tier 1. Enumerare INCHISA, decisa de cod (escalation.py),
    deci poate trece granita — spre deosebire de naratiunea modelului.
    Sta aici, nu in escalation.py, ca s-o poata folosi si Case.
    """

    UNDETERMINED = "undetermined"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    FLOOR_OVERRIDE = "floor_override"          # codul a rasturnat un benign al modelului
    LOW_CONFIDENCE = "low_confidence"
    BENIGN_UNSEEN_PAIR = "benign_unseen_pair"  # benign pe ceva nevazut in baseline
    # Mod degradat: Tier 1 n-a putut judeca (model cazut, timeout, eroare) sau
    # nici n-a incercat (alerta grava in restanta). Esecul escaladeaza, nu inchide.
    TIER1_FAILURE = "tier1_failure"
    BACKLOG_SEVERE = "backlog_severe"
    # Alerta nativa Elastic Defend (malware, comportament, memorie): Tier 1 o
    # triaza si o imbogateste, dar nu o inchide niciodata (decizie 2026-10-13).
    NATIVE_DETECTION = "native_detection"
    # Regula de honeytoken (honeytokens.RULES): nimic legitim nu atinge momeala,
    # deci escaladeaza mereu, oricat de sigur ar fi modelul (faza 12).
    HONEYTOKEN = "honeytoken"
    # Detectie a unui senzor propriu (sensor_rules.RULES, ex. YARA pe webroot): poate
    # fi fals pozitiva, dar nu o inchide Tier 1 singur (ca native_detection).
    SENSOR_DETECTION = "sensor_detection"


class FailureKind(str, Enum):
    """De ce n-a existat un verdict de model. Inchisa, decisa de cod."""

    MODEL_UNAVAILABLE = "model_unavailable"   # verificarea de sanatate a picat
    CASE_TIMEOUT = "case_timeout"             # plafonul de timp per caz depasit
    PROCESSING_ERROR = "processing_error"     # orice alta exceptie in graf


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
    # None cat timp verdictul n-a trecut prin orchestrator (ex. in harness).
    chain_id: str | None = Field(default=None, pattern=CHAIN_ID_RE)

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
    corroboration_status: Literal["not_required", "agreement", "disagreement", "budget_exhausted",
                                  "secondary_unavailable"] = "not_required"

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
        "new_url_path",
        "beaconing",
        "dns_anomaly",
    ]
    entity_type: EntityType
    entity_id: str
    detail: dict
    rarity_score: float = Field(ge=0.0, le=1.0)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class PlanStep(BaseModel):
    """Un pas concret al unei actiuni: argv pe host (niciodata sir de shell) sau
    un apel API. Doar descriere: executorul ruleaza exclusiv dry-run."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Literal["ssh_argv", "kibana_api"]
    argv: list[str] | None = Field(default=None, max_length=20)
    method: Literal["POST"] | None = None
    path: str | None = Field(default=None, max_length=200)
    body: dict | None = None

    @model_validator(mode="after")
    def _shape(self) -> "PlanStep":
        if self.kind == "ssh_argv" and (not self.argv or self.method or self.path or self.body):
            raise ValueError("ssh_argv cere doar argv")
        if self.kind == "kibana_api" and (self.argv or not (self.method and self.path)):
            raise ValueError("kibana_api cere method + path, fara argv")
        for a in self.argv or []:
            if not a or len(a) > 512 or _CONTROL_RE.search(a):
                raise ValueError(f"argument respins: {a!r}")
        return self


class ActionPlan(BaseModel):
    """Ce AR face executorul. Construit de cod din Verdict + Decision; nimic din
    el nu vine ca text liber de la model (tinta e validata dupa tipul ei)."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: ActionType
    host: str = Field(pattern=r"^[A-Za-z0-9_.\-]{1,253}$")
    target: str = Field(max_length=253)
    reversibility: Reversibility
    steps: list[PlanStep] = Field(min_length=1, max_length=10)
    rollback: list[PlanStep] = Field(default_factory=list, max_length=10)
    expires_at: datetime | None = None          # anulare automata daca nu e confirmata
    asset_criticality: str | None = Field(default=None, max_length=32)
    graduated: bool = False                     # clasa absolvita din etichete umane
    graduation_reason: str = Field(default="", max_length=300)
    requires_approval: bool = True
    approval_reason: str = Field(default="", max_length=300)
    mode: Literal["dry-run"] = "dry-run"        # singurul mod (CLAUDE.md, principiul 4)


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
    chain_id: str | None = Field(default=None, pattern=CHAIN_ID_RE)
    verdict: Verdict
    # Decizia de escaladare Tier 1 -> Tier 2, luata de cod. None = nu se aplica
    # (ex. verdict de pe calea lenta, unde nu exista un nivel urmator inca).
    escalate: bool | None = None
    escalation_reasons: list[EscalationReason] = Field(default_factory=list)
    # Setat doar cand verdictul NU vine de la model (vezi degraded.py).
    failure: FailureKind | None = None
    # Pentru un caz escaladat de Tier 1: a ajuns la Tier 2 sau a ramas doar la om
    # pentru ca bugetul de Tier 2 pe ciclu era epuizat. None = nu se aplica.
    tier2: Literal["investigated", "skipped_budget"] | None = None
    narrative: str
    hypotheses_considered: list[str] = Field(default_factory=list)
    queries_run: list[str] = Field(default_factory=list)
    critic_objection: str | None = None
    policy_decision: str
    action_executed: ActionType
    action_result: str | None = None
    # Planul executorului (dry-run) pentru o actiune care nu e gratuita; None altfel.
    execution_plan: ActionPlan | None = None
    started_at: datetime
    finished_at: datetime

    # True = actiunea a fost doar logata, nu executata. Implicit True.
    # Se trece manual pe False doar dupa ce metricile din harness trec
    # pragul pentru clasa de reversibilitate respectiva. Vezi graph.py.
    shadow_mode: bool = True


class Case(BaseModel):
    """
    Ce primeste Tier 2 cand Tier 1 escaladeaza (sau cand sweep-ul / Tier 3 gasesc ceva).

    DOAR fapte, dovezi si motivele escaladarii. Fara classification, confidence sau
    narrative de la Tier 1: un investigator care vede "suspicious/70" se ancoreaza in
    el. `extra=forbid` face ca o incercare de a strecura verdictul sa crape, nu sa treaca.

    parent/child/rule_name pot veni din telemetrie (numele procesului il alege
    atacatorul). Nu intra niciodata in text de interogare — doar ca parametri —,
    dar le limitam lungimea si interzicem caracterele de control.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    chain_id: str = Field(pattern=CHAIN_ID_RE)
    origin: Literal["tier1_alert", "rarity_sweep", "tier3_hunt"]
    host: str
    entity_id: str | None = None          # process.entity_id, cand exista
    parent: str | None = Field(default=None, max_length=255)
    child: str | None = Field(default=None, max_length=255)
    rule_name: str | None = Field(default=None, max_length=256)
    escalation_reasons: list[EscalationReason] = Field(default_factory=list, max_length=10)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list, max_length=50)
    # Fapt calculat de cod (perechea parinte-copil fata de baseline), nu judecata
    # modelului: 0.0 = vazuta in baseline, 1.0 = nevazuta sau neverificabila.
    rarity_score: float | None = Field(default=None, ge=0.0, le=1.0)

    @field_validator("host")
    @classmethod
    def _valid_host(cls, v: str) -> str:
        if not HOST_RE.match(v):
            raise ValueError(f"host respins: {v!r}")
        return v

    @field_validator("entity_id")
    @classmethod
    def _valid_entity(cls, v: str | None) -> str | None:
        if v is not None and not ENTITY_ID_RE.match(v):
            raise ValueError(f"entity_id respins: {v!r}")
        return v

    @field_validator("parent", "child", "rule_name")
    @classmethod
    def _no_control_chars(cls, v: str | None) -> str | None:
        if v is not None and _CONTROL_RE.search(v):
            raise ValueError("caractere de control in camp din telemetrie")
        return v

    @model_validator(mode="after")
    def _tier1_has_reasons(self) -> "Case":
        # Un caz venit din Tier 1 exista DOAR pentru ca a escaladat: fara motive
        # inseamna un bug in orchestrator, nu un caz valid.
        if self.origin == "tier1_alert" and not self.escalation_reasons:
            raise ValueError("caz tier1_alert fara escalation_reasons")
        return self

"""Formele de date ale deciziei invatate din etichete (faza 24, mecanismul in stil Arcanna).

Contractele nu importa nimic din restul pachetului (regula de importuri). Toate modelele au
`extra="forbid"`; mesajele care trec prin magistrala au si `schema_version`.

Vocabular:
  pipeline        o familie de alerte (una sau mai multe reguli), cu punctele ei de decizie,
                  modelul ei si actiunile ei post-decizie (config/pipelines.yml, in git);
  punct de decizie  o categorie cu putine valori, derivata din faptele calculate de cod;
  grup (bucket)   alertele cu aceleasi valori pe punctele de decizie (indexul soc-buckets);
  eticheta        votul unui OM autentificat pe un grup (attack | benign);
  consens         votul majoritar; egalitatea = nedecis, nu intra la antrenare.
"""
from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

LEARNING_SCHEMA_VERSION = 1

PIPELINE_ID_RE = r"^[a-z][a-z0-9_]{0,39}$"
DP_NAME_RE = r"^[a-z][a-z0-9_]{0,39}$"
DP_VALUE_RE = r"^[A-Za-z0-9_.:\- ]{1,80}$"
BUCKET_ID_RE = r"^b[0-9a-f]{24}$"
MODEL_HASH_RE = r"^[0-9a-f]{64}$"
USER_RE = r"^[a-z][a-z0-9_.\-]{0,31}$"

Label = Literal["attack", "benign"]


class Consensus(str, Enum):
    ATTACK = "attack"
    BENIGN = "benign"
    TIE = "tie"            # egalitate: nedecis, nu intra la antrenare
    NONE = "none"          # niciun vot


class CascadeMode(str, Enum):
    OFF = "off"            # T1_CASCADE=off: verdictele identice cu cele dinaintea fazei (L5)
    SHADOW = "shadow"      # decizia se calculeaza si se inregistreaza, nu scurteaza nimic
    ON = "on"              # scurteaza inchiderile, DOAR pe pipeline-urile cu model activ


class CascadeStep(str, Enum):
    """Pasul cascadei care a decis cazul (contorizat in metrici)."""
    NO_PIPELINE = "no_pipeline"        # alerta nu apartine niciunui pipeline -> pasul 4
    CRITICAL = "critical"              # clasa critica (L4) -> pasul 4
    FLOOR = "floor"                    # s-ar aplica o podea (L4) -> pasul 4
    HUMAN_LABEL = "human_label"        # grup cu consens uman
    MODEL = "model"                    # sursa de decizie (model propriu sau camp extern)
    FAST_PATH = "fast_path"            # pasul 4: fast_path + should_escalate, ca azi
    ERROR = "error"                    # eroare in cascada -> pasul 4 (L6)


class ModelDecision(str, Enum):
    BENIGN = "benign"
    ATTACK = "attack"
    UNCERTAIN = "uncertain"


class ModelState(str, Enum):
    CANDIDATE = "candidate"
    SHADOW = "shadow"
    ACTIVE = "active"
    RETIRED = "retired"


# ------------------------------------------------------------------------------------------------
# Configurarea pipeline-urilor (config/pipelines.yml)
# ------------------------------------------------------------------------------------------------

class NetworkZone(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str = Field(pattern=DP_NAME_RE)
    cidrs: list[str] = Field(min_length=1, max_length=20)


class ExternalSourceConfig(BaseModel):
    """Sursa externa de decizie (pasul 3): un camp scris pe alerta de alt sistem (ex. Arcanna).
    Valorile campului se traduc prin `values` in attack/benign; orice alta valoare = nesigur."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    decision_field: str = Field(pattern=r"^[A-Za-z0-9_.@]{1,120}$")
    confidence_field: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.@]{1,120}$")
    values: dict[str, Label] = Field(min_length=1, max_length=20)


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    benign_close: int = Field(default=90, ge=50, le=100)     # increderea minima pentru inchidere
    attack_likely: int = Field(default=60, ge=50, le=100)    # p(attack)*100 peste care -> motiv
    outlier_distance: int = Field(default=2, ge=1, le=20)    # puncte diferite fata de cel mai apropiat grup etichetat
    max_new_bucket_rate: float = Field(default=0.30, gt=0, le=1)   # drift: grupuri noi / cazuri, 24 h
    max_outlier_rate: float = Field(default=0.30, gt=0, le=1)      # drift: outlieri / decizii, 24 h
    max_control_disagreement: float = Field(default=0.05, gt=0, le=1)
    control_sample_pct: int = Field(default=10, ge=1, le=100)


class PipelineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=PIPELINE_ID_RE)
    description: str = Field(default="", max_length=300)
    rules: list[str] = Field(min_length=1, max_length=50)       # numele exacte ale regulilor
    decision_points: list[str] = Field(min_length=2, max_length=20)
    decision_points_version: int = Field(ge=1)
    decision_source: Literal["own_model", "external"] = "own_model"
    external: ExternalSourceConfig | None = None
    post_decision_tags: bool = True
    thresholds: Thresholds = Thresholds()

    @field_validator("decision_points")
    @classmethod
    def _names(cls, v: list[str]) -> list[str]:
        for n in v:
            if not re.match(DP_NAME_RE, n):
                raise ValueError(f"punct de decizie invalid: {n!r}")
        if len(set(v)) != len(v):
            raise ValueError("puncte de decizie duplicate")
        return v


class PipelinesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: int = Field(ge=1)
    network_zones: list[NetworkZone] = Field(default_factory=list, max_length=20)
    pipelines: list[PipelineConfig] = Field(min_length=1, max_length=50)


# ------------------------------------------------------------------------------------------------
# Grupuri si etichete
# ------------------------------------------------------------------------------------------------

class BucketKey(BaseModel):
    """Identitatea unui grup. Alta versiune a punctelor de decizie = alt grup."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    pipeline: str = Field(pattern=PIPELINE_ID_RE)
    dp_version: int = Field(ge=1)
    values: dict[str, str]
    bucket_id: str = Field(pattern=BUCKET_ID_RE)

    @field_validator("values")
    @classmethod
    def _values(cls, v: dict[str, str]) -> dict[str, str]:
        for k, x in v.items():
            if not re.match(DP_NAME_RE, k) or not re.match(DP_VALUE_RE, x):
                raise ValueError(f"valoare de punct de decizie invalida: {k}={x!r}")
        return v


class Vote(BaseModel):
    """Votul unui om pe un grup. Construit DOAR de eval/labeling.py, la actiunea omului."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    user: str = Field(pattern=USER_RE)
    label: Label
    at: datetime
    notes: str = Field(default="", max_length=500)


class LabeledBucket(BaseModel):
    """Un exemplu de antrenare: un grup cu consens uman (niciodata verdictul sistemului, L3)."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    bucket_id: str = Field(pattern=BUCKET_ID_RE)
    values: dict[str, str]
    label: Label
    first_seen: datetime
    last_seen: datetime
    count: int = Field(default=1, ge=0)


# ------------------------------------------------------------------------------------------------
# Modelul si predictia
# ------------------------------------------------------------------------------------------------

class Contribution(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    decision_point: str
    value: str
    weight: float          # log P(v|attack) - log P(v|benign); > 0 impinge spre attack


class Neighbor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    bucket_id: str = Field(pattern=BUCKET_ID_RE)
    distance: int = Field(ge=0)
    label: Label


class Prediction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    source: Literal["own_model", "external"]
    model_hash: str | None = Field(default=None, pattern=MODEL_HASH_RE)
    decision: ModelDecision
    confidence: int = Field(ge=0, le=100)          # increderea in `decision`
    p_attack: float | None = Field(default=None, ge=0.0, le=1.0)
    outlier: bool = False
    unseen_values: int = Field(default=0, ge=0)
    contributions: list[Contribution] = Field(default_factory=list, max_length=20)
    neighbors: list[Neighbor] = Field(default_factory=list, max_length=5)


class ValidationMetrics(BaseModel):
    """Metricile pe setul de validare (cele mai noi grupuri etichetate)."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    n: int = 0
    n_attack: int = 0
    n_benign: int = 0
    closures: int = 0               # grupuri pe care modelul le-ar inchide (benign peste prag)
    closures_correct: int = 0       # dintre ele, etichetate benign
    closed_attacks: int = 0         # dintre ele, etichetate attack (trebuie 0)
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    precision: float | None = None  # pe clasa attack (attack = orice nu se inchide)
    recall: float | None = None
    f1: float | None = None

    def closure_precision(self) -> float | None:
        return round(self.closures_correct / self.closures, 4) if self.closures else None


class ModelRecord(BaseModel):
    """O intrare din manifestul modelelor (data/models/MANIFEST.json)."""
    model_config = ConfigDict(extra="forbid")
    pipeline: str = Field(pattern=PIPELINE_ID_RE)
    model_hash: str = Field(pattern=MODEL_HASH_RE)
    algorithm: str = Field(max_length=40)
    dp_version: int = Field(ge=1)
    trained_at: datetime
    n_train: int = Field(ge=0)
    n_validation: int = Field(ge=0)
    labels_attack: int = Field(ge=0)
    labels_benign: int = Field(ge=0)
    validation: ValidationMetrics
    state: ModelState = ModelState.CANDIDATE
    state_since: datetime
    ever_active: bool = False


class ShadowStats(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    decisions: int = 0
    closures: int = 0
    contradicted: int = 0             # inchideri pe care calea completa le-a gasit suspicious/malicious
    closures_on_attack_buckets: int = 0


class ActiveStats(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    human_attack_on_closed_bucket: bool = False
    control_labeled: int = 0
    control_disagreements: int = 0
    new_bucket_rate: float | None = None
    outlier_rate: float | None = None
    hash_mismatch: bool = False


class ControllerInput(BaseModel):
    """Tot ce citeste controlorul pentru un pipeline. Construit de tier3, consumat de o functie pura."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    pipeline: str = Field(pattern=PIPELINE_ID_RE)
    now: datetime
    labels_attack: int = 0
    labels_benign: int = 0
    candidate: ModelRecord | None = None
    shadow: ModelRecord | None = None
    active: ModelRecord | None = None
    shadow_stats: ShadowStats = ShadowStats()
    active_stats: ActiveStats = ActiveStats()
    shadow_validation_now: ValidationMetrics | None = None   # modelul din umbra, pe validarea de acum
    regression_passed_for_shadow: bool = False
    labels_changed_since_shadow: int = 0
    thresholds: Thresholds = Thresholds()


class Transition(BaseModel):
    """O tranzitie decisa de controlor (notificare + soc-metrics + audit)."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = LEARNING_SCHEMA_VERSION
    pipeline: str = Field(pattern=PIPELINE_ID_RE)
    model_hash: str = Field(pattern=MODEL_HASH_RE)
    from_state: ModelState
    to_state: ModelState
    reason: str = Field(max_length=300)
    at: datetime
    actor: Literal["controller", "human"] = "controller"


# ------------------------------------------------------------------------------------------------
# Cascada (pasii 0-4 din Tier 1)
# ------------------------------------------------------------------------------------------------

class CascadeDecision(BaseModel):
    """Rezultatul cascadei pentru un caz. `applied` = a scurtat efectiv drumul (doar inchideri)."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = LEARNING_SCHEMA_VERSION
    mode: CascadeMode
    pipeline: str | None = Field(default=None, pattern=PIPELINE_ID_RE)
    dp_version: int | None = None
    bucket_id: str | None = Field(default=None, pattern=BUCKET_ID_RE)
    values: dict[str, str] = Field(default_factory=dict)
    step: CascadeStep
    would_close: bool = False           # ce ar face cascada daca ar fi activa
    applied: bool = False               # a inchis efectiv (mod on + pipeline activ + nu e esantion)
    control_sample: bool = False        # ar fi inchis, dar cazul merge oricum la om
    reasons: list[str] = Field(default_factory=list, max_length=5)   # EscalationReason.value
    applied_reasons: bool = False       # motivele se adauga efectiv la escaladare
    consensus: Consensus = Consensus.NONE
    pipeline_active: bool = False        # pipeline-ul are model activ (post-decizia se scrie doar atunci)
    model_state: ModelState | None = None
    prediction: Prediction | None = None
    error: str | None = Field(default=None, max_length=200)

"""Mesajele care trec intre modulele SOC-ului (faza 26, intrarea).

Azi circula in acelasi proces; din faza cozilor circula prin broker, deci sunt forme fixe:
`extra="forbid"`, enumerari inchise, `schema_version` pe fiecare mesaj. Modulul nu importa nimic
din restul pachetului (regula de importuri: contracts e stratul de jos).

`raw` din `AlertaNormalizata` e documentul alertei asa cum l-a dat Elasticsearch. E continut din
telemetrie (neincrezator): merge doar spre calea de verdict, care il trateaza ca date, niciodata
spre o actiune. Plicul din jurul lui e cel validat.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = 1


class CriticalClass(str, Enum):
    """Clasele care ajung la om indiferent de coada si de model. Valorile sunt aceleasi cu
    motivele de escaladare (schemas.EscalationReason) pe care notify.py le pagina dupa verdict."""

    HONEYTOKEN = "honeytoken"
    NATIVE_DETECTION = "native_detection"
    SENSOR_DETECTION = "sensor_detection"


class AlertaNormalizata(BaseModel):
    """O alerta citita din `.alerts-security.alerts-*`, cu ce are nevoie intrarea ca s-o
    grupeze si s-o prioritizeze, fara sa mai deschida documentul."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = SCHEMA_VERSION
    ref_index: str = Field(min_length=1, max_length=255)
    ref_id: str = Field(min_length=1, max_length=255)
    indexed_at: datetime | None = None          # @timestamp-ul alertei (cursorul merge dupa el)
    event_at: datetime | None = None            # momentul evenimentului (eventtime.alert_time)
    rule_name: str | None = Field(default=None, max_length=512)
    rule_id: str | None = Field(default=None, max_length=255)
    host: str | None = Field(default=None, max_length=255)
    source: str | None = Field(default=None, max_length=255)    # IP sursa, altfel host (potop)
    severity: str | None = Field(default=None, max_length=32)
    dedup_key: str = Field(min_length=1, max_length=2048)
    critical: CriticalClass | None = None
    raw: dict


class Contabilitate(BaseModel):
    """Socoteala unui ciclu de intrare. Invariantii (verificati de `ok()`):

        citite   = consumate + amanate
        consumate = cazuri + grupate + in_potop

    `cazuri` = alerte care deschid un caz nou (judecat); `grupate` = alerte care intra intr-un
    caz deja deschis (in lot sau intr-un ciclu anterior); `in_potop` = alerte absorbite intr-un
    incident de potop (inclusiv cele care il deschid); `amanate` = alerte citite dar lasate
    pentru ciclul urmator (plafonul de cazuri); cursorul ramane inaintea lor."""

    model_config = ConfigDict(extra="forbid")

    citite: int = 0
    consumate: int = 0
    amanate: int = 0
    cazuri: int = 0
    grupate: int = 0
    in_potop: int = 0
    incidente_potop: int = 0
    critice: int = 0
    critice_notificate: int = 0
    respinse: int = 0                     # plicul n-a putut fi validat; alerta merge totusi mai departe
    pagini: int = 0
    trunchiat: bool = False               # s-a atins plafonul de citire; cursorul nu sare peste rest

    def ok(self) -> bool:
        return (self.citite == self.consumate + self.amanate
                and self.consumate == self.cazuri + self.grupate + self.in_potop)


# ------------------------------------------------------------------------------------------------
# Faza 24 (decizia invatata): mesajele dintre niveluri, trimise prin magistrala (elasticlab/bus).
# Fiecare mesaj are `schema_version`; subiectul (topic) e fix per tip, in TOPICS.
# ------------------------------------------------------------------------------------------------

from elasticlab.contracts.learning import (BUCKET_ID_RE, LEARNING_SCHEMA_VERSION, USER_RE,  # noqa: E402
                                           CascadeDecision, Label, Transition)
from elasticlab.contracts.schemas import CHAIN_ID_RE, Case  # noqa: E402


class AlertRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    index: str = Field(min_length=1, max_length=255)
    id: str = Field(min_length=1, max_length=255)


class DecizieCascada(BaseModel):
    """Tier 1 -> grupuri / post-decizie: decizia cascadei pentru un caz, dupa verdict.
    `final_classification` e verdictul scris (pentru umbra: comparatia cu calea completa)."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = LEARNING_SCHEMA_VERSION
    decision: CascadeDecision
    chain_id: str | None = Field(default=None, pattern=CHAIN_ID_RE)
    alert_refs: list[AlertRef] = Field(default_factory=list, max_length=50)
    alert_count: int = Field(default=1, ge=1)
    event_at: datetime | None = None
    final_classification: str | None = Field(default=None, max_length=20)
    escalated: bool = False


class CazDeInvestigat(BaseModel):
    """Tier 1 -> Tier 2. Cazul (fara verdictul Tier 1, principiul 7) si identificatorul grupului.
    Niciodata increderea modelului sau eticheta ca verdict: doar motivele, in `case`."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = LEARNING_SCHEMA_VERSION
    case: Case
    entity: str = Field(max_length=600)
    bucket_id: str | None = Field(default=None, pattern=BUCKET_ID_RE)


class RezumatTier2(BaseModel):
    """Tier 2 -> pagina grupului: rezumatul investigatiei, ca omul sa eticheteze mai repede.
    NU devine eticheta (L2/L3): se scrie in `tier2_summary`, nu in voturi."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = LEARNING_SCHEMA_VERSION
    bucket_id: str = Field(pattern=BUCKET_ID_RE)
    chain_id: str | None = Field(default=None, pattern=CHAIN_ID_RE)
    summary: str = Field(max_length=2000)
    at: datetime


class FeedbackGrup(BaseModel):
    """Omul -> grupuri: votul unui om autentificat pe unul sau mai multe grupuri."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: int = LEARNING_SCHEMA_VERSION
    bucket_ids: list[str] = Field(min_length=1, max_length=200)
    label: Label
    user: str = Field(pattern=USER_RE)
    at: datetime


TOPICS: dict[str, type[BaseModel]] = {
    "cascada.decizie": DecizieCascada,
    "tier2.caz": CazDeInvestigat,
    "tier2.rezumat": RezumatTier2,
    "feedback.grup": FeedbackGrup,
    "model.tranzitie": Transition,
}

"""
ETICHETARE UMANA — logica pura, fara web si fara Elasticsearch.

Singurul loc din cod care construieste ground_truth si label_source="human".
Il apeleaza DOAR interfata de etichetare (label_ui.py), la actiunea unui om.
Niciun alt modul nu are voie sa scrie aceste campuri (vezi tests/test_labeling.py).

Omul spune ADEVARUL (attack | benign). Rezultatul TP/FP/FN/TN il calculeaza
codul, fata de verdict, cu aceeasi regula ca harness-ul: un verdict e "semnalat"
daca e malicious/suspicious sau daca actiunea nu inchide cazul.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Aceleasi multimi ca in harness.py (ALERT_CLASSES, NON_CLOSE_ACTIONS).
# Un test verifica ca outcome() si harness.score_verdict() dau acelasi rezultat.
FLAGGED_CLASSES = {"malicious", "suspicious"}
NON_CLOSE_ACTIONS = {"escalate_human", "block_ip_ttl", "freeze_process",
                     "quarantine_file", "isolate_host", "kill_process"}

# ID-urile generate de Elasticsearch: base64 url-safe, ~20 caractere.
DOC_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")   # permite \t si \n in note

GroundTruth = Literal["attack", "benign"]
Outcome = Literal["TP", "FP", "FN", "TN"]


class LabelInput(BaseModel):
    """Ce trimite omul din formular. Validat inainte de orice scriere."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    doc_id: str
    ground_truth: GroundTruth
    # Notele omului ajung, trunchiate, in contextul Tier 1 (lookup_history).
    # Scurte, fara caractere de control.
    notes: str = Field(default="", max_length=500)

    @field_validator("doc_id")
    @classmethod
    def _valid_doc_id(cls, v: str) -> str:
        if not DOC_ID_RE.match(v):
            raise ValueError("doc_id respins")
        return v

    @field_validator("notes")
    @classmethod
    def _clean_notes(cls, v: str) -> str:
        v = v.strip()
        if _CONTROL_RE.search(v):
            raise ValueError("caractere de control in note")
        return v


def is_flagged(classification: str | None, proposed_action: str | None) -> bool:
    return (classification in FLAGGED_CLASSES) or (proposed_action in NON_CLOSE_ACTIONS)


def outcome(verdict_doc: dict, ground_truth: GroundTruth) -> Outcome:
    """TP/FP/FN/TN pentru un verdict salvat in verdicts-history."""
    flagged = is_flagged(verdict_doc.get("classification"), verdict_doc.get("proposed_action"))
    if ground_truth == "attack":
        return "TP" if flagged else "FN"
    return "FP" if flagged else "TN"


def build_label_update(verdict_doc: dict, label: LabelInput, now: datetime) -> dict:
    """
    Campurile de scris in documentul din verdicts-history.

    Eticheta anterioara (daca exista) nu se pierde: trece in label_history,
    ca o reetichetare sa ramana auditabila.
    """
    history = list(verdict_doc.get("label_history") or [])
    if verdict_doc.get("ground_truth"):
        history.append({
            "ground_truth": verdict_doc.get("ground_truth"),
            "label_source": verdict_doc.get("label_source"),   # None la etichetele vechi
            "label_outcome": verdict_doc.get("label_outcome"),
            "labeled_at": verdict_doc.get("labeled_at"),
            "notes": verdict_doc.get("notes"),
        })
    return {
        "ground_truth": label.ground_truth,
        "label_source": "human",
        "label_outcome": outcome(verdict_doc, label.ground_truth),
        "labeled_at": now.isoformat(),
        "notes": label.notes or None,
        "label_history": history[-20:],
    }


# ------------------------------------------------------------------------------------------------
# Faza 24: eticheta pe GRUP (soc-buckets). Tot aici, singurul loc care construieste label_source.
# Grupul primeste VOTUL omului; verdictele (alertele) din grup NU primesc ground_truth (L2).
# ------------------------------------------------------------------------------------------------

USER_RE = re.compile(r"^[a-z][a-z0-9_.\-]{0,31}$")
BUCKET_RE = re.compile(r"^b[0-9a-f]{24}$")
MAX_BULK = 200


class BucketLabelInput(BaseModel):
    """Ce trimite omul pentru unul sau mai multe grupuri (etichetare in bloc)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    bucket_ids: list[str] = Field(min_length=1, max_length=MAX_BULK)
    label: GroundTruth
    notes: str = Field(default="", max_length=500)

    @field_validator("bucket_ids")
    @classmethod
    def _valid_ids(cls, v: list[str]) -> list[str]:
        out = []
        for b in v:
            if not BUCKET_RE.match(b or ""):
                raise ValueError("bucket_id respins")
            if b not in out:
                out.append(b)
        return out

    @field_validator("notes")
    @classmethod
    def _clean(cls, v: str) -> str:
        v = v.strip()
        if _CONTROL_RE.search(v):
            raise ValueError("caractere de control in note")
        return v


def build_bucket_vote(user: str, label: GroundTruth, notes: str, now: datetime) -> dict:
    """Votul unui om AUTENTIFICAT (user din sesiune/token, nu din formular). Il apeleaza doar
    label_ui, la actiunea omului; store/writer.add_bucket_vote doar il adauga in document."""
    if not USER_RE.match(user or ""):
        raise ValueError("utilizator respins")
    if label not in ("attack", "benign"):
        raise ValueError("eticheta respinsa")
    return {"user": user, "label": label, "label_source": "human", "at": now.isoformat(),
            "notes": (notes or "")[:500]}

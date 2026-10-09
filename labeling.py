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

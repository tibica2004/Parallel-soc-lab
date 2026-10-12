"""
RAG (Tier 1) — cazuri asemanatoare, etichetate de OM, aduse ca referinta.

Doua surse:
  1. kb/rag_cases.yml — cazuri de referinta in git, cu `reviewed: true` pus de
     om. Cele nerevizuite NU se folosesc.
  2. verdicts-history — verdicte cu label_source=human pe aceeasi regula
     (potrivire exacta pe rule_name.keyword). Optional: in studiul de ablatie e
     oprita, ca etichetele puse pe alertele generate de scenarii sa nu ajunga
     inapoi in evaluarea acelorasi scenarii.

Recuperarea e DETERMINISTA, pe trasaturi structurate (regula, parinte, proces,
tipul utilizatorului, fapte booleene), nu pe embeddings: se poate explica de ce
a fost ales un caz, iar textul din telemetrie nu influenteaza alegerea decat
prin campuri exacte. Modelul primeste cazurile ca REFERINTA, nu ca instructiuni.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

ROOT = Path(__file__).resolve().parent
CASES_FILE = ROOT / "kb" / "rag_cases.yml"
VERDICTS_IDX = "verdicts-history"

TOP_K = 3
MIN_SCORE = 5
FLAGS = ("sensitive_action", "ran_from_temp_dir", "webroot_executable_write", "in_maintenance_window")
WEIGHTS = {"rule": 3, "parent": 2, "process": 2, "user_class": 2}   # + 1 per fapt boolean egal
MAX_SCORE = sum(WEIGHTS.values()) + len(FLAGS)
HUMAN = "human"   # valoarea cautata in label_source (doar citire)


class RagCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^rag-\d{3,5}$")
    reviewed: bool
    ground_truth: Literal["attack", "benign"]
    rule: str = Field(max_length=256)
    parent: str = Field(max_length=64)
    process: str = Field(max_length=64)
    user_class: Literal["web_service", "admin", "other"]
    flags: list[Literal["sensitive_action", "ran_from_temp_dir", "webroot_executable_write",
                        "in_maintenance_window"]] = []
    situation: str = Field(max_length=300)
    lesson: str = Field(max_length=300)


def parse_cases(raw: dict | None) -> list[RagCase]:
    """Toate cazurile valideaza (o greseala in fisier opreste incarcarea —
    fisierul e scris de om, eroarea trebuie vazuta, nu sarita)."""
    cases = [RagCase(**c) for c in (raw or {}).get("cases") or []]
    ids = [c.id for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("id-uri duplicate in rag_cases.yml")
    return cases


@lru_cache(maxsize=1)
def load_cases() -> tuple[RagCase, ...]:
    """Doar cazurile revizuite de om."""
    raw = yaml.safe_load(CASES_FILE.read_text(encoding="utf-8"))
    return tuple(c for c in parse_cases(raw) if c.reviewed)


def user_class(ctx: dict) -> str:
    if ctx.get("ran_by_web_service_account"):
        return "web_service"
    if ctx.get("ran_by_known_admin"):
        return "admin"
    return "other"


def features(ctx: dict) -> dict:
    """Trasaturile cazului curent, din contextul calculat de cod (fast_path.build_context)."""
    ex = ctx.get("execution") or {}
    return {
        "rule": ctx.get("rule_name") or "",
        "parent": ex.get("parent") or "",
        "process": ex.get("process") or "",
        "user_class": user_class(ctx),
        "flags": {f for f in FLAGS if ctx.get(f)},
    }


def similarity(f: dict, c: RagCase) -> int:
    s = sum(w for k, w in WEIGHTS.items() if f[k] and f[k] == getattr(c, k))
    return s + sum(1 for fl in FLAGS if (fl in f["flags"]) == (fl in c.flags))


def retrieve(ctx: dict, cases: tuple[RagCase, ...] | None = None, k: int = TOP_K,
             min_score: int = MIN_SCORE) -> list[dict]:
    """Primele k cazuri peste prag, in ordinea scorului (la egalitate, dupa id)."""
    cases = load_cases() if cases is None else cases
    f = features(ctx)
    scored = sorted(((similarity(f, c), c) for c in cases), key=lambda sc: (-sc[0], sc[1].id))
    return [{"case_id": c.id, "similarity": round(s / MAX_SCORE, 2), "ground_truth": c.ground_truth,
             "same_rule": c.rule == f["rule"], "situation": c.situation, "lesson": c.lesson}
            for s, c in scored[:k] if s >= min_score]


def human_history(es, rule_name: str, k: int = TOP_K) -> list[dict]:
    """Verdicte etichetate de om pe aceeasi regula (potrivire exacta). Doar citire."""
    if not rule_name:
        return []
    try:
        r = es.search(index=VERDICTS_IDX, size=k, sort=[{"@timestamp": "desc"}],
                      source=["classification", "label_outcome", "ground_truth", "notes"],
                      query={"bool": {"filter": [
                          {"term": {"rule_name.keyword": rule_name}},
                          {"term": {"label_source": HUMAN}},
                      ]}})
    except Exception:
        return []
    out = []
    for h in r["hits"]["hits"]:
        s = h["_source"]
        out.append({"source": "verdicts-history", "ground_truth": s.get("ground_truth"),
                    "system_said": s.get("classification"), "outcome": s.get("label_outcome"),
                    "human_note": (s.get("notes") or "")[:160]})
    return out

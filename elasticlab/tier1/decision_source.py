"""Sursa de decizie a pasului 3 din cascada (faza 24): o interfata, doua implementari.

  OwnModelSource       clasificatorul propriu (core/classifier.py), incarcat din registru cu hash
  ExternalFieldSource  un camp scris pe alerta de alt sistem (ex. Arcanna), din config/pipelines.yml

Alegerea e din configurare (`decision_source`). Ambele intorc aceeasi forma (contracts.Prediction) si
trec prin ACEEASI cascada (core/cascade.py), deci respecta aceleasi linii rosii: nu pot inchide o
clasa critica, nici un caz cu podea, iar inchiderea are efect doar pe pipeline activ, in modul on.
Campul extern e telemetrie (date, nu instructiuni): doar se cauta intr-un dictionar fix de valori.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol

from elasticlab.contracts.learning import (ExternalSourceConfig, ModelDecision, ModelState,
                                           Prediction)
from elasticlab.core import classifier


class DecisionSource(Protocol):
    kind: str
    model_hash: str | None
    state: ModelState | None

    def predict(self, values: dict[str, str], alert: dict) -> Prediction | None: ...


class OwnModelSource:
    kind = "own_model"

    def __init__(self, artifact: dict, model_hash: str, state: ModelState):
        classifier.validate_artifact(artifact)
        self.artifact = artifact
        self.model_hash = model_hash
        self.state = state

    def predict(self, values: dict[str, str], alert: dict) -> Prediction | None:
        return classifier.predict(self.artifact, values, self.model_hash)


def _g(d: dict, path: str) -> Any:
    if path in d:
        return d[path]
    cur: Any = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def external_hash(cfg: ExternalSourceConfig) -> str:
    """Identitatea sursei externe (pentru registru si regresie): hash-ul configurarii ei."""
    return hashlib.sha256(json.dumps(cfg.model_dump(), sort_keys=True).encode()).hexdigest()


class ExternalFieldSource:
    kind = "external"

    def __init__(self, cfg: ExternalSourceConfig, state: ModelState | None = None):
        self.cfg = cfg
        self.model_hash = external_hash(cfg)
        self.state = state
        self.values = {str(k).strip().lower(): v for k, v in cfg.values.items()}

    def predict(self, values: dict[str, str], alert: dict) -> Prediction | None:
        raw = _g(alert, self.cfg.decision_field)
        if isinstance(raw, list):
            raw = raw[0] if raw else None
        if raw is None:
            return None                       # campul lipseste: pasul 4
        label = self.values.get(str(raw).strip().lower()[:64])
        conf = 0
        if self.cfg.confidence_field:
            c = _g(alert, self.cfg.confidence_field)
            try:
                c = float(c[0] if isinstance(c, list) else c)
                conf = int(round(c * 100 if 0.0 <= c <= 1.0 else c))
            except (TypeError, ValueError):
                conf = 0
        conf = max(0, min(100, conf))
        if label == "benign":
            dec = ModelDecision.BENIGN
        elif label == "attack":
            dec = ModelDecision.ATTACK
        else:
            dec = ModelDecision.UNCERTAIN
        return Prediction(source="external", model_hash=self.model_hash, decision=dec,
                          confidence=conf, p_attack=None, outlier=False)

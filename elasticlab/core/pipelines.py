"""Configurarea pipeline-urilor (config/pipelines.yml, in git) si potrivirea alerta -> pipeline.

Incarcarea valideaza forma (contracts.learning.PipelinesConfig, extra=forbid) si ca fiecare punct
de decizie exista in catalog. O regula poate apartine unui singur pipeline (altfel grupurile s-ar
dubla); o configurare invalida ridica exceptie (cascada trece atunci la pasul 4, L6).
"""
from __future__ import annotations

from pathlib import Path

import yaml

from elasticlab.contracts.learning import PipelineConfig, PipelinesConfig
from elasticlab.core.decision_points import CATALOG
from elasticlab.paths import REPO_ROOT

CONFIG_PATH = REPO_ROOT / "config" / "pipelines.yml"


def parse(data: dict) -> PipelinesConfig:
    cfg = PipelinesConfig.model_validate(data)
    seen: dict[str, str] = {}
    ids: set[str] = set()
    for p in cfg.pipelines:
        if p.id in ids:
            raise ValueError(f"pipeline duplicat: {p.id}")
        ids.add(p.id)
        for d in p.decision_points:
            if d not in CATALOG:
                raise ValueError(f"{p.id}: punct de decizie necunoscut {d!r}")
        if p.decision_source == "external" and p.external is None:
            raise ValueError(f"{p.id}: decision_source=external cere sectiunea external")
        for r in p.rules:
            if r in seen:
                raise ValueError(f"regula {r!r} e in doua pipeline-uri: {seen[r]}, {p.id}")
            seen[r] = p.id
    return cfg


def load(path: Path | None = None) -> PipelinesConfig:
    with open(path or CONFIG_PATH, encoding="utf-8") as f:
        return parse(yaml.safe_load(f) or {})


def pipeline_for(cfg: PipelinesConfig, rule_name: str | None) -> PipelineConfig | None:
    if not rule_name:
        return None
    for p in cfg.pipelines:
        if rule_name in p.rules:
            return p
    return None


def by_id(cfg: PipelinesConfig, pid: str) -> PipelineConfig | None:
    return next((p for p in cfg.pipelines if p.id == pid), None)

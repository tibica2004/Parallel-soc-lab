"""Radacina depozitului (faza 24).

Modulele mutate in elasticlab/ nu mai pot folosi Path(__file__).parent ca radacina: kb/, prompts/,
detections/, data/, templates/, static/, results/ si scenariile raman in radacina depozitului."""
from __future__ import annotations

from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parent.parent

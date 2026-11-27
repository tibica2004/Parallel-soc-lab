"""Registrul modelelor (faza 24): artefacte ca DATE (JSON, fara cod executabil) si manifestul cu hash.

Pe disc, in data/models (SOC_MODELS_DIR), nu in git (data/ e ignorat): modelele se reantreneaza orar
si sunt reproductibile din etichete (antrenare determinista).

    data/models/<pipeline>/<sha256>.json   artefactul, JSON canonic; numele = sha256 al continutului
    data/models/MANIFEST.json              ModelRecord pentru fiecare model + istoricul tranzitiilor
                                           + rezultatele regresiei pe setul de aur

La incarcare, hash-ul continutului se recalculeaza si se compara cu numele si cu manifestul; o
nepotrivire inseamna ca modelul nu se foloseste (cascada trece la pasul 4, L6) si controlorul il
retrogradeaza. Scrierea manifestului e atomica (fisier temporar + rename). Doar tier3 (controlorul)
si comanda de revenire scriu; orchestratorul doar citeste.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from elasticlab.contracts.learning import ModelRecord, ModelState, Transition
from elasticlab.core import classifier
from elasticlab.paths import REPO_ROOT

MANIFEST_VERSION = 1


class HashMismatch(Exception):
    """Continutul artefactului nu corespunde hash-ului din nume/manifest."""


def models_dir(env=None) -> Path:
    env = env if env is not None else os.environ
    return Path(env.get("SOC_MODELS_DIR") or REPO_ROOT / "data" / "models")


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def artifact_path(root: Path, pipeline: str, model_hash: str) -> Path:
    return root / pipeline / f"{model_hash}.json"


def save_artifact(root: Path, artifact: dict) -> str:
    classifier.validate_artifact(artifact)
    h = classifier.artifact_hash(artifact)
    p = artifact_path(root, artifact["pipeline"], h)
    if not p.exists():
        _atomic_write(p, classifier.canonical_json(artifact))
    return h


def load_artifact(root: Path, pipeline: str, model_hash: str) -> dict:
    p = artifact_path(root, pipeline, model_hash)
    art = json.loads(p.read_text(encoding="utf-8"))
    classifier.validate_artifact(art)
    if classifier.artifact_hash(art) != model_hash:
        raise HashMismatch(f"{pipeline}/{model_hash[:12]}")
    return art


def empty_manifest() -> dict:
    return {"version": MANIFEST_VERSION, "models": [], "transitions": [], "regressions": []}


def load_manifest(root: Path) -> dict:
    p = root / "MANIFEST.json"
    if not p.exists():
        return empty_manifest()
    m = json.loads(p.read_text(encoding="utf-8"))
    for k, v in empty_manifest().items():
        m.setdefault(k, v)
    return m


def save_manifest(root: Path, manifest: dict) -> None:
    _atomic_write(root / "MANIFEST.json", json.dumps(manifest, indent=1, sort_keys=True, default=str) + "\n")


def records(manifest: dict, pipeline: str | None = None) -> list[ModelRecord]:
    out = [ModelRecord.model_validate(r) for r in manifest.get("models", [])]
    return [r for r in out if pipeline is None or r.pipeline == pipeline]


def find(manifest: dict, pipeline: str, model_hash: str) -> ModelRecord | None:
    return next((r for r in records(manifest, pipeline) if r.model_hash == model_hash), None)


def in_state(manifest: dict, pipeline: str, state: ModelState) -> ModelRecord | None:
    """Cel mai recent model din starea ceruta (cel mult unul activ si unul in umbra per pipeline)."""
    rs = [r for r in records(manifest, pipeline) if r.state is state]
    return max(rs, key=lambda r: (r.state_since, r.model_hash)) if rs else None


def upsert(manifest: dict, rec: ModelRecord) -> None:
    rows = [r for r in manifest["models"]
            if not (r["pipeline"] == rec.pipeline and r["model_hash"] == rec.model_hash)]
    rows.append(rec.model_dump(mode="json"))
    manifest["models"] = sorted(rows, key=lambda r: (r["pipeline"], r["trained_at"], r["model_hash"]))


def apply_transition(manifest: dict, t: Transition) -> ModelRecord:
    rec = find(manifest, t.pipeline, t.model_hash)
    if rec is None:
        raise KeyError(f"model necunoscut: {t.pipeline}/{t.model_hash[:12]}")
    rec.state = t.to_state
    rec.state_since = t.at
    if t.to_state is ModelState.ACTIVE:
        rec.ever_active = True
    upsert(manifest, rec)
    manifest["transitions"].append(t.model_dump(mode="json"))
    manifest["transitions"] = manifest["transitions"][-2000:]
    return rec


def rollback(root: Path, manifest: dict, pipeline: str, model_hash: str, now: datetime) -> list[Transition]:
    """Revenirea la o versiune anterioara (comanda omului): modelul cerut, care a mai fost activ si
    al carui hash se verifica, devine activ; cel activ acum trece in umbra. Nu ocoleste controlorul:
    acesta il retrogradeaza la urmatoarea rulare daca un declansator se aplica."""
    target = find(manifest, pipeline, model_hash)
    if target is None:
        raise KeyError(f"model necunoscut: {pipeline}/{model_hash[:12]}")
    if not target.ever_active:
        raise ValueError("revenirea e permisa doar la un model care a mai fost activ")
    load_artifact(root, pipeline, model_hash)          # verifica hash-ul inainte de orice schimbare
    out: list[Transition] = []
    cur = in_state(manifest, pipeline, ModelState.ACTIVE)
    if cur is not None and cur.model_hash == model_hash:
        return out
    if cur is not None:
        out.append(Transition(pipeline=pipeline, model_hash=cur.model_hash, from_state=cur.state,
                              to_state=ModelState.SHADOW, reason="revenire la o versiune anterioara",
                              at=now, actor="human"))
    sh = in_state(manifest, pipeline, ModelState.SHADOW)
    if sh is not None and sh.model_hash not in (model_hash, getattr(cur, "model_hash", None)):
        out.append(Transition(pipeline=pipeline, model_hash=sh.model_hash, from_state=sh.state,
                              to_state=ModelState.RETIRED, reason="inlocuit la revenire", at=now,
                              actor="human"))
    out.append(Transition(pipeline=pipeline, model_hash=model_hash, from_state=target.state,
                          to_state=ModelState.ACTIVE, reason="revenire ceruta de om", at=now,
                          actor="human"))
    for t in out:
        apply_transition(manifest, t)
    return out


def record_regression(manifest: dict, *, pipeline: str, model_hash: str, prompt_set: str | None,
                      passed: bool, at: datetime, details: dict) -> None:
    manifest["regressions"].append({"pipeline": pipeline, "model_hash": model_hash,
                                    "prompt_set": prompt_set, "passed": bool(passed),
                                    "at": at.isoformat(), "details": details})
    manifest["regressions"] = manifest["regressions"][-500:]


def last_regression(manifest: dict, pipeline: str, model_hash: str, prompt_set: str | None) -> dict | None:
    """Ultima regresie pentru ACEST model si ACEST set de prompturi (alt prompt_set = nu conteaza)."""
    rs = [r for r in manifest.get("regressions", [])
          if r["pipeline"] == pipeline and r["model_hash"] == model_hash and r["prompt_set"] == prompt_set]
    return rs[-1] if rs else None

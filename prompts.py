#!/usr/bin/env python3
"""
VERSIONAREA PROMPTURILOR (pasul 8.2) — orice schimbare de prompt e vizibila si deliberata.

Prompturile raman in cod (constantele de mai jos), dar fiecare are sha256 in prompts/MANIFEST.json,
cu o versiune. La pornire, orchestratorul verifica: un prompt schimbat fara bump de versiune ->
refuza sa porneasca, cu mesaj clar in jurnal si pe Discord. Fiecare verdict si fiecare ciclu poarta
`prompt_set` = rezumatul setului curent, ca rezultatele sa se poata lega de prompturile exacte.

  python prompts.py --check                         # 0 = la zi, 1 = schimbat fara bump
  python prompts.py --update --reason "de ce"       # bump versiunile schimbate + CHANGELOG
Inainte de --update: `make regression` (pasul 8.3) pe setul de aur.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "prompts" / "MANIFEST.json"
CHANGELOG = ROOT / "prompts" / "CHANGELOG.md"

# nume -> (modul, constanta) sau ("file", cale relativa)
REGISTRY: dict[str, tuple[str, str]] = {
    "fast.fact_rules": ("fast_path", "FACT_RULES"),
    "fast.pattern": ("fast_path", "PATTERN_PROMPT"),
    "fast.verdict": ("fast_path", "VERDICT_PROMPT"),
    "fast.extended_rules": ("fast_path", "EXTENDED_RULES"),
    "fast.l1_agent": ("l1_agent", "L1_PROMPT"),
    "hunt.investigator": ("hunt_path", "HUNT_PROMPT"),
    "hunt.secondary_note": ("hunt_path", "SECONDARY_NOTE"),
    "hunt.primary_note": ("hunt_path", "PRIMARY_NOTE"),
    "hunt.tier1_note": ("hunt_path", "TIER1_NOTE"),
    "hunt.fact_rules": ("hunt_path", "HUNT_FACT_RULES"),
    "hunt.case_note": ("hunt_path", "HUNT_NOTE"),
    "tier3.hunt_plan": ("hunt", "PLAN_PROMPT"),
    "tier3.rule_draft": ("rules", "DRAFT_PROMPT"),
    "tier3.incident_narrative": ("tier3", "NARRATIVE_PROMPT"),
    "static.triage": ("file", "prompts/static_triage.v2.txt"),
}


def _text(src: tuple[str, str]) -> str:
    mod, name = src
    if mod == "file":
        return (ROOT / name).read_text(encoding="utf-8")
    return getattr(importlib.import_module(mod), name)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def current() -> dict[str, str]:
    return {k: sha(_text(v)) for k, v in REGISTRY.items()}


def load_manifest(path: Path = MANIFEST) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {"prompts": {}}


def diff(manifest: dict, now: dict[str, str]) -> list[str]:
    """Prompturile al caror hash difera de manifest (sau lipsesc din el). Pur."""
    known = manifest.get("prompts", {})
    return sorted(k for k, h in now.items() if (known.get(k) or {}).get("sha256") != h)


def prompt_set(hashes: dict[str, str]) -> str:
    """Rezumatul setului: un singur identificator scurt pentru verdicte si cicluri. Pur."""
    return sha(json.dumps(sorted(hashes.items())))[:12]


def bump(manifest: dict, now: dict[str, str], reason: str, when: str) -> tuple[dict, list[str]]:
    """Versiune +1 pentru fiecare prompt schimbat; cele noi pornesc de la v1. Pur."""
    out = {"prompts": dict(manifest.get("prompts", {}))}
    removed = sorted(k for k in out["prompts"] if k not in now)
    changed = diff(manifest, now) + [f"{k} (sters)" for k in removed]
    for k in diff(manifest, now):
        v = int((out["prompts"].get(k) or {}).get("version", 0)) + 1
        out["prompts"][k] = {"version": v, "sha256": now[k], "updated": when, "reason": reason[:300]}
    for k in list(out["prompts"]):
        if k not in now:
            del out["prompts"][k]
    out["prompt_set"] = prompt_set(now)
    return out, changed


def verify() -> tuple[bool, list[str], str]:
    now = current()
    bad = diff(load_manifest(), now)
    return (not bad), bad, prompt_set(now)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--update", action="store_true")
    ap.add_argument("--reason", default="")
    a = ap.parse_args(argv)
    now = current()
    if a.check:
        bad = diff(load_manifest(), now)
        print(f"prompt_set={prompt_set(now)}; " + (f"SCHIMBATE fara bump: {bad}" if bad else "la zi"))
        return 1 if bad else 0
    if not a.reason.strip():
        print("--update cere --reason (motivul intra in MANIFEST si CHANGELOG)")
        return 2
    when = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    new, changed = bump(load_manifest(), now, a.reason, when)
    if not changed:
        print("nimic schimbat")
        return 0
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(new, indent=1, sort_keys=True) + "\n")
    with CHANGELOG.open("a", encoding="utf-8") as f:
        f.write(f"\n## {when} — prompt_set {new['prompt_set']}\n"
                + "".join((f"- {k}\n" if k.endswith(" (sters)") else f"- {k} -> v{new['prompts'][k]['version']}\n")
                          for k in changed)
                + f"Motiv: {a.reason}\n")
    print(f"actualizat: {changed}; prompt_set={new['prompt_set']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

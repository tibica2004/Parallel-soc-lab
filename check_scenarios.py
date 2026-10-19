#!/usr/bin/env python3
"""
VALIDATORUL SETULUI DE ABLATIE — verificari de format, inainte de orice rulare.

Nu ruleaza nimic pe web-prod si nu cheama modelul. Verifica:
  - structura: lista `scenarios`, campuri obligatorii, campuri necunoscute;
  - valori: path = fast, ground_truth = attack|benign, rule_name dintre regulile
    cunoscute (sau, cu --es, dintre cele care au produs alerte in ultimele 30 zile),
    injection = bool, generate = text nevid pe un singur rand;
  - nume unice; comenzi `generate` repetate (avertisment);
  - separarea de RAG: niciun nume sau comanda din scenarii in kb/rag_cases.yml;
  - echilibrul: atacuri / benigne / injectie, per regula si total.

Erorile opresc (cod 1); avertismentele doar se afiseaza.

    python3 check_scenarios.py                       # scenarios_ablation.yml
    python3 check_scenarios.py alt.yml --es          # si regulile reale din ES
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
RAG_FILE = ROOT / "kb" / "rag_cases.yml"
OTHER_SETS = ("scenarios.yml", "scenarios_fast.yml", "scenarios_validation.yml")

# Regulile care au produs alerte in laborator (EQL proprii + Defend nativ).
KNOWN_RULES = {
    "RCE: Web server spawns shell",
    "Webshell: Executable written to webroot",
    "Reverse shell: Interactive shell or /dev/tcp connection",
    "Payload download: curl/wget spawned by web server or shell",
    "Suspicious execution from temp directory",
    "Malicious Behavior Detection Alert: Payload Execution by Web Server",
}
REQUIRED = ("name", "path", "ground_truth", "rule_name", "generate")
ALLOWED = set(REQUIRED) | {"injection", "notes", "validation"}
MIN_TOTAL = 10


def check(data, rules: set[str], rag_text: str = "", other_names: set[str] = frozenset()
          ) -> tuple[list[str], list[str], dict]:
    """Functie pura. Intoarce (erori, avertismente, sumar)."""
    errors, warnings = [], []
    if not isinstance(data, dict) or not isinstance(data.get("scenarios"), list):
        return ["fisierul trebuie sa aiba o lista `scenarios`"], [], {}
    scs = data["scenarios"]
    names = Counter()
    gens = Counter()
    per_rule = defaultdict(Counter)
    totals = Counter()
    rag_low = rag_text.lower()

    for i, sc in enumerate(scs, 1):
        where = f"scenariul {i}"
        if not isinstance(sc, dict):
            errors.append(f"{where}: nu e un dictionar")
            continue
        name = sc.get("name")
        if isinstance(name, str) and name.strip():
            where = f"scenariul {i} ({name!r})"
            names[name.strip()] += 1
        for k in REQUIRED:
            if k not in sc or sc[k] in (None, ""):
                errors.append(f"{where}: lipseste `{k}`")
        for k in set(sc) - ALLOWED:
            errors.append(f"{where}: camp necunoscut `{k}`")
        if sc.get("path") not in (None, "", "fast"):
            errors.append(f"{where}: path={sc.get('path')!r} (setul de ablatie e doar pe calea rapida)")
        gt = sc.get("ground_truth")
        if gt not in (None, "") and gt not in ("attack", "benign"):
            errors.append(f"{where}: ground_truth={gt!r} (attack|benign)")
        rule = sc.get("rule_name")
        if rule not in (None, "") and rule not in rules:
            errors.append(f"{where}: rule_name necunoscut {rule!r}")
        inj = sc.get("injection", False)
        if not isinstance(inj, bool):
            errors.append(f"{where}: injection trebuie sa fie true/false")
            inj = False
        gen = sc.get("generate")
        if gen not in (None, ""):
            if not isinstance(gen, str) or not gen.strip():
                errors.append(f"{where}: generate trebuie sa fie text nevid")
            elif "\n" in gen.strip():
                errors.append(f"{where}: generate pe un singur rand")
            else:
                gens[gen.strip()] += 1
                # separarea de RAG: comanda nu are voie sa apara in cazurile de referinta
                if rag_low and gen.strip().lower() in rag_low:
                    errors.append(f"{where}: comanda `generate` apare in {RAG_FILE.name}")
        if isinstance(name, str) and name.strip():
            if rag_low and name.strip().lower() in rag_low:
                errors.append(f"{where}: numele apare in {RAG_FILE.name}")
            if name.strip() in other_names:
                warnings.append(f"{where}: acelasi nume exista si in alt set de scenarii")
        if gt in ("attack", "benign"):
            kind = "injection" if inj else gt
            totals[kind] += 1
            per_rule[rule or "?"][kind] += 1

    for n, c in names.items():
        if c > 1:
            errors.append(f"numele {n!r} apare de {c} ori")
    for g, c in gens.items():
        if c > 1:
            warnings.append(f"comanda `generate` repetata de {c} ori: {g[:80]}")

    n_total = sum(totals.values())
    if n_total < MIN_TOTAL:
        warnings.append(f"doar {n_total} scenarii valide (minim recomandat {MIN_TOTAL})")
    if not totals["benign"]:
        warnings.append("niciun scenariu benign: rata de fals pozitive nu se poate masura")
    if not totals["attack"] + totals["injection"]:
        warnings.append("niciun atac: recall-ul nu se poate masura")
    for r, c in sorted(per_rule.items()):
        if not c["benign"]:
            warnings.append(f"regula {r!r}: fara scenariu benign")
    summary = {"total": n_total, **{k: totals[k] for k in ("attack", "benign", "injection")},
               "per_rule": {r: dict(c) for r, c in sorted(per_rule.items())}}
    return errors, warnings, summary


def rules_from_es(days: int = 30) -> set[str]:
    """Numele regulilor care au produs alerte in ultimele `days` zile (cheia read-only)."""
    from elastic_tools import ES
    r = ES.search(index=".alerts-security.alerts-*", size=0,
                  query={"range": {"@timestamp": {"gte": f"now-{int(days)}d"}}},
                  aggs={"r": {"terms": {"field": "kibana.alert.rule.name", "size": 500}}})
    return {b["key"] for b in r["aggregations"]["r"]["buckets"]}


def other_set_names(skip: Path) -> set[str]:
    out = set()
    for f in OTHER_SETS:
        p = ROOT / f
        if p.resolve() == skip.resolve() or not p.exists():
            continue
        d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        out |= {str(s.get("name")).strip() for s in d.get("scenarios", []) if isinstance(s, dict)}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("fisier", nargs="?", default="scenarios_ablation.yml")
    ap.add_argument("--es", action="store_true", help="accepta si regulile cu alerte reale din ES")
    a = ap.parse_args()
    path = Path(a.fisier)
    if not path.is_absolute():
        path = ROOT / path
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        print(f"EROARE: nu pot citi {path.name}: {e}")
        return 1
    rules = set(KNOWN_RULES)
    if a.es:
        rules |= rules_from_es()
    rag = RAG_FILE.read_text(encoding="utf-8") if RAG_FILE.exists() else ""
    errors, warns, summ = check(data, rules, rag, other_set_names(path))

    print(f"{path.name}: {summ.get('total', 0)} scenarii — atacuri {summ.get('attack', 0)}, "
          f"benigne {summ.get('benign', 0)}, injectie {summ.get('injection', 0)}")
    for r, c in (summ.get("per_rule") or {}).items():
        print(f"  {r}: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))
    for w in warns:
        print(f"AVERTISMENT: {w}")
    for e in errors:
        print(f"EROARE: {e}")
    print("OK" if not errors else f"{len(errors)} erori")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

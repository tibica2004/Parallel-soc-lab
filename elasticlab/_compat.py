"""Vechile cai ale modulelor mutate in faza 24 (docs/plan-refactorizare.md). Se scoate in faza 33.

La fiecare cale veche (`fast_path.py` in radacina) a ramas un fisier subtire care cheama `alias()`:
`import fast_path` intoarce ACELASI obiect de modul ca `elasticlab.tier1.fast_path` (nu o copie si
nu `import *`), deci monkeypatch-ul din teste, starea la nivel de modul si `importlib.reload` se
comporta ca inainte. Scripturile rulate direct (`python orchestrator.py`, ExecStart) trec prin
`run_main()`, care executa modulul nou ca `__main__`, exact cum se executa inainte fisierul vechi.
"""
from __future__ import annotations

import importlib.util
import runpy
import sys
from types import ModuleType

# cale veche (nume de modul in radacina) -> modulul nou. Sursa unica pentru fisierele subtiri si teste.
MOVED: dict[str, str] = {
    "schemas": "elasticlab.contracts.schemas",
    "degraded": "elasticlab.core.degraded",
    "escalation": "elasticlab.core.escalation",
    "executor": "elasticlab.core.executor",
    "honeytokens": "elasticlab.core.honeytokens",
    "llm": "elasticlab.core.llm",
    "maintenance": "elasticlab.core.maintenance",
    "policy": "elasticlab.core.policy",
    "prompts": "elasticlab.core.prompts",
    "sdnotify": "elasticlab.core.sdnotify",
    "tracing": "elasticlab.core.tracing",
    "benign_gen": "elasticlab.extras.benign_gen",
    "build_whitelists": "elasticlab.extras.build_whitelists",
    "exposure": "elasticlab.extras.exposure",
    "nday_watch": "elasticlab.extras.nday_watch",
    "static_triage": "elasticlab.extras.static_triage",
    "wp_inventory": "elasticlab.extras.wp_inventory",
    "absence_check": "elasticlab.ops.absence_check",
    "cycle_metrics": "elasticlab.ops.cycle_metrics",
    "fp_rate": "elasticlab.ops.fp_rate",
    "llm_probe": "elasticlab.ops.llm_probe",
    "metrics": "elasticlab.ops.metrics",
    "notify": "elasticlab.ops.notify",
    "reader": "elasticlab.ops.reader",
    "readiness": "elasticlab.ops.readiness",
    "cases": "elasticlab.store.cases",
    "state": "elasticlab.store.state",
    "behavioral_rules": "elasticlab.tier1.behavioral_rules",
    "defend_native": "elasticlab.tier1.defend_native",
    "enrich": "elasticlab.tier1.enrich",
    "fast_path": "elasticlab.tier1.fast_path",
    "l1_agent": "elasticlab.tier1.l1_agent",
    "rag": "elasticlab.tier1.rag",
    "sensor_rules": "elasticlab.tier1.sensor_rules",
    "threat_intel": "elasticlab.tier1.threat_intel",
    "anomalies": "elasticlab.tier2.anomalies",
    "case_adapter": "elasticlab.tier2.case_adapter",
    "elastic_tools": "elasticlab.tier2.elastic_tools",
    "hunt_path": "elasticlab.tier2.hunt_path",
    "risk": "elasticlab.tier2.risk",
    "hunt": "elasticlab.tier3.hunt",
    "incidents": "elasticlab.tier3.incidents",
    "kibana_rules": "elasticlab.tier3.kibana_rules",
    "rules": "elasticlab.tier3.rules",
    "tier3": "elasticlab.tier3.tier3",
}


def alias(old: str, new: str) -> ModuleType:
    """Leaga numele vechi de modulul nou. Daca modulul nou nu e inca incarcat, il inregistreaza sub
    AMBELE nume inainte sa-l execute: un import circular care trece prin numele vechi primeste
    modulul real (partial initializat, ca la orice import circular), nu fisierul subtire."""
    mod = sys.modules.get(new)
    if mod is None:
        spec = importlib.util.find_spec(new)
        if spec is None or spec.loader is None:
            raise ModuleNotFoundError(f"lipseste modulul {new} (aliasat de {old})", name=new)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[new] = mod
        sys.modules[old] = mod
        try:
            spec.loader.exec_module(mod)
        except BaseException:
            sys.modules.pop(new, None)
            raise
        parent, _, child = new.rpartition(".")
        setattr(sys.modules[parent], child, mod)
    sys.modules[old] = mod
    return mod


def run_main(new: str) -> None:
    """`python <cale veche>.py ...`: ruleaza modulul nou ca `__main__` (blocul lui `if __name__ ==
    "__main__"` decide codul de iesire, ca inainte). sys.argv[1:] raman neschimbate."""
    runpy.run_module(new, run_name="__main__", alter_sys=True)

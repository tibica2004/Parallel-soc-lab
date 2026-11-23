"""Cale veche (faza 24): modulul e acum elasticlab/apps/orchestrator.py.

Fisier subtire: `python orchestrator.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import orchestrator` da ACELASI obiect de modul ca `elasticlab.apps.orchestrator` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.apps.orchestrator")
else:
    alias(__name__, "elasticlab.apps.orchestrator")

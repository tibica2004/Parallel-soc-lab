"""Cale veche (faza 24): modulul e acum elasticlab/extras/static_triage.py.

Fisier subtire: `python static_triage.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import static_triage` da ACELASI obiect de modul ca `elasticlab.extras.static_triage` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.extras.static_triage")
else:
    alias(__name__, "elasticlab.extras.static_triage")

"""Cale veche (faza 24): modulul e acum elasticlab/ops/absence_check.py.

Fisier subtire: `python absence_check.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import absence_check` da ACELASI obiect de modul ca `elasticlab.ops.absence_check` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.ops.absence_check")
else:
    alias(__name__, "elasticlab.ops.absence_check")

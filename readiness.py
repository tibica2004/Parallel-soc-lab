"""Cale veche (faza 24): modulul e acum elasticlab/ops/readiness.py.

Fisier subtire: `python readiness.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import readiness` da ACELASI obiect de modul ca `elasticlab.ops.readiness` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.ops.readiness")
else:
    alias(__name__, "elasticlab.ops.readiness")

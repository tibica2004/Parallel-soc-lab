"""Cale veche (faza 24): modulul e acum elasticlab/ops/fp_rate.py.

Fisier subtire: `python fp_rate.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import fp_rate` da ACELASI obiect de modul ca `elasticlab.ops.fp_rate` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.ops.fp_rate")
else:
    alias(__name__, "elasticlab.ops.fp_rate")

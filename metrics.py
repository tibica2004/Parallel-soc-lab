"""Cale veche (faza 24): modulul e acum elasticlab/ops/metrics.py.

Fisier subtire: `python metrics.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import metrics` da ACELASI obiect de modul ca `elasticlab.ops.metrics` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.ops.metrics")
else:
    alias(__name__, "elasticlab.ops.metrics")

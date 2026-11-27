"""Cale veche (faza 24): modulul e acum elasticlab/eval/coverage.py.

Fisier subtire: `python coverage.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import coverage` da ACELASI obiect de modul ca `elasticlab.eval.coverage` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.eval.coverage")
else:
    alias(__name__, "elasticlab.eval.coverage")

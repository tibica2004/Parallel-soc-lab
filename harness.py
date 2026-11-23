"""Cale veche (faza 24): modulul e acum elasticlab/eval/harness.py.

Fisier subtire: `python harness.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import harness` da ACELASI obiect de modul ca `elasticlab.eval.harness` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.eval.harness")
else:
    alias(__name__, "elasticlab.eval.harness")

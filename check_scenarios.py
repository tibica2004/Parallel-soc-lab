"""Cale veche (faza 24): modulul e acum elasticlab/eval/check_scenarios.py.

Fisier subtire: `python check_scenarios.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import check_scenarios` da ACELASI obiect de modul ca `elasticlab.eval.check_scenarios` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.eval.check_scenarios")
else:
    alias(__name__, "elasticlab.eval.check_scenarios")

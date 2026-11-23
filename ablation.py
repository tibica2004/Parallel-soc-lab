"""Cale veche (faza 24): modulul e acum elasticlab/eval/ablation.py.

Fisier subtire: `python ablation.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import ablation` da ACELASI obiect de modul ca `elasticlab.eval.ablation` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.eval.ablation")
else:
    alias(__name__, "elasticlab.eval.ablation")

"""Cale veche (faza 24): modulul e acum elasticlab/tier3/tier3.py.

Fisier subtire: `python tier3.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import tier3` da ACELASI obiect de modul ca `elasticlab.tier3.tier3` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.tier3.tier3")
else:
    alias(__name__, "elasticlab.tier3.tier3")

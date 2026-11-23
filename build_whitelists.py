"""Cale veche (faza 24): modulul e acum elasticlab/extras/build_whitelists.py.

Fisier subtire: `python build_whitelists.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import build_whitelists` da ACELASI obiect de modul ca `elasticlab.extras.build_whitelists` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.extras.build_whitelists")
else:
    alias(__name__, "elasticlab.extras.build_whitelists")

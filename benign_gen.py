"""Cale veche (faza 24): modulul e acum elasticlab/extras/benign_gen.py.

Fisier subtire: `python benign_gen.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import benign_gen` da ACELASI obiect de modul ca `elasticlab.extras.benign_gen` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.extras.benign_gen")
else:
    alias(__name__, "elasticlab.extras.benign_gen")

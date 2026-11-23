"""Cale veche (faza 24): modulul e acum elasticlab/extras/nday_watch.py.

Fisier subtire: `python nday_watch.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import nday_watch` da ACELASI obiect de modul ca `elasticlab.extras.nday_watch` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.extras.nday_watch")
else:
    alias(__name__, "elasticlab.extras.nday_watch")

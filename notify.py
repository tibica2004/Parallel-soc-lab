"""Cale veche (faza 24): modulul e acum elasticlab/ops/notify.py.

Fisier subtire: `python notify.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import notify` da ACELASI obiect de modul ca `elasticlab.ops.notify` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.ops.notify")
else:
    alias(__name__, "elasticlab.ops.notify")

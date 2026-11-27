"""Cale veche (faza 24): modulul e acum elasticlab/apps/label_ui.py.

Fisier subtire: `python label_ui.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import label_ui` da ACELASI obiect de modul ca `elasticlab.apps.label_ui` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.apps.label_ui")
else:
    alias(__name__, "elasticlab.apps.label_ui")

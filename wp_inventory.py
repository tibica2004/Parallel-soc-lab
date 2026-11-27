"""Cale veche (faza 24): modulul e acum elasticlab/extras/wp_inventory.py.

Fisier subtire: `python wp_inventory.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import wp_inventory` da ACELASI obiect de modul ca `elasticlab.extras.wp_inventory` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.extras.wp_inventory")
else:
    alias(__name__, "elasticlab.extras.wp_inventory")

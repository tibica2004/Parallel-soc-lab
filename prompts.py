"""Cale veche (faza 24): modulul e acum elasticlab/core/prompts.py.

Fisier subtire: `python prompts.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import prompts` da ACELASI obiect de modul ca `elasticlab.core.prompts` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.core.prompts")
else:
    alias(__name__, "elasticlab.core.prompts")

"""Cale veche (faza 24): modulul e acum elasticlab/eval/prompt_injection.py.

Fisier subtire: `python prompt_injection.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import prompt_injection` da ACELASI obiect de modul ca `elasticlab.eval.prompt_injection` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.eval.prompt_injection")
else:
    alias(__name__, "elasticlab.eval.prompt_injection")

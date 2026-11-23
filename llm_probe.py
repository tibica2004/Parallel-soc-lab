"""Cale veche (faza 24): modulul e acum elasticlab/ops/llm_probe.py.

Fisier subtire: `python llm_probe.py ...` ruleaza modulul nou ca __main__ (ExecStart, Makefile, scripturi),
iar `import llm_probe` da ACELASI obiect de modul ca `elasticlab.ops.llm_probe` (elasticlab/_compat.py).
Se scoate in faza 33."""
from elasticlab._compat import alias, run_main

if __name__ == "__main__":
    run_main("elasticlab.ops.llm_probe")
else:
    alias(__name__, "elasticlab.ops.llm_probe")

# Pasul 8: portile de reproductibilitate. Ruleaza pe es-node-1 (cu GPU-ul liber: fara harness,
# fara OpenClaw; benign-gen oprit). `make regression` e obligatoriu inainte de orice bump de prompt
# sau schimbare de model; `make test-prompts` la orice schimbare de prompt.
SHELL := /bin/bash
ENV := set -a; . ./soc.env; set +a; source env.sh >/dev/null 2>&1;

.PHONY: test test-prompts regression determinism golden injection
test:
	venv/bin/python -m pytest -q tests
test-prompts:
	venv/bin/python prompts.py --check && venv/bin/python -m pytest -q tests/test_prompts_manifest.py tests/test_untrusted_context.py tests/test_prompt_injection.py
golden:
	$(ENV) venv/bin/python regression.py export
regression:
	$(ENV) venv/bin/python -u regression.py run
determinism:
	$(ENV) venv/bin/python -u regression.py determinism --n 40
injection:
	$(ENV) venv/bin/python -u prompt_injection.py

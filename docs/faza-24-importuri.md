# Faza 24 — regula de importuri: incalcari listate (nereparate)

Regula e in `.importlinter` (import-linter 2.17). In faza 24 incalcarile se LISTEAZA; in faza 33
regula devine obligatorie si se repara (docs/plan-refactorizare.md).

Rulare (import-linter NU e in venv-ul de productie; se instaleaza separat):

    python3 -m venv /tmp/lint && /tmp/lint/bin/pip install import-linter
    cd ~/lab-refactor && PYTHONPATH=. /tmp/lint/bin/lint-imports --no-cache

Rezultat pe `faza-24-structura-pachet` (70 de fisiere, 147 de dependente):

| Contract | Stare |
|---|---|
| contracts nu importa din restul pachetului | pastrat |
| core importa doar din contracts | pastrat |
| tier1 si tier2 nu se importa intre ele | INCALCAT (3 importuri) |

## Incalcari

| De la | La | Ce se importa | Nota pentru faza 33 |
|---|---|---|---|
| `tier1.fast_path` (l.36) | `tier2.elastic_tools` | `ES`, `_esql` | clientul ES si executorul ES\|QL sunt comune; locul lor e in core (sau in uneltele din faza 26) |
| `tier1.fast_path` (l.37) | `tier2.hunt_path` | `GUIDES_DIR`, `SENSITIVE_CHILD`, `SENSITIVE_CMD`, `TEMP_DIRS`, `WEB_SVC_USERS` | constante de domeniu folosite de ambele cai; de mutat in core |
| `tier2.hunt_path` (l.487, l.577) | `tier1.l1_agent` | `HUNT_EXEC_TEXT_FIELDS`, `wrap_execution`, `UNTRUSTED_OPEN/CLOSE`, `strip_delimiters` | delimitarea continutului neincrezator (principiul 10) e comuna; de mutat in core |

## Dependente intre straturi permise de regula, dar de stiut

Nu incalca niciun contract de azi; le notez ca sa nu fie o surpriza cand structura se strange:

- `tier3.tier3` -> `apps.orchestrator` (importuri lenese, l.372 si l.408): Tier 3 foloseste
  `orchestrator.WRITER` si `orchestrator.HuntRunner`. Dupa faza 28 (Scriitorul) si 29 (workeri)
  dependenta ar trebui sa dispara.
- `ops.readiness` -> `eval.labeling` si `apps.label_ui` -> `eval.labeling`: logica de etichetare e
  folosita in productie, nu doar la evaluare.
- `tier3.tier3` -> `extras.exposure`, `tier3.tier3` -> `tier2.elastic_tools`.
- `core.prompts.REGISTRY` numeste module din tier1/tier2/tier3 ca SIRURI (`importlib.import_module`),
  deci import-linter nu le vede: `core` le citeste prompturile la `--check`, prin fisierele subtiri.
  Dupa faza 33 (fara fisiere subtiri) sirurile trebuie trecute pe caile noi.

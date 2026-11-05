# elastic-lab: SOC agentic Blue Team pe Elastic Stack + modele locale

Laborator de securitate defensiva: un SOC cu trei niveluri (triaj, investigatie, proactiv)
construit pe Elastic Stack 9.5.1, cu modele locale (qwen3:14b prin Ollama) si cod determinist
in jurul modelului. EXCLUSIV DEFENSIV: shadow mode permanent, nicio actiune automata pe hosturi.

Proiect de licenta (CTI, AC Iasi) + stagiu. Documentatia si comentariile sunt in romana, fara diacritice.

## De unde incepi (in ordine)

1. `CLAUDE.md`: contextul, infrastructura, cele 10 principii nenegociabile, regulile de lucru.
2. `docs/roadmap-intelegere.md`: parcurgerea laboratorului in ordinea in care curg datele,
   de la masinile OpenStack pana la verdictul din Elasticsearch (16 pasi, comenzi read-only).
3. `docs/pasi/REZUMAT.md`: starea proiectului (ce exista, ce merge, ce ramane).
4. `docs/arhitectura.md`: diagrama arhitecturii tinta (Mermaid).
5. `docs/plan-0day.md`: planul extinderii defensive 0-day / N-day (pasii 0-13, regulile R1-R16).
6. `docs/faze.md`: fazele 0-20 (istoric) si `docs/pasi/stare.md` (jurnal cronologic).

## Cum functioneaza, pe scurt

```
web-prod (senzori: Defend eBPF, auditd, Suricata, Apache, momeli) -> Elastic Agent -> ES
   -> reguli Kibana -> .alerts-security.alerts-*   (+ sweep-uri de raritate, in cod)
   -> soc-orchestrator (ciclu 120 s, shadow)
        alerta   -> Tier 1 (fast_path.py) -> should_escalate() -> Case -> Tier 2 (hunt_path.py) -> policy.decide() -> soc-audit
        finding  --------------------------------------------------> Case -> Tier 2 -> decide() -> soc-audit
   -> soc-tier3 (orar): incidente, reguli EQL proprii cu shadow 7 zile, vanatoare ATT&CK
   -> om: label_ui (ground_truth), dashboard Kibana, Discord
```

Principiul central: **codul decide, modelul judeca**. Escaladarea, podelele de incredere,
politicile, bugetele si rutarea sunt cod determinist; modelul propune doar verdicte si naratiuni,
validate prin Pydantic (`extra="forbid"`). Esecul escaladeaza la om, nu inchide.

## Harta repo-ului

| Unde | Ce |
|---|---|
| `orchestrator.py` | bucla principala: cursor, dedup, plafon pe cazuri, mod degradat, persistenta |
| `fast_path.py`, `l1_agent.py`, `enrich.py`, `rag.py`, `escalation.py` | Tier 1: triaj |
| `hunt_path.py`, `case_adapter.py`, `policy.py`, `executor.py` | Tier 2: investigatie + motor de politici (dry-run) |
| `tier3.py`, `hunt.py`, `rules.py`, `incidents.py`, `kibana_rules.py`, `exposure.py` | Tier 3: programat |
| `schemas.py` | granita Pydantic: verdicte, cazuri, actiuni (enumerari inchise) |
| `elastic_tools.py`, `behavioral_rules.py`, `sensor_rules.py`, `honeytokens.py` | sweep-uri de raritate si definitiile regulilor de detectie |
| `absence_check.py`, `llm_probe.py`, `nday_watch.py`, `static_triage.py`, `fp_rate.py`, `readiness.py` | timerele din jurul orchestratorului |
| `label_ui.py`, `cases.py`, `labeling.py`, `notify.py` | omul: etichetare, cazuri, notificari |
| `harness.py`, `scenarios*.yml`, `ablation.py`, `regression.py`, `prompt_injection.py` | portile de regresie (atacuri reale pe web-prod, in laborator) |
| `prompts/` + `prompts.py` | prompturile versionate (MANIFEST cu sha256) |
| `deploy/` | unitati systemd, firewall nft, scripturi de setup pentru es-node-1, web-prod, benign-gen, Kibana |
| `detections/` | fise per detectie; `docs/detectii-oprite.md` ce s-a oprit si de ce |
| `kb/`, `static/semgrep/`, `data/` | baza de cunostinte locala, reguli Semgrep, baseline-uri (data/ e generat, ignorat de git) |
| `tests/` | teste unitare pytest, fara model si fara Elasticsearch |
| `results/` | rulari de referinta ale harness-ului si ablatiei |
| `experiments/` | experimente masurate (acord A/B, re-triaj static) |

## Rulare

```
source env.sh                          # venv + ES_URL + chei (fisierul nu e in repo; vezi env.sh.example)
python3 -m pytest tests -q             # 1099 teste, ~5 s, fara model si fara ES
SHADOW_MODE=true python3 orchestrator.py --minutes 60 --limit 5     # un ciclu manual, fara actiuni
SCENARIOS=scenarios_fast.yml VERBOSE=1 python3 -u harness.py        # poarta rapida (4 scenarii, lenta, atacuri reale pe web-prod)
```

Porti de regresie (referinta): fast 4/4, dev 14/14 (recall 100%), validare 8/8, 0-day 1/1,
injectie 48/48. Orice regresie opreste lucrul; nu se ajusteaza scenariile sau pragurile ca sa treaca.

## Secrete

`env.sh`, `soc.env`, `.env` nu sunt in repo (vezi `*.example`). Cheile ES sunt scoped, fara
delete/manage; web-prod nu detine niciun secret al SOC-ului (R16).

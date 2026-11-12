# Jurnalul prompturilor (pasul 8.2)

Fiecare schimbare de prompt: `make regression` pe setul de aur, apoi `python prompts.py --update --reason "..."`.

## 2026-11-02 — prompt_set 4f01c8b50efc
- fast.extended_rules -> v1
- fast.fact_rules -> v1
- fast.l1_agent -> v1
- fast.pattern -> v1
- fast.verdict -> v1
- hunt.case_note -> v1
- hunt.critic -> v1
- hunt.investigator -> v1
- hunt.secondary_note -> v1
- static.triage -> v1
- tier3.hunt_plan -> v1
- tier3.incident_narrative -> v1
- tier3.rule_draft -> v1
Motiv: linia de baza la introducerea manifestului (dupa intarirea la injectie 6.1, 2026-11-02)

## 2026-11-02 — prompt_set f1d721739bf7
- hunt.critic (sters)
Motiv: plann S3: criticul sters din hunt_path (masurat daunator la 14B, oprit din faza 7)

## 2026-11-05 — prompt_set 2103d7ecb43a
- hunt.fact_rules -> v1
- hunt.primary_note -> v1
- hunt.tier1_note -> v1
Motiv: faza 22: prompturile Tier 2 lipsa din manifest (tier1_note, primary_note, fact_rules extras din _i_seed, text identic)

## 2026-11-05 — prompt_set 23664c93b9cd
- hunt.investigator -> v2
Motiv: faza 22 G: o fraza despre tool_eql_pattern (catalog inchis) si campurile permise in tool_rarity_of

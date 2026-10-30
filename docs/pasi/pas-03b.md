# Pasul 3.B — Sweep de raritate (tipurile lipsa)

EXCLUSIV DEFENSIV, doar observare. Shadow activ. Nicio comanda pe web-prod (totul ruleaza in
orchestrator, pe es-node-1, read-only pe ES).

## Ce exista deja si ce adauga 3.B

`elastic_tools.run_full_sweep` (orchestrator, la fiecare `--sweep-every 30` cicluri ~ 1 h) are deja
12 sweep-uri pe tiparul `novel(ultima ora, baseline 30 zile)`: parinte-copil, destinatii, porturi
(conexiuni acceptate), cai URL, JA4, scrieri in webroot, executie fileless, enumerare, recon WP,
beaconing, DNS. Findings merg direct pe calea lenta (Tier 2), deci Tier 1 nu le inchide.

3.B adauga tipurile din 3.2 care lipseau:

| Tip | Sursa | Scor | Masurat 2026-10-30 (24 h vs 30 z) |
|---|---|---|---|
| `new_executable` | process.executable nou pe host, ORICE user (fara caile fileless, le are deja suspicious_exec_path) | 0.9 in afara directoarelor de sistem, 0.6 /usr/bin..., 0.4 /opt/Elastic | 4 (aide, diff, systemd-timedated, endpoint-security: toate explicabile) |
| `new_user` | user.name nou care ruleaza procese pe host | 1.0 | 0 |
| `sbom_drift` | diferenta intre ultimele doua SBOM-uri: apache_module / php_ext / plugin / tema adaugat, sters, versiune schimbata, sau ACELASI plugin+versiune cu alt sha256 (cod schimbat fara update) | 0.9 / 0.6 / 0.5 / 1.0 | 0 |

Plus o reparatie R9 in `process_findings`: findings peste bugetul de investigatii (`--hunt-limit 5`)
erau sarite si, cu baseline-ul glisant, intrau in baseline la sweep-ul urmator -> pierdute pentru
totdeauna (masurat: 9 sweep-uri peste limita in 7 zile, pana la 511 findings, maxim 240 intr-un
sweep). Acum: verdict scris de cod (undetermined + escalate_human, motiv BACKLOG_SEVERE), fara model,
marcat vazut -> ajung la om.

## Abateri (cu motiv)

| Text 3.2 | Ales | Motiv |
|---|---|---|
| index nou `baseline-rarity` + cheie + `approved_by` (baseline/human) | baseline glisant din telemetrie (30 zile), ca toate sweep-urile existente | acelasi tipar ca restul codului; fara index si cheie noi. O entitate e raportata O DATA, apoi intra in baseline. Aprobarea umana = eticheta din interfata. |
| `rarity_alert` in soc-incidents, preluat de coada | RarityFinding direct pe calea lenta | asa functioneaza deja parinte-copil; un ocol prin soc-incidents nu adauga nimic. |
| `listen_port` din logs-system.socket | sweep-ul existent pe conexiuni acceptate | logs-system.socket nu exista (0 documente). |
| `cron_hash` prin soc-reader-gate | amanat | cere gate-ul SSH soc-reader (pasul 1b). Scrierile in cron sunt deja vazute de auditd (soc_persistence) si de hunt.py. |
| `user` din auditd useradd + system.auth | user.name din evenimentele de proces | un cont nou care NU ruleaza nimic nu face rau; cand ruleaza, apare aici. Crearea contului: auditd soc_identity + hunt.py. |

Constatare: SBOM-ul are un modul Apache numit `Loaded` (prima linie „Loaded Modules:” din
`apache2ctl -M`). Inofensiv pentru deriva (apare in ambele zile); de reparat in soc-sbom.sh.

## A. Fisiere (diff aratat)

`elastic_tools.py` (3 sweep-uri + `sbom_drift` pur + `_as_list`), `schemas.py` (3 kind-uri),
`orchestrator.py` (FINDING_KEY + buget R9), `hunt_path.py` (UNTRUSTED_DETAIL_KINDS: cai, nume de
cont si de plugin sunt alese de atacator), `tests/test_rarity_3b.py` (11 teste).

## B. Comenzi

1. (Claude) commit in ~/lab; scp `elastic_tools.py schemas.py orchestrator.py hunt_path.py` pe
   es-node-1 (copii `.pre-3b`), sha256.
2. (OMUL) `sudo systemctl restart soc-orchestrator`.

## C. Verificare

Test de fum read-only facut deja pe ES real (24 h): new_executable 4, new_user 0, sbom_drift 0.
Dupa restart: urmatorul sweep (≤ 1 h) scrie in jurnal `FINDINGS: N`; un executabil nou (test cu OK:
`/usr/local/bin/soc-rarity-test` copiat din /usr/bin/true si rulat o data pe web-prod) -> finding
new_executable -> calea lenta -> soc-audit.

## D. Metrica

`FINDINGS` per sweep si `FINDINGS peste buget` in jurnal; acceptare: zero findings pierdute
(fiecare fie investigat, fie escaladat fara model), new_user = 0 in operare normala.

## E. Rollback

`cp -p X.pre-3b X` pentru cele 4 fisiere pe es-node-1 + restart orchestrator.

# Pasul 2 — Analiza statica pe codul de pe web-prod (Semgrep + triaj local)

Scop: gasim tiparele de cod vulnerabil (sursa 0-day-urilor web) in PHP-ul instalat, inainte
sa le gaseasca altcineva, si dam omului pentru fiecare: descriere, mitigare, regula de
detectie propusa. EXCLUSIV DEFENSIV: schema nu are campuri exploit/poc/payload (E2), promptul
le interzice, iar extra=forbid respinge orice raspuns care le contine.

Pe web-prod nu exista cod propriu: se scaneaza WordPress core + plugin-uri + teme (doar *.php).

## A. Fisiere

| Fisier | Ce face |
|---|---|
| static/semgrep/<regula>.yaml (12) | regulile: unserialize, $wpdb fara prepare, upload fara validare, AJAX fara nonce/capabilitate, REST fara permission_callback, echo neescapat, include dinamic, citire fisier cu intrare, exec/eval, extract, SQL cu $_GET/$_POST. Fiecare cu cwe/owasp. |
| static/semgrep/<regula>.php (12) | testele `semgrep --test`: DOAR forma vulnerabila minima (`// ruleid:`) si varianta corecta (`// ok:`). Fara payload. |
| static_triage.py | sync (soc-reader, rrsync -ro) -> semgrep -> finding_id idempotent -> triaj (rol static_triage) -> decizia codului -> static-findings + draft_rule -> soc-metrics type=static. |
| prompts/static_triage.v1.txt | rolul "analist defensiv", cod in `<untrusted_code>`, JSON strict, interdictii explicite, raspuns in romana. |
| llm.py (diff) | rolul `static_triage` (temperatura 0, 1200 tokeni, timeout 120 s); `timeout` per rol, implicit 300 ca inainte. |
| tests/test_static_triage.py | 25 de teste pure (schema/E2, decizie, id, fragment, delimitatori, rsync fara momele). |
| deploy/soc-static.service/.timer | oneshot, duminica 05:00, NoNewPrivileges, ProtectSystem=strict. |
| deploy/es-node-1/static-findings-setup.sh | pentru OM: indexul static-findings (mapping strict) + cheia soc-static-writer. |

Diff llm.py:
```diff
     "rules":     {"temperature": 0.1, "max_tokens": 1500},
+    # pasul 2: triajul rezultatelor Semgrep (determinist, raspuns scurt, timeout mai mic)
+    "static_triage": {"temperature": 0.0, "max_tokens": 1200, "timeout": 120},
 }
-        max_tokens=cfg["max_tokens"], timeout=300,
+        max_tokens=cfg["max_tokens"], timeout=cfg.get("timeout", 300),
```

### Decizii (si alternative respinse)

1. **Copia webroot-ului: doar *.php, fara momele.** rsync exclude `wp-config.php`, `.env.bak`,
   `backup.sql`, uploads/cache/upgrade. Motiv: citirea momelilor declanseaza honeytoken-urile
   (auditd) la fiecare rulare, iar wp-config.php are parola reala a bazei — nu o copiem pe
   es-node-1. Respins: copia completa din task 2.1.
2. **Draftul de regula al modelului NU intra automat in shadow/promovare.** E text liber (EQL
   scris de model); principiul 2 interzice text liber spre actiuni, iar fluxul existent
   (rules.py) scrie EQL-ul din sabloane si il valideaza pe un caz real de telemetrie, pe care un
   finding static nu il are. Se scrie in soc-incidents ca `draft_rule`, `status=proposed`,
   `requires_human_review=true`. Respins: 2.5 "shadow 7 zile -> promovare" automat.
3. **Statusul il decide codul:** esec de model/JSON -> `escalated` (triage_failed); incredere
   < 60 -> `escalated` (nu inchis, nu aruncat); FP cu incredere >= 60 -> `closed_fp`; TP ->
   `open`. Respins: "codul elimina" findings sub 60 (ar fi ascuns incertitudinea; principiul 8).
4. **Buget**: 200 triaje / 60 min. Ce depaseste -> `pending_triage` (reluat la rularea
   urmatoare) si exit 2. Ordinea: ERROR inaintea WARNING.
5. **draft_rule cu cheia existenta ES_INCIDENTS_WRITER** (create_doc/index doar pe
   soc-incidents), nu o a doua permisiune pe cheia static. Acelasi privilegiu minim, o cheie
   mai putin de rotit.
6. **Semgrep intr-un venv separat** (~/semgrep-venv, versiune fixa 1.180.0), ca sa nu atinga
   dependentele orchestratorului. `--metrics=off --disable-version-check`.
7. Fisierele de reguli sunt separate (unul per regula), nu un singur wordpress.yml: asa le cere
   `semgrep --test` (testul are acelasi nume ca regula).

## B. Comenzi (es-node-1; nimic pe web-prod in afara de citirea prin soc-reader)

```
# 1. (facut de Claude) cod copiat cu scp, sha256 verificat; llm.py.pre-2 = copia veche
# 2. (facut de Claude) Semgrep: python3 -m venv ~/semgrep-venv && ~/semgrep-venv/bin/pip install semgrep==1.180.0
# 3. (OM) indexul + cheia, cu contul elastic:
ssh tiberiu@172.30.6.106 'cd ~/lab && bash deploy/es-node-1/static-findings-setup.sh'
#    asteptat: "static-findings creat", "ES_STATIC_WRITER_API_KEY adaugata", 200, 403
# 4. masurare fara model:
ssh tiberiu@172.30.6.106 'cd ~/lab && source env.sh && set -a && . ./soc.env && set +a && venv/bin/python static_triage.py --dry-run'
# 5. rulare completa (GPU liber: fara harness, fara OpenClaw):
ssh tiberiu@172.30.6.106 'cd ~/lab && set -a && . ./soc.env && set +a && venv/bin/python static_triage.py --no-sync'
# 6. (OM, sudo) unitatile:
ssh -t tiberiu@172.30.6.106 'sudo install -m 644 ~/lab/deploy/soc-static.service ~/lab/deploy/soc-static.timer /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now soc-static.timer && systemctl list-timers soc-static.timer'
```

## C. Verificare

```
~/semgrep-venv/bin/semgrep --metrics=off --validate --config static/semgrep/   # 0 erori, 12 reguli
~/semgrep-venv/bin/semgrep --metrics=off --test static/semgrep/                # 12/12
venv/bin/python -m pytest -q tests/test_static_triage.py                       # 25 passed
curl -s -H "Authorization: ApiKey $ES_STATIC_WRITER_API_KEY" "$ES_URL/static-findings/_count"   # >= 1
curl -s -H "Authorization: ApiKey $ES_READER_API_KEY" "$ES_URL/soc-metrics/_search?q=type:static&sort=@timestamp:desc&size=1"
journalctl -u soc-static --since today | tail     # "gata:", exit 0 (sau 2 = buget, vizibil)
```

## D. Metrica (soc-metrics, type=static)

findings_total, findings_new, findings_known, findings_tp, findings_fp, findings_escalated,
findings_failed, findings_pending_budget, rules_drafted, runtime_s, per_rule.{regula},
semgrep_errors. Acceptare: `semgrep --test` 100%; 2 rulari fara crash; a doua rulare are
findings_new = 0 (idempotenta).

## E. Rollback (doar daca se cere; nu e pas obligatoriu)

```
sudo systemctl disable --now soc-static.timer; sudo rm /etc/systemd/system/soc-static.{service,timer}; sudo systemctl daemon-reload
cp -p ~/lab/llm.py.pre-2 ~/lab/llm.py
rm -rf ~/lab/data/static ~/semgrep-venv
# cu contul elastic: DELETE static-findings; POST /_security/api_key/_invalidate {"name":"soc-static-writer"};
# scoate ES_STATIC_WRITER_API_KEY din soc.env; draft_rule-urile din soc-incidents au source=static.
```

## Rezultate (2026-11-02, es-node-1)

- `semgrep --validate`: 12 reguli, 0 erori; `semgrep --test`: 12/12; pytest 27/27 (si pe es-node-1).
- Defect gasit la prima rulare: snapshot-ul sta sub data/ (in .gitignore) si semgrep a scanat
  0 fisiere, raportand "0 rezultate" fara eroare. Reparat: `--no-git-ignore` + garda de
  acoperire (scanat < 90% din fisierele PHP = esec, exit 1). Commit dfed52c.
- Copia: 1487 fisiere PHP, 25 MB, fara wp-config.php/backup.sql/.env.bak; 1442 scanate.
- Rularea 1 (cu model, 25.8 min, exit 0): 77 rezultate (61 xss-echo, 9 exec, 3 include,
  3 file-read, 1 wpdb) -> 43 open, 19 closed_fp, 15 escalated (din care 1 triage_failed),
  42 draft_rule propuse in soc-incidents.
- Rularea 2 (sync complet, 37 s, exit 0): findings_new=0, findings_known=77 -> idempotent.
- static-findings _count=77; soc-incidents draft_rule source=static = 42; soc-metrics type=static = 2.

### Calitatea triajului: NESATISFACATOARE pe WordPress core

Toate cele 43 "open" sunt in WordPress core 7.1.3 (niciunul in plugin-uri/teme). Doua verificate
manual, ambele fals pozitive:
- wp-admin/setup-config.php:338 (`$wpdb->query("SELECT $prefix")`): $prefix e validat cu
  `preg_match('|[^a-z0-9_]|i')` la linia 308, in afara ferestrei de +-12 linii vazute de model.
- wp-admin/users.php:350: $id si user_login vin din date incarcate, nu direct din cerere.
Concluzie: qwen3:14b cu fereastra ingusta supra-declara "adevarat pozitiv" pe cod pe care nu-l
vede intreg. Nicio actiune automata nu decurge din asta (open = la om; draft = propunere), dar
42 de drafturi sunt zgomot pentru om.

Propunere (de decis de om): findings in fisiere de core identice cu sumele oficiale WordPress
(api.wordpress.org/core/checksums) -> status `upstream_core`, decis de cod, fara model si fara
draft (remedierea e update-ul de WordPress, deja urmarit de N-day watch). Modelul ramane pentru
plugin-uri, teme si fisierele de core MODIFICATE (exact cele interesante pentru un 0-day/webshell).
Plus fereastra = functia intreaga (nu +-12 linii).

# Plan: extinderea defensiva 0-day / N-day (pasii 0-12b)

Sursa: task-ul "Extindere SOC agentic Blue Team" (documentele 6, 7 si completarile G),
reconciliat cu codul existent (fazele 0-20) si cu CLAUDE.md. Ordinea e D3:
0 -> 1 -> 1b -> 1c -> 3 -> 2 -> 4 -> 7 -> 6 -> 5 -> 8 -> 9 -> 10 -> 11 -> 12 -> 12b.

Fiecare pas = o ramura `faza-NN-nume` in ~/lab (nu repo separat in /opt/soc, G5 se
aplica prin ramurile existente). La finalul fiecarui pas: raport A-E si oprire.
Agentul scrie cod, teste si comenzile exacte; omul ruleaza tot ce atinge web-prod,
es-node-1, cheile ES si regulile Kibana, comanda cu comanda.

## Presupuneri (implicite, schimbabile)

- Codul ramane in ~/lab, deploy pe es-node-1 prin git pull (ca acum).
- PHP `disable_functions` NU se aplica: harness-ul (dev/val/fast) genereaza atacul prin
  `system()`; restul hardening-ului din B5 se aplica.
- Notificare: Telegram bot (token + chat_id in soc.env), trimisa din Python; licenta
  basic nu are conectori webhook/email in Kibana. De verificat: `GET _license`.
- Backup offsite: pull de pe es-node-1 in /mnt/backup cu cheie dedicata soc-backup
  (exceptie temporara permisa de B1), pana exista o VM de backup.

## Corectii fata de task (verificate in repo)

1. web-prod = Ubuntu 24.04, `libapache2-mod-php` 8.3 (docs/migrare.md:205). Nu exista
   php-fpm8.2: parintele shell-urilor e `apache2`; listele albe se scriu pe binarele reale.
2. Agentul de pe web-prod trimite la ES direct pe 192.168.10.121:9200 (output Fleet).
   Firewall-ul de pe es-node-1 trebuie sa permita 9200 din 192.168.10.138 (G4 l-ar taia).
3. Docker publica 9200/5601 pe 0.0.0.0 (docker-compose.yml:21,43) si ocoleste lantul
   `input` din nft: filtrarea se pune in `DOCKER-USER`. Rollback-ul NU foloseste
   `nft flush ruleset` (sterge si regulile Docker); se sterge doar tabelul propriu.
4. B1 push web-prod -> es-node-1 contrazice G4 (fara cheie SSH pe web-prod): pull.
5. Regulile de "absenta" (orchestrator_down, integrity_checker_down, backup lipsa) pe
   basic: Elasticsearch query rule exista, dar fara conector; notificarea o face
   poller-ul Python (pasul 0/7), nu Kibana.
6. Pasul 8 cere temperature 0 pe toate rolurile: `hunt_b` are 0.7 intentionat
   (faza 7, erori decorelate A/B). Decizie de luat la pasul 8, cu masuratoare.
7. Pasul 9 (executor care ruleaza real prin ssh) contrazice principiul 4 din CLAUDE.md
   ("executorul ruleaza doar dry-run"). Pasul 9 incepe doar dupa ce omul modifica CLAUDE.md.
8. harness.py si ablation.py raman pe tiberiu@ (genereaza atacuri cu sudo pe tinta de
   laborator); "nicio comanda din cod pe tiberiu@" se aplica orchestratorului si enrich-ului.

## Ce exista deja (se extinde, nu se rescrie)

| Cerinta din task | Existent |
|---|---|
| Inventar + N-day (pas 1) | wp_inventory.py, exposure.py, kb/wp_vulns.yml, tier3 --expunere, soc-wp-inventory |
| Honeytokens (3.3) | honeytokens.py, .env.bak, soc-honeytoken-read (auditd), deploy/kibana/honeytoken_rules.py |
| Raritate (3.2) | sweep extins (faza 12): parinte-copil, destinatii, porturi, cai URL, webroot, JA4 |
| Detectie comportamentala (3.1 a, b) | "RCE: Web server spawns shell", new_webroot_write, YARA |
| Integritate (3.4) | canary_check.py, /etc/cron.d/soc-canary |
| soc-metrics (1c, 7) | metrics.py, deploy/kibana/build_dashboard.py, soc-metrici.ndjson |
| Executor (9) | executor.py: planuri dry-run in soc-audit, absolvire din etichete |
| Reguli Tier 3 + shadow (2.5, 5.4) | rules.py, kibana_rules.py (prefix t3-), tier3.py |
| Injectie (6.1) | ablatia: 10/10 cazuri de injectie |
| Suricata ET Open (12) | faza 12 pas 5 (lipseste doar timer-ul de update) |

## Pasii

### Pasul 0 — protectie imediata (faza-21-protectie)
- Agent: deploy/web-prod/soc-backup.sh + .service/.timer (mysqldump MariaDB + tar
  webroot/apache/php, sha256, retentie 14 z, `logger soc-backup OK`); fragment
  unattended-upgrades; nftables pentru web-prod si es-node-1 (DOCKER-USER); conf Apache
  (ServerTokens Prod, ServerSignature Off, TraceEnable Off, xmlrpc denied); notify.py
  (Telegram, dedup 15 min, teste fara retea); poller de absenta.
- Om: verifici IPv6 pe web-prod (G6), bind-ul Ollama pe GPU, `GET _license`; rulezi
  comenzile; testul de restore pe o VM temporara.
- Poarta: restore reusit; notificare de test < 3 min; `nft list ruleset` conform;
  `curl -I` fara versiune; harness fast 4/4 dupa firewall (telemetria trece).

### Pasul 1 — SBOM + N-day watch (faza-22-nday)
- Agent: soc-sbom.sh (user soc-sbom, NDJSON in /var/log/soc, fallback mods-enabled),
  nday_watch.py extinde exposure.py: OSV/NVD doar apache/php/core, WPScan pentru
  plugin-uri (cache 24 h), VulnRecord Pydantic, _id fix, hunt_request + patch_request in
  soc-incidents; tier3.py consuma hunt_request (diff aratat). BENIGN_GEN_IPS in soc.env (G3).
- Om: user soc-sbom, Custom Logs in Fleet (logs-soc.sbom-*), indicele asset-vulns,
  cheile ES_VULNS_WRITER si ES_INCIDENTS_WRITER, WPSCAN_API_KEY.
- Poarta: teste unitare; dry-run live; 3 zile de timere cu exit 0; zero duplicate.

### Pasul 1b — soc-reader (faza-23-soc-reader)
- Agent: soc-reader-gate (lista alba exacta, rrsync -ro pentru rsync, log), teste pytest
  pe gate cu SSH_ORIGINAL_COMMAND; enrich/wp_inventory pe soc-reader prin mediu.
- Om: user, authorized_keys cu command=, sshd Match, cheia pe es-node-1.
- Poarta: "ls /" -> DENIED; enrich atinge Tier 1 -> harness fast 4/4 + dev 14/14.

### Pasul 1c — soc-metrics cu cheie proprie (faza-24-metrici)
- Agent: mapping explicit (type keyword), scrierea din pasii 1-6 prin ES_METRICS_WRITER.
- Om: cheia scoped; mapping-ul aplicat cu contul tau.

### Pasul 3 — detectie fara semnatura (faza-25-detectie)
- Agent: 10 reguli EQL ca JSON (parinte apache2, liste albe din build_whitelists.py pe
  7 zile), reguli auditd (shadow read uid 33, wp-config cu exe!=apache2, backup.sql),
  honeytokens noi (H1b user MariaDB fara GRANT, H2 mu-plugin, H3 backup.sql, H4 robots),
  bypass in l1_agent pentru a/h/i si soc-honeytoken (preset malicious 100; config_error
  pentru WP_SELF_IPS/BENIGN_GEN_IPS) — diff aratat; integrity_check.py extinde
  canary_check.py (silence, canar, hash, agent, fleet); tipurile de raritate lipsa
  (user, apache_module/php_ext din SBOM, cron_hash prin soc-reader); AIDE (G9).
- Om: fiecare honeytoken separat, regulile auditd in policy Fleet, importul regulilor.
- Poarta: dev 14/14, val 8/8, fast 4/4 + scenarios_0day.yml; testele din 3.6;
  honeytoken 0 alerte in 48 h fara teste.

### Pasul 2 — analiza statica (faza-26-static)
- Agent: reguli Semgrep + tests/*.php (doar pattern vulnerabil minimal si varianta
  corecta), StaticTriage fara campuri exploit/poc/payload, prompt static_triage.v1,
  run_static.py (buget 200 findings/60 min), draft_rule in fluxul rules.py existent.
- Om: semgrep pe es-node-1, static-findings + cheia, timer duminica 05:00.
- Poarta: `semgrep --test` 100%; 2 rulari fara crash. Nota: pe web-prod nu exista cod
  propriu, deci se scaneaza core + plugin-uri (akismet, hello).

### Pasul 4 — trafic benign (faza-27-benign)
- Agent: benign_gen.py (Playwright, X-SOC-Benign, profil zi/noapte), soc-wp-update.sh
  (G2, user deploy), fp_rate.py.
- Om: VM benign-gen 192.168.10.150, cont soc-benign-admin (editor), cheia
  ES_BENIGN_WRITER, firewall 9200 din .150.
- Poarta: 24 h fara restart, 4 rapoarte FP. Benign-gen se opreste in timpul harness-ului
  (GPU partajat, conditii de referinta).

### Pasul 7 — observabilitate (faza-28-observabilitate)
- Agent: write_cycle_metrics in orchestrator, tokeni in llm.py, llm_probe.py, panourile
  noi in build_dashboard.py, unitatile systemd (G7: Restart, MemoryMax, watchdog —
  ExecStart neatins), alertele de absenta prin poller.
- Poarta: atinge bucla -> fast 4/4 + dev 14/14; 24 h fara gol > 4 min; test
  orchestrator_down aprobat.

### Pasul 6 — securitatea SOC-ului (faza-29-securitate-soc)
- Agent: suita de injectie (>= 40 cazuri, extinde ablatia), truncare/strip de delimitatori
  in cod; Makefile test-prompts.
- Om: docker-compose (path.repo), SLM soc-daily, restore de test, offsite, chrony pe 3 hosturi.
- Poarta: injectie >= 98% identic si 100% pe malicious; restore OK; offset < 50 ms.

### Pasul 5 — acoperire ATT&CK (faza-30-attack)
- Agent: art_runner.sh (afiseaza comanda, asteapta OK, cleanup), emulation.ndjson ->
  Custom Logs, coverage.py, stratul Navigator, ipoteze Tier 3 din gap_list.
- Om: VM lab-sink 192.168.10.160, snapshot pre-test, rulezi fiecare test.
- Poarta: >= 20 tehnici, toate cleanup_ok, fiecare unseen cu ipoteza Tier 3.

### Pasul 8 — reproductibilitate (faza-31-reproductibil)
- Agent: optiuni fixe per rol in llm.py, prompturi in fisiere + MANIFEST cu sha256,
  regression.py, Makefile regression/determinism.
- Om: >= 100 alerte etichetate in UI (>= 25 malicious/suspicious/benign) pentru golden_v1.
  Acesta e drumul critic: etichetarea trebuie inceputa de acum.
- Poarta: determinism >= 98%, fara schimbare malicious <-> benign; F1 malicious nu scade;
  atinge toate tier-urile -> dev, val, fast.

### Pasul 9 — iesire controlata din shadow, pregatire (faza-32-readiness)
- Precondite: CLAUDE.md principiul 4 modificat de om; mod_remoteip verificat (A10).
- Agent: readiness_check c1-c9, BlockIpTtl, executorul cu cele 8 garzi, soc-block-gate.
- Om: tabelul nft inet soc, user soc-blocker, sudoers, never_block.txt.
- Poarta: would_block in soc-audit, set nft gol permanent in shadow, refused_kill.

### Pasul 10 — igiena (faza-33-igiena)
- Agent: CLAUDE.md (sectiunile cerute, 172.20.99 eliminat), agregarea in Case in
  case_adapter (atinge Tier 1 -> fast + dev).
- Om: ServerName Apache.

### Pasul 11 — retentie ES (faza-34-ilm); Pasul 12 — suricata-update zilnic
(faza-35-suricata-update); Pasul 12b — ModSecurity CRS DetectionOnly (faza-36-modsec,
poarta fast + dev).

## Calendar

Codul nu e drumul critic; ferestrele de asteptare sunt: 3 zile (pas 1), 48 h + 7 zile
shadow-review (pas 3), 24 h (pasii 4, 7), etichetarea a >= 100 alerte (pas 8),
readiness 3 zile la rand (pas 9). Minim realist: 4-5 saptamani.

## Limite (raspunsul la "prinde 0-day?")

Planul prinde urmele comportamentale ale exploatarii (shell din apache2, fisier PHP
nou, outbound nou, momeli, conturi/cron, telemetrie tacuta). Nu prinde fiabil:
exploatarea care ramane in procesul PHP (SQLi cu exfiltrare prin raspuns, auth bypass
urmat de actiuni WordPress legitime), un update de plugin compromis (fereastra de update
e marcata benign), un exploit de kernel care opreste agentul (se vede doar tacerea).
Singura actiune automata posibila (block_ip_ttl) nu opreste un exploit dintr-un request.

# REZUMAT — extinderea defensiva SOC (plan-0day)

Rezumat de sine statator: ce s-a facut, ce ramane, constatari cheie. Pentru detalii A-E
pe fiecare pas, vezi `docs/pasi/pas-00.md`, `pas-01.md`, `pas-01c.md`, `pas-03.md` si
starea vie `docs/pasi/stare.md`. Plan complet: `docs/plan-0day.md`.
Ultima actualizare: 2026-10-29. Ramura: `faza-21-protectie` (nepublicata, fara push).

EXCLUSIV DEFENSIV. Shadow mode activ (nicio actiune pe hosturi pana la pasul 9).

---

## Topologie si model de lucru

- Sesiunea Claude ruleaza pe **elastic-lab vechi** (172.20.99.220 = IP admin). Claude da
  comenzile, le ruleaza de aici, intoarce rezultatele.
- **es-node-1** (creierul SOC): intern 192.168.10.121, flotant 172.30.6.106. Docker (es01,
  kibana :5601, fleet :8220), orchestrator, tunel LLM. Cod in `/home/tiberiu/lab`.
- **web-prod** (victima WordPress): intern 192.168.10.138, flotant 172.30.6.249. Apache/PHP/WP.
- **atacator**: flotant 172.30.6.133 (toate atacurile externe apar pe web-prod ca acest IP — SNAT).
- Kibana: `http://172.30.6.106:5601` (HTTP, doar de pe IP admin din setul `admin_v4`).

**Deploy pe es-node-1 = prin `scp`** (NU git — es-node-1 e o clona cu alta ramura; continutul
fisierelor coincide cu sesiunea minus modificarile mele). **`sudo` pe es-node-1 cere parola**
(fara NOPASSWD) → pasii cu sudo/Fleet/parola elastic ii face OMUL; Claude face scp + verificari
read-only (cheile intra in antetul HTTP, nu se afiseaza).

## Reguli absolute (rezumat)

R1 exclusiv defensiv. R3 nimic pe web-prod/es-node-1 fara OK per comanda. R4 shadow pana la
pasul 9. R5 codul decide, modelul judeca. R9 esecul escaladeaza, nu inchide. R12 diff inainte
de a modifica fisiere existente. R16 niciun secret al SOC-ului pe web-prod (chei doar in
`soc.env`/`env.sh` pe es-node-1). G5 commit per pas: `pas N.M: <rezumat>`.

---

## FACUT (verificat pe hosturi)

### PASUL 0 — protectie imediata (complet, 0.1-0.5)
- **0.1 Backup**: `soc-backup.timer` 01:30 pe web-prod (baza wp + grants + webroot, sha256,
  14 zile); `soc-backup-pull.timer` 02:15 pe es-node-1 (cheie `soc-backup` doar `rrsync -ro`,
  30 zile); test de restore. Verificat: backup OK, cheia refuza `ls /`, restore 12 tabele.
- **0.2 Patch-uri**: `unattended-upgrades` fara reboot + syslog; WordPress fara auto-update
  (`AUTOMATIC_UPDATER_DISABLED`, `WP_AUTO_UPDATE_CORE=false`, `DISALLOW_FILE_EDIT`);
  `wp-config.php` root:www-data 640; `soc-wp-update.timer` 02:00 in mod raport (APPLY=0).
- **0.3 Firewall** nft propriu (`inet soc_fw`, separat de Docker) pe ambele hosturi, cu revert
  automat la 10 min. web-prod: 80/443 oricine, 22 doar es-node-1 + admin. es-node-1: 22/5601/8088
  doar admin, 8220 din es-net, 9200 doar web-prod+benign-gen. Verificat: atacatorul blocat pe 22/9200.
- **0.4 Notificari Discord** (webhook): `notify.py` (escaladari critice: honeytoken/sensor/native),
  `absence_check.py` + `soc-absence.timer` (10 min: backup>26h, servicii, canar). Webhook DOAR
  in soc.env+env.sh (R16). ACTIV, test Discord confirmat (204).
- **0.5 Hardening Apache**: `soc-hardening.conf` drop-in (ServerTokens Prod, ServerSignature Off,
  TraceEnable Off, ServerName 192.168.10.138, xmlrpc.php blocat). Verificat: `Server: Apache` fara
  versiune, xmlrpc 403.

### PASUL 1 — SBOM + N-day watch (complet)
- **1.A SBOM** (web-prod): `soc-sbom.sh` (user `soc-sbom`, timer 03:00) → `/var/log/soc/sbom.ndjson`
  → Fleet Custom Logs (dataset `soc.sbom`) → `logs-soc.sbom-*`. Fara chei/retea pe web-prod.
  Verificat: 77 componente, core apache 2.4.58 / php 8.3.6 / wp_core 7.1.3.
- **1.B N-day watch** (es-node-1): `nday_watch.py` (`soc-nday.timer` 04:00) citeste SBOM, coreleaza
  cu **NVD (cu parsare de interval, `nvd_affects`)** + OSV + WPScan → `asset-vulns` (idempotent,
  `_id` fix). Hunt/patch plafonat (`NDAY_HUNT_MIN_CVSS=9`, `NDAY_HUNT_MAX=10`, pe `new|newly_confirmed`)
  → `soc-incidents`. `es_client` hard-fail pe cheie lipsa (R9). Verificat: exit 0, idempotent
  (224→224); **224 vulns (118 confirmate / 106 needs_review), 114 cu patch, 10 hunt + 10 patch_request**.
  22 teste. Chei in soc.env: ES_VULNS/INCIDENTS/METRICS_WRITER + ES_READER (soc-reader).

### PASUL 1b — partial
- Cheia **`soc-reader`** creata ca `ES_READER_API_KEY` (cheie de CITIRE ES, cuprinzatoare:
  logs-*, .alerts-security, verdicts-history, soc-audit, soc-incidents, soc-metrics, asset-vulns).
  NU am inlocuit `ES_API_KEY` (ar fi pierdut citirea pe soc-traces/baseline-entity-parentchild).
- **NEFACUT**: gate-ul SSH read-only `soc-reader` pe web-prod (pasul 6.2) — necesar pentru
  cron_hash (3.B) si canar-HASH (3.D).

### PASUL 1c — soc-metrics (complet)
- `soc-metrics` exista deja (scris de orchestrator, 672 docs) → confirmare, nu creare.
  Agregabil pe `type.keyword`; cheile ES_METRICS_WRITER + ES_READER OK. nday aliniat la
  `@timestamp` (standard Kibana). Gol pentru pasul 7: 666/672 docuri orchestrator n-au `type`.

### PASUL 3.A — reguli comportamentale fara semnatura (operational + verificat)
- **6 reguli EQL** (`behavioral_rules.py`) care prind LANTUL de exploatare, nu semnatura:
  `soc-web-spawns-shell` (apache/php-fpm → shell), `soc-php-written-in-webroot`,
  `soc-wwwdata-unexpected-exec`, `soc-webprod-new-outbound`, `soc-wwwdata-writes-outside-webroot`,
  `soc-apache-reads-shadow` (auditd — Defend nu emite citiri, A3).
- **Liste albe din baseline** (`build_whitelists.py`) cu `NEVER_WHITELIST` care exclude binarele
  de recon/shell chiar daca apar in baseline (baseline contaminat de atac: `id`/`env` fusesera
  rulate de un atacator). Rezultat pe web-prod: `wwwdata_exec=[dash, php8.3]`.
- **Escaladare** `EscalationReason.BEHAVIORAL` (schemas.py + escalation.py), pasat din orchestrator.
- **Importer** Kibana extins (`deploy/kibana/honeytoken_rules.py`) — rulat de om cu contul elastic.
- **Verificat pe host**: toate 6 regulile `pornita` in Kibana; test live `sudo -u www-data
  /usr/bin/uptime` pe web-prod → `soc-wwwdata-unexpected-exec` a declansat in ~1 min (sev high,
  tags soc-behavioral+shadow-review). Detectie fara semnatura confirmata end-to-end. 124 teste.
- In fereastra **shadow-review de 7 zile** inainte de promovare.

---

## RAMAS DE FACUT

### 3.A — doua actiuni de om (optionale, nu blocheaza restul)
- **Step 3 — regula auditd** pe web-prod (ca regula `soc-apache-reads-shadow` sa alerteze; pana
  atunci e inerta; celelalte 5 merg). Fleet → policy web-prod → `auditd_manager`:
  `-a always,exit -F arch=b64 -S openat,open -F path=/etc/shadow -F perm=r -F uid=$(id -u www-data) -k soc_shadow_read`
- **Step 4 — restart orchestrator** (activeaza motivul explicit `BEHAVIORAL`; pana atunci
  podelele `fast_path` escaladeaza oricum alertele web):
  `ssh -t tiberiu@172.30.6.106 'sudo systemctl restart soc-orchestrator'`

### Restul pasului 3
- **3.C** honeytokens WordPress/MySQL: wp-config decoy + user MySQL `wp_backup` fara grants +
  mu-plugin `soc-honey.php` (login) + `backup.sql` + robots traps. Extinde `honeytokens.py`/
  `honeytokens.sh`. (Familia `.env.bak` exista deja.)
- **3.D** integritate → `soc-incidents`: adauga canar-HASH + fleet-server la `absence_check.py`
  si scrie `integrity_alert` in soc-incidents (azi doar Discord). canar-HASH depinde de soc-reader (1b).
- **3.E** AIDE (FIM gazda) pe web-prod (G9).
- **3.B** sweep de raritate pe absenta (executable/listen_port/cron_hash vs baseline 7z);
  cron_hash depinde de soc-reader (1b).

### Pasii urmatori (ordinea D3)
`2` (analiza statica Semgrep) → `4` (trafic benign) → `7` (observabilitate + dashboard) →
`6` (prompt injection, snapshot, chrony) → `5` (ATT&CK/Atomic Red Team) → `8` (determinism,
regression) → `9` (pregatire iesire din shadow, NU activare) → `10` (igiena) → `11` (ILM) →
`12` (suricata-update) → `12b` (ModSecurity CRS).

**Durata realista**: minim 4-5 saptamani — fiecare lot de reguli noi are 7 zile shadow;
pasul 8 cere ≥100 alerte etichetate manual de om.

---

## Constatari / decizii cheie (gotchas)

- **Bypass escaladare NU e in l1_agent.py** (cum spunea textul initial), ci in `fast_path.py`
  (podele) + `escalation.py` (`EscalationReason`). Motive noi se adauga acolo.
- **Baseline-ul de 7 zile e contaminat de atac** → listele albe trebuie curatate (NEVER_WHITELIST),
  altfel orbesc exact regulile de detectie. Calibrarea curata vine cu benign-gen (pasul 4).
- **ES_API_KEY principal are `read:false`** pe asset-vulns + soc-incidents → am facut `soc-reader`
  (ES_READER) separat. Cand wireuim tier3 sa consume hunturile: largim rolul ES_API_KEY sau
  wireuim ES_READER.
- **`soc-reader` SSH gate (pe web-prod) ≠ ES_READER_API_KEY** (cheie ES). Gate-ul SSH e nefacut
  si blocheaza 3.B cron_hash + 3.D canar-HASH.
- **A10/c9 blocaj pentru pasul 9**: tot traficul extern vine pe un singur IP SNAT (172.30.6.133),
  deci block_ip_ttl ar bloca toata calea externa; criteriul "≥5 IP-uri externe distincte" e de
  neatins in lab. Detectia merge; doar blocarea automata (pasul 9) devine grosiera → de decis
  manual-only in lab.
- **never_block (pasul 9) = lista de IP-uri specifice, nu CIDR**: 172.30.6.133 (blocabil) e in
  acelasi /24 cu es-node-1/web-prod/admin (care nu trebuie blocate).
- **Licenta ES = basic**: fara conectori email/webhook in Kibana → notificarile merg prin
  `notify.py`/Discord. Regulile de "absenta" = Elasticsearch query rule "count below 1" (NU threshold).
- **Elastic Defend (eBPF) nu emite evenimente de citire** → regulile pe "read" sunt pe
  `logs-auditd_manager.*` (cheie auditd), nu pe endpoint.
- **GOTCHA la retragerea boxei vechi**: nft `soc_fw` permite SSH/5601 doar de la `admin_v4`
  (contine 172.20.99.220 = boxa sesiunii). Inainte de a o retrage: adauga noul IP in `admin_v4`
  pe AMBELE hosturi (`sudo nft add element inet soc_fw admin_v4 { <IP> }` + in deploy/*/soc-fw.nft),
  altfel pierzi SSH-ul.

## De facut de om (oricand)
- Etichetare in interfata: ≥100 alerte (25 malicious / 25 suspicious / 25 benign) — drum critic pasul 8.
- Rotatia cheilor API ES + SSH la 90 zile (G8).
- Daca transcriptul conversatiei nu e strict privat: regenereaza webhook-ul Discord.
- Laura: are nevoie de Ollama din retea? (acum asculta 0.0.0.0:11434; atacatorul nu ajunge la el).

## Commits cheie (ramura faza-21-protectie)
`0.1-0.5` protectie · `1.A` SBOM · `55f1814` 1.B nday · `bc47d45` 1c · `5ce30b2` draft pas 3 ·
`a73f95d` 3.A reguli+teste · `9f634f0` importer · `9af9647` build_whitelists (anti-contaminare) ·
`a8aad1b` 3.A verificat end-to-end. (git log pentru lista completa.)

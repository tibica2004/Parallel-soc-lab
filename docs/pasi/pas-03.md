# Pasul 3 — Detecție de exploatare fără semnătură (DRAFT)

Nucleul defensiv: prinde exploatarea 0-day/N-day prin COMPORTAMENT, nu prin semnături.
Acesta e un DRAFT de plan. Fiecare sub-bucată se livrează ulterior A–E, cu diff arătat
înainte (R12) și OK per comandă pe hosturi (R3). Nimic nu se rulează acum. Shadow rămâne
activ (R4). EXCLUSIV DEFENSIV: pasul 3 doar DETECTEAZĂ; nicio blocare (aia e pasul 9).

## 0. Reconciliere cu ce există deja (CITEȘTE ÎNTÂI)

Survey 2026-10-29 pe ~/lab. NU reconstruim ce există; umplem golurile.

| Componentă PASUL 3 | Stare azi | Ce face pasul 3 |
|---|---|---|
| Plumbing import reguli Kibana | EXISTĂ (`deploy/kibana/honeytoken_rules.py` basic auth elastic → spațiu default; tier3 via ApiKey `KIBANA_TIER3_API_KEY` → spațiu `tier3`) | reutilizează; nu rescrie |
| Pipeline gap_detect → draft → shadow 7z → promote | EXISTĂ complet (`rules.py`, `kibana_rules.py`, `tier3.py`; `SHADOW_DAYS=7`; auto-off >20/h) | regulile noi behavioral intră în calibrarea shadow (scrise de mână, nu prin draft model) |
| Bypass escaladare (honeytoken/sensor/native) | EXISTĂ, dar în `fast_path.py` (floors `:546-571`) + `escalation.py` (`EscalationReason.HONEYTOKEN/SENSOR_DETECTION/NATIVE_DETECTION`) — **NU în l1_agent.py** | adaugă `BEHAVIORAL` (+`RARITY` dacă lipsește) acolo, nu în l1_agent |
| Hunt ES\|QL (cron/ssh_key/identity/tmp_exec/shell_network/setuid/shadow_read/credential_grep/ids_high) | EXISTĂ ca hunt Tier-2 (`hunt.py:87-158`) → produc Cases, NU reguli real-time | rămân hunt; promovăm la reguli real-time DOAR golurile web-centrice (vezi 3.A) |
| Honeytoken `.env.bak` + citiri auditd | EXISTĂ (`honeytokens.py`, `deploy/web-prod/honeytokens.sh`, `auditd-fim.md`) | EXTINDEM cu setul WordPress/MySQL (3.C) |
| Baseline raritate | PARȚIAL/altfel (parent-child 90z `fast_path.py:223`; baseline-entity via transforms; beacon/DNS `anomalies.py:147,172`) | adăugăm absența pe executable/listen_port/cron_hash (3.B) |
| Integritate (telemetry-silence, canar-missing, servicii) | PARȚIAL, dar alertează prin Discord (`canary_check.py`, `absence_check.py`), NU scrie în soc-incidents | adăugăm canar-HASH, fleet-server, și scriere `integrity_alert`→soc-incidents (3.D) |
| AIDE (FIM gazdă) | LIPSEȘTE (FIM Elastic abandonat, `auditd-fim.md:41`) | îl adăugăm (3.E, G9) |

Corecții din addenda aplicate: A3 (Defend eBPF nu emite read → reguli pe
`logs-auditd_manager.*`, deja tiparul din honeytokens.py); A4 (wp-config via auditd openat
cu `exe!=` + user MySQL `wp_backup`); A5 (mu-plugin pentru login, nu body apache.access);
A6 (alertele de „absență" = Elasticsearch query rule „count below 1", NU threshold); G9 (AIDE).

## Realități de lab care constrâng planul

- `source.ip` extern = **172.30.6.133** (flotant atacator, SNAT). Honeytoken hit de la
  BENIGN_GEN_IPS/self → `config_error`, nu malicious.
- Câmpul `host` e OBIECT (`host.name`), nu string — regulile EQL filtrează `host.name == "web-prod"`.
- Licență ES **basic**: fără conectori Kibana email/webhook. Alertele ES query „count below 1"
  se creează, dar notificarea umană merge prin `notify.py`/Discord (deja, pasul 0.4).
- Deploy: es-node-1 e clonă git divergentă → deploy prin **scp** (nu git). **sudo pe es-node-1
  cere parolă** (fără NOPASSWD) → pașii cu sudo îi rulezi TU (`ssh -t ... sudo ...`); eu fac
  scp + verificări read-only. Import reguli Kibana în spațiul default = basic auth elastic → TU.

## Dependențe (blochează sub-bucăți)

- **soc-reader (gate SSH read-only pe web-prod, pasul 1b/6.2) — NEFĂCUT.** Atenție: `ES_READER_API_KEY`
  creat la 1b e cheia de CITIRE ES, NU gate-ul SSH `soc-reader` de pe web-prod. 3.B (cron_hash)
  și 3.D (canar-HASH) au nevoie de gate-ul SSH soc-reader ca să citească hash-uri de pe web-prod.
  → fie facem întâi 1b (soc-reader gate), fie amânăm doar cron_hash/canary-hash.
- **benign-ground-truth (pasul 4) — NEEXISTENT.** Calibrarea listelor albe (3.A) și excluderea
  ferestrei de update pentru AIDE (3.E) se bazează pe el. Până atunci: liste albe din baseline
  7 zile existent; excludere manuală a ferestrei soc-wp-update.

---

## 3.A — Reguli EQL comportamentale în timp real (Kibana, spațiu default)

Doar golurile web-centrice pe care Defend native + hunt.py NU le prind în timp real:

a) **soc-web-spawns-shell** (T1059.004, T1505.003): `process where event.type=="start" and
   process.parent.name in ("apache2","php-fpm8.3","php-fpm","php","php8.3") and process.name in
   ("sh","bash","dash","python3","perl","ruby","curl","wget","nc","ncat","socat","base64")`.
b) **soc-php-written-in-webroot** (T1505.003): `file where event.type in
   ("creation","change","rename") and file.path like~ "/var/www/*" and file.extension in
   ("php","phtml","phar","php5","php7","php8","phps","inc") and not process.name in
   ("php","wp","rsync","apt","dpkg") and not process.executable like~ "/usr/bin/php*"`.
   (Notă A5: crearea mu-plugin-ului din 3.C va declanșa asta — e așteptat; etichetă benign o
   dată + hash în baseline.)
c) **soc-wwwdata-unexpected-exec** (T1059): `process where event.type=="start" and
   user.name=="www-data" and not process.executable in (<listă albă din baseline 7z>)`.
d) **soc-webprod-new-outbound** (T1071, T1041): `network where event.type=="connection_attempted"
   and host.name=="web-prod" and network.direction=="egress" and not destination.ip in
   (<baseline 7z>) and not cidrmatch(destination.ip,"192.168.10.0/24") and not
   destination.port in (53,123)`.
e) **soc-wwwdata-writes-outside-webroot**: `file where event.type in ("creation","change") and
   user.name=="www-data" and not file.path like~ "/var/www/*" and not file.path like~ "/tmp/*"
   and not file.path like~ "/var/lib/php/sessions/*"`.
f) **soc-apache-reads-shadow** (T1003.008) — DOAR auditd (A3): `logs-auditd_manager.*`,
   `auditd.data.key=="soc_shadow_read"`; regulă auditd `-a always,exit -F arch=b64 -S openat,open
   -F path=/etc/shadow -F perm=r -F uid=<www-data> -k soc_shadow_read`.

Restul (cron/ssh_key/identity/tmp_exec/setuid/shell_network) rămân hunt.py (deja acoperite);
nu le dublăm ca reguli real-time decât dacă calibrarea arată că sweep-ul întârzie.

**A. Fișiere:** modul nou `behavioral_rules.py` (dict-uri EQL, model_config extra=forbid unde
sunt obiecte), reutilizează `honeytokens.kibana_payload`; `build_whitelists.py` (agregare terms
pe `process.executable` unde user.name=www-data și pe `destination.ip` egress, 7z, min_doc_count≥3)
scrie listele albe în regulile c) și d) înainte de import. Tag `soc-behavioral` + `shadow-review`.
**B. Comenzi:** eu rulez build_whitelists (read-only ES); TU imporți în Kibana (basic auth elastic),
regulă auditd pentru f) în policy auditd_manager (TU, Fleet). **C. Verificare:** `_find?filter=tags:soc-behavioral`
→ regulile enabled; test benign (curl normal) → 0 alerte; test comportament (`sudo -u www-data
/usr/bin/uptime`) → alertă c). **D. Metrică:** soc-metrics type=detection (rules_active_behavioral,
alerts_behavioral_24h). **E. Rollback:** DELETE reguli după tag; scoate regula auditd.
**Escaladare:** `escalation.py` + `EscalationReason.BEHAVIORAL` pentru a,f (web-spawns-shell,
shadow-read) → escalate_human direct; diff arătat.

## 3.B — Sweep de raritate pe absență (es-node-1)

Gol: absența pe executable/listen_port/cron_hash față de baseline 7z (parent-child 90z există deja).
**A. Fișiere:** index `baseline-rarity` (cheie `ES_BASELINE_WRITER_API_KEY` scoped) SAU extindere
`EntityType` (`schemas.py:59`) cu executable/listen_port/cron_hash; sweep în `anomalies.py` care
emite `RarityFinding` pentru entity_value absentă din baseline 7z → soc-incidents type=rarity_alert
(coada orchestratorului îl ia ca alertă, ca la parent-child). Surse: executable ←
logs-endpoint.events.process; listen_port ← logs-system.socket; cron_hash ← **soc-reader gate**
sha256 (DEPENDENȚĂ 1b). **B–E:** build_baseline o dată (7z, approved_by=baseline); apoi doar
etichetare umană adaugă; verificare cu un executabil nou rulat ca www-data → rarity_alert.

## 3.C — Honeytokens WordPress/MySQL (web-prod, root, OK per comandă)

Extinde `honeytokens.py` + `deploy/web-prod/honeytokens.sh` (setul `.env.bak` rămâne). Backup
wp-config întâi (`cp wp-config.php wp-config.php.pre-honey.$(date +%s)`). Tag `soc-honeytoken`
(escalation.py are deja HONEYTOKEN reason). Toate citirile de fișier → auditd (A3).

- **wp-config decoy**: constantă falsă `DB_PASSWORD_BACKUP`; auditd (A4, fără zgomot):
  `-a always,exit -F arch=b64 -S openat,open -F path=/var/www/html/wp-config.php -F perm=r
  -F exe!=/usr/sbin/apache2 -F exe!=/usr/sbin/php-fpm8.3 -F exe!=/usr/bin/php8.3 -k soc_honey_wpconfig`
  (verifică binarele exacte cu `readlink -f`).
- **MySQL `wp_backup`** (A4, momeala care contează): `CREATE USER 'wp_backup'@'%' ... ` fără GRANT;
  în wp-config `DB_BACKUP_USER/PASSWORD`; MariaDB `log_warnings=2`; integrare Fleet **mysql** (error
  log) pe web-prod; KQL `logs-mysql.error*` `message:*wp_backup*` → critical.
- **mu-plugin `soc-honey.php`** (A5): hook `wp_login_failed`+`wp_login`+`authenticate`,
  `error_log("SOC_HONEY user=<u> ip=<REMOTE_ADDR>")`; KQL `logs-apache.error*` `message:"SOC_HONEY"`.
  (Declanșează 3.A-b la creare → etichetă benign o dată + hash în baseline.)
- **backup.sql decoy** (2KB inert): auditd read `-k soc_honey_sql` + KQL apache `url.path:"/backup.sql"
  and status 200/206/304`.
- **robots.txt**: `Disallow: /wp-admin-old/`, `/db-backup/` + directoare goale; KQL trap.
- **.credentials.txt** (opțional): `/wp-content/uploads/.credentials.txt`; auditd read + GET.

config_error: hit de la BENIGN_GEN_IPS/self → nu honeytoken, ci escalate_human tag config_error.

## 3.D — Monitor de integritate → soc-incidents (es-node-1)

Gol: scrierea `integrity_alert` în soc-incidents (azi doar Discord) + canar-HASH + fleet-server.
Extinde `absence_check.py` (NU duplica; are deja telemetry-silence, canar-missing, servicii) sau
`soc-integrity` nou:
- `check_canary_hash()`: soc-reader gate `sha256sum /usr/local/bin/soc-canary /etc/cron.d/soc-canary`
  vs `/etc/soc/canary.sha256` (DEPENDENȚĂ 1b soc-reader).
- `check_fleet_server()`: `GET https://localhost:8220/api/status` != HEALTHY.
- `emit(kind)`: scrie `{type:"integrity_alert", kind, severity:critical, ts, evidence}` în
  soc-incidents (dedup 10 min) + păstrează notify.py. Orchestratorul preia integrity_alert ca
  critical → escalate_human fără model.
- A6: regula de rezervă „integrity_checker_down" = Elasticsearch query rule „count below 1" pe
  soc-audit type=integrity_check în 5 min (NU threshold).

## 3.E — AIDE (web-prod, root, OK) — G9

`apt install aide`; `aide.conf` acoperă /etc, /usr/local/bin, /usr/sbin, /var/www/html minus
wp-content/uploads și wp-content/cache; `aide --init` după pasul 0 și după fiecare `soc-wp-update.sh`
(re-init automat în script, logat); timer 03:30 `aide --check` → `logger -t aide`; KQL
`logs-system.syslog*` `process.name:"aide" and message:*changed*` → high, intră în Tier 1 cu
excluderea ferestrei de update (din benign-ground-truth când există; până atunci manual).

## 3.F — Wiring: shadow + escalare

- Reguli noi (3.A, 3.C) cu tag `shadow-review`; verdictele lor `shadow_review=true` 7 zile pentru
  calibrare (ca restul pipeline-ului existent).
- `escalation.py`: adaugă `EscalationReason.BEHAVIORAL` (și `RARITY` dacă nu există) la set;
  diff arătat (R12). Floors în `fast_path.py` rămân sursa pentru honeytoken/sensor.
- gap_detect/draft/promote existent: regulile behavioral scrise de mână NU trec prin draft model,
  dar intră în fereastra de calibrare shadow.

## Ordine de implementare propusă

1. (dacă facem) **1b soc-reader gate** întâi — deblochează 3.B cron_hash + 3.D canary-hash.
2. **3.A** reguli EQL web-centrice + escalation.BEHAVIORAL (valoarea cea mai mare, independent).
3. **3.C** honeytokens WP/MySQL (web-prod, root).
4. **3.D** integritate → soc-incidents + fleet + canary-hash.
5. **3.E** AIDE.
6. **3.B** rarity-absență (depinde de soc-reader pentru cron_hash; executable/listen_port merg fără).
Fiecare lot de reguli: 7 zile shadow înainte de promovare.

## Condiții de oprire specifice pasului 3

- orice regulă/acțiune ar bloca sau escalada automat un IP din never_block → oprire (pasul 3 e
  doar detecție; blocarea e pasul 9).
- honeytoken hit de la BENIGN_GEN_IPS/self tratat ca malicious (trebuie config_error).
- o regulă comportamentală generează zgomot masiv pe trafic benign cunoscut → recalibrare listă
  albă, NU dezactivare tăcută.

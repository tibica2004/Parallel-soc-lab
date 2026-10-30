# Stare: extinderea defensiva (plan-0day) — oprit la 2026-10-29

Ramura: faza-21-protectie (nepublicata, fara push). Planul complet: docs/plan-0day.md.
Detaliile pasului 0 (fisiere, comenzi, verificare, metrica, rollback): docs/pasi/pas-00.md.
Sesiunea Claude ruleaza pe elastic-lab vechi (172.20.99.220); hosturile se ating doar
prin IP-urile flotante: es-node-1 172.30.6.106, web-prod 172.30.6.249, atacator 172.30.6.133.

## Facut (si verificat pe hosturi)

| Bucata | Ce exista acum | Verificat |
|---|---|---|
| Plan | docs/plan-0day.md: pasii 0-12b reconciliati cu codul existent | — |
| 0.1 Backup | web-prod: soc-backup.timer 01:30 (baza wp + grants + webroot, sha256, 14 zile); es-node-1: soc-backup-pull.timer 02:15 (cheie soc-backup doar `rrsync -ro`, 30 zile); soc-backup-restore-test.sh | backup OK, cheia refuza `ls /`, pull OK, restore 12 tabele |
| 0.2 Patch-uri | unattended-upgrades fara reboot + syslog; WordPress fara auto-update (AUTOMATIC_UPDATER_DISABLED, WP_AUTO_UPDATE_CORE=false, DISALLOW_FILE_EDIT); wp-config root:www-data 640; soc-wp-update.timer 02:00 in mod raport (APPLY=0) | HTTP 200, 0 update-uri disponibile |
| 0.3 web-prod | firewall nft `inet soc_fw` (soc-fw.service): 80/443 oricine, 22 doar es-node-1 + 172.20.99.220 | SSH admin OK, SSH de pe es-node-1 OK, 22 inchis pentru atacator |
| 0.3 es-node-1 | firewall nft `inet soc_fw` (soc-fw.service): 22/5601/8088 doar admin, 8220 din es-net, forward_guard filtreaza Docker (9200 doar web-prod+benign-gen, 5601 doar admin, IPv6 9200/5601 drop) | SSH admin OK, ES de pe web-prod 401 + telemetrie vie (_count=453/5min), ES de pe atacator BLOCKED, 8220 TCP open din web-prod, stiva activa; agent Healthy = de confirmat in Fleet UI |
| 0.4 notificari | Discord (webhook): notify.py (notify_human + maybe_notify_escalation critic: honeytoken/sensor/native), absence_check.py + soc-absence.timer (10 min: backup>26h, servicii, canar), diff orchestrator persist(). Webhook DOAR in soc.env+env.sh pe es-node-1 (R16) | deploy es-node-1 OK; soc-absence verde (backup 5.9h, servicii active, canar 0.3min); test Discord "notificare trimisa" (204); soc-orchestrator repornit cu webhook |
| 0.5 hardening Apache | web-prod: deploy/web-prod/soc-hardening.conf (drop-in, a2enconf): ServerTokens Prod, ServerSignature Off, TraceEnable Off, ServerName 192.168.10.138 (UseCanonicalName Off), xmlrpc.php Require all denied. Niciun fisier distro modificat; reload, nu restart | `Server: Apache` (fara versiune/OS), site 200, xmlrpc 403, pagina 404 fara semnatura |
| 1.A SBOM | web-prod: soc-sbom.sh (user soc-sbom, timer 03:00) -> /var/log/soc/sbom.ndjson -> Fleet Custom Logs (soc.sbom) -> logs-soc.sbom-*. Fara chei/retea pe web-prod (R16) | logs-soc.sbom-default LIVE, ultimul doc 77 componente, core apache 2.4.58 / php 8.3.6 / wp_core 7.1.3 |
| 1.B N-day watch | es-node-1: nday_watch.py (soc-nday.timer 04:00) citeste SBOM, NVD cu range-parsing (nvd_affects) + WPScan -> asset-vulns; hunt/patch_request plafonat (NDAY_HUNT_MIN_CVSS=9, NDAY_HUNT_MAX=10) pe new\|newly_confirmed -> soc-incidents. es_client hard-fail pe cheie lipsa. Chei in soc.env: 3 writer + ES_READER (soc-reader) | exit 0, idempotent (224->224); 224 vulns (118 confirmate/106 needs_review), 114 cu patch; 10 hunt + 10 patch_request; teste 22/22 |

Constatari pe parcurs:
- Ollama pe GPU asculta pe 0.0.0.0:11434 (setat explicit; modelele sunt in /home/laura).
  Atacatorul NU ajunge la el (timeout). Legarea pe 127.0.0.1 doar cu acordul Laurei;
  tunelurile (SOC si OpenClaw) merg si dupa. Modelul qwen3:14b neatins (ID bdbd181c33f2).
- web-prod fara IPv6 global; licenta ES = basic (fara conectori email/webhook in Kibana).
- es-node-1 are un singur disc: copia de backup sta langa ES (exceptie temporara).

## PASUL 0 + 1 + 1c COMPLET (SBOM, N-day watch, soc-metrics). Urmatorul: PASUL 3

Pasul 0 (protectie imediata) e inchis si verificat pe hosturi. Rezumat raport PASUL 0:
- 0.1 backup zilnic web-prod + copie trasa pe es-node-1 (cheie doar rrsync -ro) + restore test.
- 0.2 unattended-upgrades fara reboot; WordPress fara auto-update; wp-config root:www-data 640;
  soc-wp-update in mod raport.
- 0.3 firewall nft propriu (inet soc_fw) pe ambele hosturi, separat de Docker, revert la 10 min.
- 0.4 notificari Discord (escaladari critice + alerte de absenta la 10 min). ACTIV.
- 0.5 hardening Apache (semnatura ascunsa, xmlrpc blocat). ACTIV.

Blocaje/limite stiute: agent Healthy in Fleet = de confirmat vizual (0.3); etichetarea
>=100 alerte ramane drumul critic pentru pasul 8; benign-ground-truth/regulile 3.x inca
nu exista (de aceea 0.5 nu scrie etichete benign inca).

PASUL 1 FACUT (1.A SBOM + 1.B N-day watch), verificat pe host 2026-10-29. SBOM pe web-prod
(soc-sbom.timer 03:00 -> logs-soc.sbom-*) + nday_watch.py pe es-node-1 (NVD cu range-parsing
pentru Apache/PHP/WP core, WPScan pentru plugin-uri) -> asset-vulns (224 vulns, idempotent)
+ hunt/patch_request plafonat in soc-incidents (10+10). soc-nday.timer 04:00. Detalii si
acceptare in docs/pasi/pas-01.md.

PASUL 1c FACUT (2026-10-29): soc-metrics exista deja si e scris de orchestrator (672 docs);
confirmat ca sink, agregabil pe type.keyword, cheile ES_METRICS_WRITER + ES_READER OK.
nday aliniat la @timestamp (ca orchestratorul). Gol pentru pasul 7: docurile orchestrator
nu au `type` (666/672) — de adaugat type="cycle" la write_cycle_metrics. Detalii: pas-01c.md.

PASUL 3.A IN CURS (2026-10-29): reguli comportamentale fara semnatura. COD GATA + testat
(124 teste) + commitat (a73f95d, 9f634f0, 9af9647): behavioral_rules.py (6 reguli EQL:
web->shell, PHP in webroot, www-data exec nevazut, outbound nou, scriere in afara webroot,
citire /etc/shadow via auditd), build_whitelists.py (liste albe din baseline 7z, cu
NEVER_WHITELIST care exclude recon - baseline contaminat de atac), escalation.BEHAVIORAL,
importer extins. DEPLOYAT pe es-node-1 (scp, sha256 verificat; divergenta investigata =
doar modificarile mele 3.A, es-node-1 era baza curata). Liste albe generate+curatate pe
es-node-1: wwwdata_exec=[dash, php8.3] (id/env excluse ca recon), 8 egress externe.
soc-orchestrator = Type=simple (cod vechi pana la restart).
VERIFICAT pe host 2026-10-29: cele 6 reguli `pornita` in Kibana (verifica); test live
`sudo -u www-data /usr/bin/uptime` pe web-prod -> soc-wwwdata-unexpected-exec a declansat
in ~1 min (sev high, tags soc-behavioral+shadow-review). Detectia fara semnatura merge
end-to-end; curatarea listei albe confirmata (uptime neinclus -> alerta; dash/php8.3 nu).

RAMAS de facut de om pentru 3.A (nu pot: parola elastic / Fleet / sudo):
- Step 2: import reguli in Kibana: `ssh tiberiu@172.30.6.106 'cd ~/lab && source env.sh &&
  python3 deploy/kibana/honeytoken_rules.py verifica'` apoi `... aplica` (contul elastic).
- Step 3: regula auditd pe web-prod (ca regula f sa alerteze): in policy auditd_manager (Fleet)
  `-a always,exit -F arch=b64 -S openat,open -F path=/etc/shadow -F perm=r -F uid=<www-data> -k soc_shadow_read`.
- Step 4: `ssh -t tiberiu@172.30.6.106 'sudo systemctl restart soc-orchestrator'` (activeaza
  escaladarea BEHAVIORAL; pana atunci podelele fast_path escaladeaza oricum alertele web).
Regulile intra in fereastra shadow-review 7 zile inainte de promovare.

Urmeaza dupa 3.A: 3.C honeytokens WP/MySQL, 3.D integritate->soc-incidents, 3.E AIDE,
3.B raritate. Apoi pasii 2, 4, 7, 6, 5, 8, 9, 10, 11, 12, 12b. Draft A-E complet: pas-03.md.

## PASUL 3.D (monitor de integritate) — FACUT 2026-10-30

Cod f719c06 + 4046536 (detalii A-E: docs/pasi/pas-03d.md). absence_check.py extins (timer la
1 min, AccuracySec=1s): tacere pe 7 fluxuri web-prod (prag din pauzele reale; Suricata pe
agent.name, n-are host.name; Apache exclus), fleet-server /api/status (HTTP :8220),
integrity_alert Pydantic in soc-incidents (ES_INCIDENTS_WRITER, dedup 10 min), puls
integrity_check in soc-metrics (ES_METRICS_WRITER); orchestratorul pagineaza daca pulsul
lipseste > 5 min (paza reciproca). Deployat (*.pre-3d), unitati instalate, orchestrator repornit.
Verificat: puls ok la ~1 min, 0 integrity_alert false, exit 0.
Amanat: hash canar (cere gate soc-reader, 1b); stare agent din Fleet API (cheie Kibana fleet:read).
De facut la pasul 7: mapping explicit pe soc-metrics (create_doc a extins mapping-ul automat;
ES avertizeaza ca nu va mai fi permis). Notat pentru 11/12: eve.json 545 MB pe web-prod, nerotit?
Test negativ ramas (optional, cu OK): oprirea soc-absence.timer 6 min -> Discord "monitorul tace".

## PASUL 3.C (honeytokens WordPress/MySQL) — FACUT si verificat 2026-10-30

Cod: de10129, f90057b, 2407d7e, 09e11d2 (+ diagnostic d19fe57). Detalii A-E: docs/pasi/pas-03c.md.
Fara conturi reale (wp_backup MySQL si backup_admin WP NU exista: orice incercare e logata).
Plantat pe web-prod (copii in /root/soc-pre-honey-20261030T072907Z), cod pe es-node-1 (*.pre-3c),
BENIGN_GEN_IPS in soc.env, 6 reguli soc-honey-* in Kibana (10 honeytoken in total), orchestrator
repornit (activeaza si BEHAVIORAL din 3.A). web-prod: mod_php in apache2 (fara php-fpm), MariaDB
10.11 log_warnings=2, jurnal in journald -> logs-system.syslog.

Teste (HTTP de pe es-node-1: boxa admin NU ajunge pe 80 la web-prod, doar 22):
- T1 /backup.sql -> backup-sql-http 36 s; T2 /db-backup/ -> robots-trap; T3 login backup_admin ->
  wp-login 33 s; T4 mysql wp_backup -> mysql-user 26 s; T5 curl local -> motiv
  honeytoken_config_error (fara Discord). Orchestrator: 5/5 escaladate (3 Tier 2, 2 peste buget).
- T7 head backup.sql -> backup-sql-read; T8 cat wp-config (refuzat) -> wpconfig-read. 5 cereri
  la site -> 0 evenimente wp-config (excluderea apache2 merge).

GOTCHA MAJOR — kernelul de audit pe web-prod e IMUABIL (enabled=2, optiunea Immutable din
auditd_manager): dupa incarcarea regulilor, kernelul refuza orice schimbare pana la reboot. Fleet
ramane "Healthy" si nu apare nicio eroare; auditbeat sare tacut peste reguli. Simptom: regulile
noi nu prind nimic, cele vechi da. Diagnostic: deploy/web-prod/audit-status.py (sudo; auditctl -s
prin netlink, fara pachetul auditd, care ar fura socketul). ORICE regula auditd noua = Fleet +
REBOOT web-prod. Rebootat 08:10: 19/19 reguli (18 + ignore-self), din nou blocat. Decizie: Immutable
ramane pornit (atacatorul cu root nu poate opri auditul fara reboot, iar reboot-ul se vede).
- Fleet: un rand rupt in campul Audit rules (soc_kmod) a facut configul invalid din 29.10 14:57
  ("failed to unpack the auditd config") pana azi 07:43. CORECTIE (masurat la 3.D): colectarea NU
  s-a oprit (pauza max 4 min in 3 zile); componenta veche a mers mai departe, doar configurile noi
  nu se aplicau. Lipeste doar randuri intregi.
- kernel lost=2632 evenimente auditd de la boot-ul din 26.10 -> de urmarit la pasul 7.
- YARA (soc-yara-scan) citea momelile -> fals pozitive la 10 min. Fix: backup.sql sarit dupa cale,
  wp-config.php inca scanat iar regula wpconfig-read exclude /usr/bin/yara (excludere in Kibana,
  nu in kernel, ca sa nu mai cerem un reboot).
- De etichetat benign: soc-php-written-in-webroot la plantare (07:29-07:33), yara 08:13-08:17,
  "Payload download: curl/wget" din testele mele (curl din bash), testele T1-T8.

## Sesiune 2026-10-29 (continuare): acces de pe boxa veche + constatari retea

Model de lucru confirmat: sesiunea Claude ruleaza inca pe elastic-lab vechi (172.20.99.220);
Claude da comenzile, le ruleaza de aici si intoarce rezultatele. Deblocat prin doua reguli
in ~/.claude/settings.json (user): `Bash(ssh tiberiu@172.30.6.106:*)` (es-node-1) si
`Bash(ssh tiberiu@172.30.6.249:*)` (web-prod). SSH testat pe ambele; atacatorul prin MCP
opencyber-attacker (ruleaza chiar pe VM-ul atacator, 10.10.0.220). Editarea propriilor
permisiuni ramane blocata (Self-Modification) — o face omul.

Constatari (conteaza pentru pasul 9 si pentru retragerea boxei vechi):
- **source.ip pe web-prod = 172.30.6.133** (IP-ul FLOTANT al atacatorului, SNAT), NU
  10.10.0.220. Dovada: logs-apache.* are 125.821 docs de la 172.30.6.133 (atacurile
  "purple-0day-agresiv"). Routerul OpenStack rescrie adresa interna la L3.
- **never_block (pasul 9) trebuie lista de IP-uri specifice, nu un CIDR**: IP-ul blocabil
  al atacatorului (172.30.6.133) e in ACELASI 172.30.6.0/24 cu infrastructura care nu
  trebuie blocata (es-node-1 172.30.6.106, web-prod self 172.30.6.249, IP admin). Deci
  WP_SELF_IPS/never_block enumera exact acele flotante; BENIGN_GEN_IPS si logica
  honeytoken config_error cheie pe 172.30.6.133 pentru "atacatorul din lab".
- **A10/c9 e blocaj real pentru pasul 9 in topologia asta (nu pentru detectie)**: tot
  traficul extern se prabuseste pe un singur IP SNAT (172.30.6.133). block_ip_ttl pe
  source.ip ar bloca acel unic flotant = toata calea externa; mod_remoteip/XFF nu ajuta
  (nu exista proxy aplicativ, e SNAT L3 de router); criteriul c9 ("≥5 source.ip externe
  distincte") e de neatins. Detectia (pasii 1-3) coreleaza bine; doar blocarea automata
  (pasul 9) devine grosiera — de decis: block_ip_ttl manual-only in lab, sau test din mai
  multe flotante de atacator.
- **atacator → web-prod:80 e functional si stabil** (5/5 × 200 OK, ~5 ms). Timeout-ul
  initial a fost un tranzitoriu unic (primul pachet pe cale "rece" ~15 ms). web-prod: Apache
  active, asculta *:80; nft soc_fw accepta 80/443 de la oricine.
- **GOTCHA la retragerea boxei vechi**: nft soc_fw pe web-prod permite SSH 22 doar de la
  192.168.10.121 (es-node-1) si @admin_v4={172.20.99.220} = BOXA VECHE (hostul sesiunii).
  Inainte de a retrage boxa veche: adauga noul IP de control in admin_v4 pe web-prod SI
  es-node-1 (`sudo nft add element inet soc_fw admin_v4 { <IP_nou> }` + in deploy/*/soc-fw.nft),
  altfel pierzi SSH-ul la hosturi.

## De facut de om (oricand)

- [ ] **PASUL 1.B — DEPLOYAT si verificat pe host 2026-10-29 (functional complet).**
  SBOM soc.sbom -> logs-soc.sbom-default LIVE; cele 4 chei (3 writer + ES_READER) in
  /home/tiberiu/lab/soc.env (600); soc-nday.service+timer instalate (04:00). nday_watch
  ruleaza exit 0, idempotent. Stare: asset-vulns 224 vulns (118 confirmate / 106
  needs_review), 114 cu patch; soc-incidents 10 hunt_request + 10 patch_request (top-10
  critical, plafonat). Cod: NVD range-parsing (nvd_affects), plafon hunt
  (NDAY_HUNT_MIN_CVSS=9.0, NDAY_HUNT_MAX=10), hunt pe new|newly_confirmed, es_client
  hard-fail pe cheie lipsa. Teste 22/22. RAMAS de facut de om, optional:
  1. **Prerequisit 0 (recomandat la 1c/tier3):** ES_API_KEY principal are `read:false`
     pe asset-vulns + soc-incidents. Am creat cheia `soc-reader` ca ES_READER_API_KEY
     (separata, folosita la verificare); NU am inlocuit ES_API_KEY (ar fi pierdut
     soc-traces/baseline-entity-parentchild). Cand wireuim tier3 sa consume hunturile,
     fie largim rolul lui ES_API_KEY cu asset-vulns+soc-incidents, fie wireuim ES_READER.
  2. WPSCAN_API_KEY (optional): fara el, cele 4 plugin-uri/teme raman needs_review.
  Note: s-a facut un reset unic al flagului hunt_requested (poluare de la rularile cu cod
  vechi, dinainte de fix). Nu se repeta (codul vechi nu mai exista).
- Kibana -> Security -> Alerts: nicio alerta de momeala (.env.bak) dupa backup-urile din
  28.10 de la 11:01 incoace? (ultima confirmare pentru 0.1)
- Laptop (varianta B): cheie, IP, security groups, setul admin_v4 — comenzile sunt in
  conversatie; IP-ul se adauga in deploy/*/soc-fw.nft si live cu
  `sudo nft add element inet soc_fw admin_v4 { <IP> }`.
- 0.4 e activ pe Discord. Daca transcriptul conversatiei nu e strict privat,
  regenereaza webhook-ul in Discord si actualizeaza soc.env+env.sh pe es-node-1.
- Laura: are nevoie de Ollama din retea? (decide legarea pe 127.0.0.1)
- Etichetare in interfata: >= 100 alerte (25 malicious / 25 suspicious / 25 benign) —
  drumul critic pentru pasul 8.
- Etichete benign pentru actiunile din 28.10: modificarea wp-config.php, rularile
  soc-wp-update (www-data -> python3/wp).

## Ramas

Pasul 0: FACUT COMPLET (0.1-0.5), verificat pe hosturi.
Urmeaza, in ordine D3: 1, 1b, 1c, 3, 2, 4, 7, 6, 5, 8, 9, 10, 11, 12, 12b (15 pasi),
minim 4-5 saptamani din cauza ferestrelor de asteptare (shadow 7 zile per lot de reguli).

Decizii deja luate (implicite, schimbabile): cod in ~/lab cu o ramura per pas; fara
disable_functions si fara schimbarea proprietarului webroot (altfel pica portile
harness: scenarios_fast.yml:13 si :25); update-uri WordPress doar in mod raport;
backup tras de es-node-1 (web-prod fara chei spre SOC); atacatorul fara SSH pe web-prod.

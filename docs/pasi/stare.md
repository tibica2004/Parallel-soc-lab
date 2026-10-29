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

Urmatorul in ordinea D3 (... -> 1c[FACUT] -> 3 -> 2 -> ...): PASUL 3 = detectie
comportamentala fara semnatura (reguli EQL), honeytokens, monitor de integritate, sweep de
raritate. Nucleul defensiv, cel mai mare pas. Draft A-E in pas-03.md.

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

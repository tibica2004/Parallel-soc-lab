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

Constatari pe parcurs:
- Ollama pe GPU asculta pe 0.0.0.0:11434 (setat explicit; modelele sunt in /home/laura).
  Atacatorul NU ajunge la el (timeout). Legarea pe 127.0.0.1 doar cu acordul Laurei;
  tunelurile (SOC si OpenClaw) merg si dupa. Modelul qwen3:14b neatins (ID bdbd181c33f2).
- web-prod fara IPv6 global; licenta ES = basic (fara conectori email/webhook in Kibana).
- es-node-1 are un singur disc: copia de backup sta langa ES (exceptie temporara).

## PASUL 0 COMPLET (0.1-0.5). Urmatorul: PASUL 1 (inventar SBOM + N-day watch)

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

PASUL 1 (urmatorul, ordinea D3: 1 -> 1b -> 1c -> 3 -> 2 -> ...): inventar SBOM pe web-prod
(user soc-sbom, soc-sbom.timer 03:00 -> /var/log/soc/sbom.ndjson -> Custom Logs ->
logs-soc.sbom-*) + nday_watch.py pe es-node-1 (OSV/NVD pentru Apache/PHP/WP core, WPScan/
Wordfence pentru plugin-uri/teme) -> index asset-vulns + trigger de hunt in soc-incidents.
Detalii A-E: de scris in docs/pasi/pas-01.md inainte de rulare.

## De facut de om (oricand)

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

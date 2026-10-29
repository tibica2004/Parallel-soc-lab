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

Constatari pe parcurs:
- Ollama pe GPU asculta pe 0.0.0.0:11434 (setat explicit; modelele sunt in /home/laura).
  Atacatorul NU ajunge la el (timeout). Legarea pe 127.0.0.1 doar cu acordul Laurei;
  tunelurile (SOC si OpenClaw) merg si dupa. Modelul qwen3:14b neatins (ID bdbd181c33f2).
- web-prod fara IPv6 global; licenta ES = basic (fara conectori email/webhook in Kibana).
- es-node-1 are un singur disc: copia de backup sta langa ES (exceptie temporara).

## Urmatorul pas: 0.4 notificari umane (NERULAT)

0.3 e inchis pe ambele hosturi (vezi tabelul de mai sus si pas-00.md).

0.4: licenta ES e basic -> fara conectori email/webhook in Kibana, deci notificarea
trece printr-un bot Telegram apelat din Python pe es-node-1. De pregatit:
- Bot @BotFather: token + chat_id, pusi DOAR in env.sh pe es-node-1 (nu in repo, nu pe
  web-prod — R16).
- functie notify_human() apelabila din orchestrator (escalate_human severity critical,
  dedup 15 min per case_id) si dintr-un script de "alerte de absenta".
- alerte de absenta (fara conector Kibana): script/timer pe es-node-1 care verifica si
  trimite pe Telegram: backup > 26 h (ultimul `soc-backup OK` in logs-system.syslog-*),
  orchestrator fara scriere recenta (soc-audit/heartbeat), canar lipsa.
Detalii si format A-E: de scris in pas-00.md la 0.4 inainte de rulare.

## De facut de om (oricand)

- Kibana -> Security -> Alerts: nicio alerta de momeala (.env.bak) dupa backup-urile din
  28.10 de la 11:01 incoace? (ultima confirmare pentru 0.1)
- Laptop (varianta B): cheie, IP, security groups, setul admin_v4 — comenzile sunt in
  conversatie; IP-ul se adauga in deploy/*/soc-fw.nft si live cu
  `sudo nft add element inet soc_fw admin_v4 { <IP> }`.
- Bot Telegram (@BotFather) pentru 0.4; token + chat_id doar in env.sh pe es-node-1.
- Laura: are nevoie de Ollama din retea? (decide legarea pe 127.0.0.1)
- Etichetare in interfata: >= 100 alerte (25 malicious / 25 suspicious / 25 benign) —
  drumul critic pentru pasul 8.
- Etichete benign pentru actiunile din 28.10: modificarea wp-config.php, rularile
  soc-wp-update (www-data -> python3/wp).

## Ramas

Pasul 0: 0.3 es-node-1 -> 0.4 notificari (Telegram din Python, alerte de absenta:
backup > 26 h, orchestrator, canar) -> 0.5 hardening Apache (ServerTokens Prod,
ServerSignature Off, TraceEnable Off, xmlrpc.php blocat) -> raport PASUL 0.
Apoi, in ordine: 1, 1b, 1c, 3, 2, 4, 7, 6, 5, 8, 9, 10, 11, 12, 12b (15 pasi), minim 4-5
saptamani din cauza ferestrelor de asteptare.

Decizii deja luate (implicite, schimbabile): cod in ~/lab cu o ramura per pas; fara
disable_functions si fara schimbarea proprietarului webroot (altfel pica portile
harness: scenarios_fast.yml:13 si :25); update-uri WordPress doar in mod raport;
backup tras de es-node-1 (web-prod fara chei spre SOC); atacatorul fara SSH pe web-prod.

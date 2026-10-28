# Stare: extinderea defensiva (plan-0day) — oprit la 2026-10-28

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

Constatari pe parcurs:
- Ollama pe GPU asculta pe 0.0.0.0:11434 (setat explicit; modelele sunt in /home/laura).
  Atacatorul NU ajunge la el (timeout). Legarea pe 127.0.0.1 doar cu acordul Laurei;
  tunelurile (SOC si OpenClaw) merg si dupa. Modelul qwen3:14b neatins (ID bdbd181c33f2).
- web-prod fara IPv6 global; licenta ES = basic (fara conectori email/webhook in Kibana).
- es-node-1 are un singur disc: copia de backup sta langa ES (exceptie temporara).

## Urmatorul pas: 0.3 pe es-node-1 (NERULAT)

Comenzile E1-E4 (copiere, incarcare cu stergere automata la 10 min, teste, permanentizare)
sunt in conversatie si rezumate in pas-00.md la 0.3. Testele critice: "ES de pe web-prod"
= 401 si `_count` pe logs-* de la web-prod > 0 (altfel firewall-ul ar taia telemetria).
Daca un test pica: NU rulezi E4; tabelul dispare singur in 10 minute.

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

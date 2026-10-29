# PASUL 0 — protectie imediata

Ramura faza-21-protectie. Pasul se livreaza pe bucati; fiecare bucata are A-E si
se aplica doar dupa aprobare, comanda cu comanda.

Fapte verificate (2026-10-28), pe care se bazeaza pasul:
- web-prod: Ubuntu 24.04, ens3 192.168.10.138, fara IPv6 global, fara firewall
  (nft gol, ufw inactiv); asculta 22 (toate interfetele), 80, MariaDB doar pe
  127.0.0.1; rsyslog, mariadb, apache2, unattended-upgrades active; disc 30 GB liberi.
- es-node-1: ens3 192.168.10.121; Docker pe iptables-nft (tabelele ip/ip6 nat, filter,
  raw); 5601 si 9200 publicate pe 0.0.0.0 si [::] prin docker-proxy; Fleet Server pe
  *:8220; un singur disc (vda, 135 GB liberi), fara volum separat.
- Administrarea vine de la 172.20.99.220 (elastic-lab vechi) pe ambele hosturi.
- GPU: Ollama pe 0.0.0.0:11434 (setat explicit), modele in /home/laura; atacatorul NU
  ajunge la el (timeout); ambele tuneluri fac -L 11434:localhost:11434. Licenta ES: basic.

Bucatile: 0.1 backup (aici) -> 0.2 patch -> 0.3 firewall -> 0.4 notificare -> 0.5 hardening Apache.

## 0.1 Backup web-prod + copie trasa pe es-node-1

### A. Fisiere (toate noi)
- deploy/web-prod/soc-backup.sh -> /usr/local/bin/soc-backup.sh (root, 755): mysqldump
  --all-databases + tar (/var/www/html, /etc/apache2, /etc/php), gzip -t / tar -t,
  SHA256SUMS-<zi>, retentie 14 zile, `logger -t soc-backup OK|EROARE`.
- deploy/web-prod/soc-backup.exclude -> /usr/local/etc/soc-backup.exclude: momeala
  .env.bak si cache-ul. Motiv: tar ar citi momeala in fiecare noapte (regula auditd de
  citire exclude doar /opt/Elastic/*); lista sta in fisier, nu pe linia de comanda,
  pentru ca regula de folosire a momelii cauta ".env.bak" in process.command_line.
- deploy/web-prod/soc-backup.service/.timer: oneshot root, ProtectSystem=strict,
  scrie doar in /var/backups/soc; zilnic 01:30, Persistent.
- deploy/soc-backup-pull.sh -> /usr/local/bin (es-node-1): rsync prin cheia soc-backup,
  verificare sha256 a copiei de azi, retentie 30 zile.
- deploy/soc-backup-pull.service/.timer: User=tiberiu, scrie doar in /var/backups/web-prod;
  zilnic 02:15.
- deploy/soc-backup-restore-test.sh -> /usr/local/bin (es-node-1): restaureaza ultima
  copie intr-un container mariadb:10.11 fara retea, verifica >= 10 tabele in `wp` si
  wp-config.php + version.php in arhiva; containerul se sterge.

Abateri de la task, cu motiv: copia e trasa (nu impinsa) pentru ca G4 interzice chei pe
web-prod; testul de restore foloseste un container in loc de o VM (aceeasi verificare,
fara VM noua); copia sta pe acelasi disc cu ES (es-node-1 nu are volum separat) —
exceptie temporara; recomandat un volum Cinder dedicat.

### B. Comenzi (de pe elastic-lab, user tiberiu; sudo cere parola)

1. web-prod — copiere:
```
scp deploy/web-prod/soc-backup.sh deploy/web-prod/soc-backup.exclude deploy/web-prod/soc-backup.service deploy/web-prod/soc-backup.timer tiberiu@172.30.6.249:/tmp/
```
2. web-prod — instalare (se opreste daca rrsync lipseste, inainte de orice schimbare):
```
ssh -t tiberiu@172.30.6.249 'set -e; command -v rrsync; sudo groupadd --system soc-backup; sudo useradd --system --gid soc-backup --shell /bin/sh --home-dir /var/lib/soc-backup --create-home soc-backup; sudo install -d -o root -g soc-backup -m 750 /var/backups/soc; sudo install -o root -g root -m 755 /tmp/soc-backup.sh /usr/local/bin/soc-backup.sh; sudo install -d -m 755 /usr/local/etc; sudo install -o root -g root -m 644 /tmp/soc-backup.exclude /usr/local/etc/soc-backup.exclude; sudo install -o root -g root -m 644 /tmp/soc-backup.service /tmp/soc-backup.timer /etc/systemd/system/; rm /tmp/soc-backup.sh /tmp/soc-backup.exclude /tmp/soc-backup.service /tmp/soc-backup.timer; sudo systemctl daemon-reload'
```
   Asteptat: o cale (`/usr/bin/rrsync`), apoi nimic. Daca rrsync lipseste: stop, imi spui.
3. web-prod — prima rulare:
```
ssh -t tiberiu@172.30.6.249 'sudo systemctl start soc-backup.service; sudo ls -l /var/backups/soc; sudo journalctl -t soc-backup -n 3 --no-pager'
```
   Asteptat: db-<azi>.sql.gz, grants-<azi>.sql.gz, webroot-<azi>.tar.gz, SHA256SUMS-<azi> (root:soc-backup,
   640) si linia `OK db=... web=...`.
4. web-prod — timer:
```
ssh -t tiberiu@172.30.6.249 'sudo systemctl enable --now soc-backup.timer && systemctl list-timers soc-backup.timer --no-pager'
```
5. es-node-1 — cheie dedicata si director:
```
ssh -t tiberiu@172.30.6.106 'ssh-keygen -t ed25519 -N "" -C soc-backup@es-node-1 -f ~/.ssh/soc-backup_ed25519 && sudo install -d -o tiberiu -g tiberiu -m 700 /var/backups/web-prod'
```
6. web-prod — cheia autorizata DOAR pentru rrsync -ro, DOAR de la es-node-1:
```
PUB=$(ssh tiberiu@172.30.6.106 'cat ~/.ssh/soc-backup_ed25519.pub')
ssh -t tiberiu@172.30.6.249 "sudo install -d -o soc-backup -g soc-backup -m 700 /var/lib/soc-backup/.ssh && echo 'restrict,from=\"192.168.10.121\",command=\"/usr/bin/rrsync -ro /var/backups/soc\" $PUB' | sudo tee /var/lib/soc-backup/.ssh/authorized_keys >/dev/null && sudo chown soc-backup:soc-backup /var/lib/soc-backup/.ssh/authorized_keys && sudo chmod 600 /var/lib/soc-backup/.ssh/authorized_keys && sudo cat /var/lib/soc-backup/.ssh/authorized_keys"
```
   (Daca la pasul 2 rrsync a iesit in alta cale, inlocuieste /usr/bin/rrsync.)
7. es-node-1 — copiere si instalare:
```
scp deploy/soc-backup-pull.sh deploy/soc-backup-pull.service deploy/soc-backup-pull.timer deploy/soc-backup-restore-test.sh tiberiu@172.30.6.106:/tmp/
ssh -t tiberiu@172.30.6.106 'sudo install -o root -g root -m 755 /tmp/soc-backup-pull.sh /tmp/soc-backup-restore-test.sh /usr/local/bin/ && sudo install -o root -g root -m 644 /tmp/soc-backup-pull.service /tmp/soc-backup-pull.timer /etc/systemd/system/ && rm /tmp/soc-backup-pull.* /tmp/soc-backup-restore-test.sh && sudo systemctl daemon-reload'
```
8. es-node-1 — test negativ (cheia nu poate rula comenzi) + prima copie:
```
ssh -t tiberiu@172.30.6.106 'ssh -i ~/.ssh/soc-backup_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new soc-backup@192.168.10.138 "ls /"; echo "rc=$?"; sudo systemctl start soc-backup-pull.service; sudo journalctl -t soc-backup-pull -n 3 --no-pager; ls -l /var/backups/web-prod'
```
   Asteptat: refuz de la rrsync si rc != 0; apoi `OK <azi>` si cele 3 fisiere.
   Atentie: "Restricted directory does not exist" NU e dovada restrictiei, ci semn ca
   /var/backups/soc lipseste pe web-prod (prima rulare din 2026-10-28, corectata la pasul 2).
9. es-node-1 — testul de restore (prima data descarca mariadb:10.11, ~400 MB):
```
ssh -t tiberiu@172.30.6.106 'soc-backup-restore-test.sh'
```
   Asteptat: `OK: db-<azi>.sql.gz -> N tabele in wp; ...` cu N >= 10.
10. es-node-1 — timer:
```
ssh -t tiberiu@172.30.6.106 'sudo systemctl enable --now soc-backup-pull.timer && systemctl list-timers soc-backup-pull.timer --no-pager'
```

### C. Verificare
- Pasii 3, 8, 9 de mai sus (OK in jurnal, sha256 verificat, restore cu >= 10 tabele).
- Linia de backup a ajuns in ES (syslog prin integrarea system), pe es-node-1:
```
ssh tiberiu@172.30.6.106 'cd ~/lab && source env.sh && curl -s -H "Authorization: ApiKey $ES_API_KEY" -H "Content-Type: application/json" "$ES_URL/logs-system.syslog-*/_search?filter_path=hits.hits._source" -d "{\"size\":1,\"sort\":[{\"@timestamp\":\"desc\"}],\"query\":{\"term\":{\"process.name\":\"soc-backup\"}},\"_source\":[\"@timestamp\",\"message\",\"host.name\"]}"'
```
  Asteptat: un document cu `OK db=...`. Alerta de "backup lipsa > 26 h" vine in bucata 0.4.
- In Kibana -> Security -> Alerts: nicio alerta de momeala in 10 minute dupa pasul 3
  (dovada ca excluderea .env.bak functioneaza).

### D. Metrica
backup_age_h (din ultimul `soc-backup OK` in logs-system.syslog-*), calculata de
notificatorul din 0.4 si scrisa in soc-metrics din pasul 1c. Acceptare: < 26 h;
restore test OK; 3 nopti la rand cu OK pe ambele timere.

### E. Rollback
web-prod:
```
ssh -t tiberiu@172.30.6.249 'sudo systemctl disable --now soc-backup.timer; sudo rm -f /etc/systemd/system/soc-backup.service /etc/systemd/system/soc-backup.timer /usr/local/bin/soc-backup.sh /usr/local/etc/soc-backup.exclude; sudo systemctl daemon-reload; sudo userdel -r soc-backup; sudo groupdel soc-backup 2>/dev/null; true'
```
es-node-1:
```
ssh -t tiberiu@172.30.6.106 'sudo systemctl disable --now soc-backup-pull.timer; sudo rm -f /etc/systemd/system/soc-backup-pull.service /etc/systemd/system/soc-backup-pull.timer /usr/local/bin/soc-backup-pull.sh /usr/local/bin/soc-backup-restore-test.sh; sudo systemctl daemon-reload; rm -f ~/.ssh/soc-backup_ed25519 ~/.ssh/soc-backup_ed25519.pub; docker image rm mariadb:10.11'
```
Backup-urile deja facute (/var/backups/soc pe web-prod, /var/backups/web-prod pe
es-node-1) NU se sterg in rollback; le stergi tu, daca vrei, cu `sudo rm -r`.

Rezultat 0.1 (2026-10-28): backup OK (4 fisiere), cheia soc-backup refuza `ls /`
(rrsync rc=1), pull OK cu sha256, restore OK (12 tabele in wp). De confirmat de om:
nicio alerta de momeala dupa backup.

Confirmat ulterior: pull-ul corectat scrie fisierele ca tiberiu:tiberiu; restore OK.

## 0.2 Patch-uri (apt + WordPress controlat)

Inspectie (2026-10-28): unattended-upgrades activ (doar security + ESM), 124 pachete
de actualizat; wp-config.php `www-data:www-data 664` (citibil de oricine, modificabil
de www-data); nicio constanta de update in wp-config -> WordPress se actualizeaza
singur, necontrolat; webroot detinut de www-data.

Decizii (implicite, schimbabile): proprietarul webroot-ului ramane www-data — un
webroot nescriibil pentru www-data face scenariul fast `drop.php` (scenarios_fast.yml:25)
sa nu mai reuseasca, deci poarta fast 4/4 ar pica; timer-ul de update porneste in
APPLY=0 (doar raport), ca versiunile marcate vulnerabile in kb/wp_vulns.yml (faza 18)
sa nu se schimbe fara decizia omului.

### A. Fisiere (noi)
- deploy/web-prod/52soc-unattended -> /etc/apt/apt.conf.d/: fara repornire automata,
  rulari in syslog (originile raman cele implicite).
- deploy/web-prod/soc-wp-update.py (+ .service/.timer, 02:00, User=www-data,
  ProtectSystem=strict): APPLY=0 raporteaza update-urile disponibile; APPLY=1 aplica
  core minor + slug-urile aprobate; fiecare schimbare = o linie in
  /var/log/soc/benign-actions.ndjson. wp-cli apelat cu argv, slug-uri validate
  (fara `--all` sau alte flaguri strecurate in lista).
- deploy/web-prod/soc-wp-update.conf -> /usr/local/etc/ (APPLY=0, liste goale).
- deploy/web-prod/soc-logrotate -> /etc/logrotate.d/soc (weekly, 8, copytruncate).
- tests/test_soc_wp_update.py: 10 teste (config fara shell, slug-uri, inregistrari).
- wp-config.php (modificat pe host, nu in repo): AUTOMATIC_UPDATER_DISABLED,
  WP_AUTO_UPDATE_CORE=false, DISALLOW_FILE_EDIT; proprietar root:www-data 640.
  Copie inainte in /var/backups/soc-pre-pas0/ (root 700, nu se trage pe es-node-1).

### B. Comenzi (de pe elastic-lab)
1. Copiere:
```
scp deploy/web-prod/soc-wp-update.py deploy/web-prod/soc-wp-update.service deploy/web-prod/soc-wp-update.timer deploy/web-prod/soc-wp-update.conf deploy/web-prod/soc-logrotate deploy/web-prod/52soc-unattended tiberiu@172.30.6.249:/tmp/
```
2. Instalare (copie wp-config inainte de orice schimbare):
```
ssh -t tiberiu@172.30.6.249 'set -e; sudo install -d -o root -g root -m 700 /var/backups/soc-pre-pas0; sudo cp -p /var/www/html/wp-config.php /var/backups/soc-pre-pas0/wp-config.php.$(date +%s); sudo install -d -o root -g root -m 755 /var/log/soc; sudo install -o www-data -g adm -m 640 /dev/null /var/log/soc/benign-actions.ndjson; sudo install -o www-data -g adm -m 640 /dev/null /var/log/soc/soc-wp-update.log; sudo install -o root -g root -m 755 /tmp/soc-wp-update.py /usr/local/bin/soc-wp-update.py; sudo install -o root -g root -m 644 /tmp/soc-wp-update.conf /usr/local/etc/soc-wp-update.conf; sudo install -o root -g root -m 644 /tmp/soc-logrotate /etc/logrotate.d/soc; sudo install -o root -g root -m 644 /tmp/52soc-unattended /etc/apt/apt.conf.d/52soc-unattended; sudo install -o root -g root -m 644 /tmp/soc-wp-update.service /tmp/soc-wp-update.timer /etc/systemd/system/; rm /tmp/soc-wp-update.py /tmp/soc-wp-update.service /tmp/soc-wp-update.timer /tmp/soc-wp-update.conf /tmp/soc-logrotate /tmp/52soc-unattended; sudo systemctl daemon-reload; sudo ls -l /var/backups/soc-pre-pas0'
```
3. wp-config.php (wp-cli `config set` nu incarca WordPress) + verificare ca site-ul merge:
```
ssh -t tiberiu@172.30.6.249 'set -e; W="sudo /usr/local/bin/wp --allow-root --path=/var/www/html"; $W config set AUTOMATIC_UPDATER_DISABLED true --raw --type=constant; $W config set WP_AUTO_UPDATE_CORE false --raw --type=constant; $W config set DISALLOW_FILE_EDIT true --raw --type=constant; sudo chown root:www-data /var/www/html/wp-config.php; sudo chmod 640 /var/www/html/wp-config.php; sudo php -l /var/www/html/wp-config.php; stat -c "%U:%G %a %n" /var/www/html/wp-config.php; curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost/'
```
   Asteptat: 3 x `Success: ...`, `No syntax errors detected`, `root:www-data 640`, `HTTP 200`.
   Daca HTTP nu e 200: rollback-ul wp-config de mai jos, imediat.
4. Prima rulare a update-ului (doar raport) + timer:
```
ssh -t tiberiu@172.30.6.249 'sudo systemctl start soc-wp-update.service; systemctl is-failed soc-wp-update.service; sudo tail -3 /var/log/soc/soc-wp-update.log; sudo cat /var/log/soc/benign-actions.ndjson; sudo systemctl enable --now soc-wp-update.timer'
```
   Asteptat: `inactive` (nu `failed`), linia `apply=False core=7.1.3 inregistrari=N` si N
   linii `wp_update_available` (0 daca totul e la zi).
5. unattended-upgrades:
```
ssh -t tiberiu@172.30.6.249 'apt-config dump | grep -E "Automatic-Reboot |SyslogEnable"; sudo unattended-upgrade --dry-run 2>&1 | tail -3'
```
6. es-node-1 — scriptul de pull corectat (fara proprietar/grup de pe web-prod):
```
scp deploy/soc-backup-pull.sh tiberiu@172.30.6.106:/tmp/
ssh -t tiberiu@172.30.6.106 'sudo install -o root -g root -m 755 /tmp/soc-backup-pull.sh /usr/local/bin/ && rm /tmp/soc-backup-pull.sh && sudo systemctl start soc-backup-pull.service && ls -l /var/backups/web-prod'
```

### C. Verificare
- Pasul 3: wp-config `root:www-data 640`, constantele prezente, site HTTP 200.
- Pasul 4: serviciul nu e `failed`; benign-actions.ndjson are randurile asteptate.
- Pasul 5: `Automatic-Reboot "false"`, `SyslogEnable "true"`; dry-run fara erori.
- Modificarea wp-config.php (root, proces wp/php) poate aparea ca scriere in webroot in
  sweep: se eticheteaza benign in interfata.
- Fisierul benign-actions.ndjson ajunge in ES abia cand se adauga integrarea Custom Logs
  (pasul 1, impreuna cu SBOM-ul).

### D. Metrica
patches_pending = randuri `wp_update_available` din ultima rulare + pachete de securitate
in asteptare; calculata in 0.4. Acceptare: timer 3 nopti fara `failed`; WordPress nu se
mai actualizeaza singur (versiunea se schimba doar cu APPLY=1).

### E. Rollback
```
ssh -t tiberiu@172.30.6.249 'set -e; f=$(sudo sh -c "ls -1 /var/backups/soc-pre-pas0/wp-config.php.* | tail -1"); test -n "$f"; sudo cp -p "$f" /var/www/html/wp-config.php; sudo systemctl disable --now soc-wp-update.timer; sudo rm -f /etc/systemd/system/soc-wp-update.service /etc/systemd/system/soc-wp-update.timer /usr/local/bin/soc-wp-update.py /usr/local/etc/soc-wp-update.conf /etc/apt/apt.conf.d/52soc-unattended /etc/logrotate.d/soc; sudo systemctl daemon-reload; stat -c "%U:%G %a %n" /var/www/html/wp-config.php; curl -s -o /dev/null -w "HTTP %{http_code}\n" http://localhost/'
```
(`cp -p` readuce si proprietarul/drepturile vechi. /var/log/soc ramane: il folosesc pasii urmatori.
Globul se expandeaza sub sudo: directorul e root 700, iar ca tiberiu ramanea literal —
prima rulare din 2026-10-28 s-a oprit la cp fara sa schimbe nimic.)

Rezultat 0.2 (2026-10-28): wp-config `root:www-data 640` cu cele 3 constante, HTTP 200,
timerele soc-wp-update si soc-backup enabled, primul raport: 0 update-uri disponibile.

## 0.3 Firewall (web-prod si es-node-1)

Decizii (implicite): administrare doar de la 172.20.99.220 (singura adresa vazuta pe
ambele hosturi; daca elastic-lab vechi se opreste, recuperarea e prin consola OpenStack
si se adauga noul IP in setul admin_v4). Portul 22 de pe web-prod NU e deschis
atacatorului (B4); regula de brute-force SSH din faza 20 nu se mai poate testa de acolo.

### A. Fisiere (noi)
- deploy/web-prod/soc-fw.nft: input drop; permis lo, established, ICMP, DHCP, 80/443
  de oriunde, 22 doar de la 192.168.10.121 si admin; drop-urile logate (soc-fw-drop).
- deploy/es-node-1/soc-fw.nft: input drop; 22 si 8088 (etichetare) doar admin, 8220 din
  192.168.10.0/24, retelele Docker catre host; lantul forward_guard (prioritate -10)
  filtreaza porturile publicate de Docker: 9200 doar de la web-prod (.138) si benign-gen
  (.150), 5601 doar admin, IPv6 spre 9200/5601 drop. Corectii fata de task: 9200 e
  deschis pentru web-prod (agentul trimite direct in ES); filtrarea Docker nu poate sta
  in INPUT; fara `flush ruleset` / nftables.service.
- deploy/soc-fw-apply.sh: `nft -c`, programeaza stergerea tabelului peste 10 minute,
  incarca; omul anuleaza stergerea doar dupa ce o sesiune SSH NOUA merge.
- deploy/soc-fw.service: incarca tabelul la boot (inainte de retea), ExecStop il sterge.
Ambele fisiere: validate cu `nft -c` si incarcate de doua ori intr-un namespace izolat
(idempotente).

### B. Comenzi — web-prod intai, apoi es-node-1. Testele din fiecare bloc in 10 minute.
Vezi mesajul din conversatie pentru ordinea exacta; pe scurt, per host:
copiere -> instalare + soc-fw-apply.sh -> teste dintr-o sesiune noua ->
`systemctl stop soc-fw-revert.timer && systemctl enable --now soc-fw.service`.
Daca un test pica: nu faci nimic, tabelul dispare singur in 10 minute.

### C. Verificare
web-prod: SSH nou de la admin; SSH de pe es-node-1 (harness, backup); HTTP 200 local;
22 inchis pentru atacator. es-node-1: SSH nou; Kibana de la admin; de pe web-prod ES
raspunde 401 si Fleet 200; de pe atacator ES nu raspunde; orchestratorul, tunelul LLM
si containerele active; dupa 10 minute agentul web-prod Healthy in Fleet.

### D. Metrica
fw_dropped_24h = linii `soc-fw-drop` in logs-system.syslog-* per host (in 0.4).
Acceptare: zero pierderi de telemetrie (agent Healthy, documente noi in logs-* de la
web-prod), harness-ul ajunge pe web-prod prin SSH.

### E. Rollback (per host)
```
ssh -t tiberiu@<host> 'sudo systemctl disable --now soc-fw.service; sudo nft delete table inet soc_fw 2>/dev/null; sudo rm -f /etc/systemd/system/soc-fw.service /etc/soc/soc-fw.nft /usr/local/sbin/soc-fw-apply.sh; sudo systemctl daemon-reload; sudo nft list tables'
```
Tabelele Docker (ip/ip6 nat, filter) raman neatinse.

Rezultat 0.3 web-prod (2026-10-28): incarcat cu plasa de 10 min; SSH nou de la admin OK,
HTTP local 200, SSH de pe es-node-1 OK, 22 inchis pentru atacator; soc-fw.service
enabled + active, revert anulat.

Rezultat 0.3 es-node-1 (2026-10-29): incarcat cu plasa de 10 min, apoi permanentizat
(soc-fw.service enabled + active). SSH nou de la admin OK; ES de pe web-prod 401 cu
telemetrie vie (logs-* _count=453 in ultimele 5 min); ES de pe atacator BLOCKED; stiva
(es01, kibana, soc-orchestrator, soc-llm-tunnel) activa.

Atentie la verificare: proba `curl https://.:8220/api/status` da 000 CHIAR si de pe
es-node-1 (localhost si .121), pentru ca Fleet Server reseteaza handshake-ul TLS pentru
un client fara certificat — e artefact de proba, NU blocaj de firewall. 8220 asculta pe
*:8220 si INPUT permite 192.168.10.0/24. Verificarea corecta pentru 8220 e reachability
TCP din web-prod + Healthy in Fleet UI, nu /api/status:
  web-prod: `timeout 5 bash -c "echo > /dev/tcp/192.168.10.121/8220" && echo open` -> open.
`.fleet-agents` e index restrictionat: ES_API_KEY (read-only) ia 403 pe el; starea
Healthy a agentului se confirma vizual in Kibana -> Fleet, nu din cod cu cheia curenta.

## 0.4 Notificare umana (Discord)

Licenta ES = basic, deci fara conectori email/webhook in Kibana. Notificarea trece
printr-un webhook Discord apelat din Python pe es-node-1. Secretul (URL-ul webhook) sta
DOAR in soc.env pe es-node-1 (R16): nu in repo, nu pe web-prod. Egress HTTPS catre
discord.com e liber (soc_fw are doar chain-uri input/forward, output e accept).

Abatere motivata fata de B3: notify_human() e in notify.py, NU in policy.py. policy.py
e cod pur (nu atinge reteaua, e testabil); un POST HTTP acolo i-ar strica contractul.

### A. Fisiere
Noi:
- notify.py: notify_human(title, detail, severity, dedup_key, dedup_minutes, host) ->
  POST pe Discord, pointer scurt (severitate, regula, host, case_id, "vezi Kibana"),
  NU telemetrie bruta (R7). Fara webhook -> no-op (log + False), nu crapa. Dedup per
  cheie (implicit 15 min) in data/notify-dedup.json (ignorat de git), fail-open. Orice
  eroare de retea e prinsa: notify_human nu ridica exceptie. `python notify.py` = test.
  maybe_notify_escalation(): pagineaza DOAR escaladarile critice (honeytoken,
  sensor_detection, native_detection), dedup per chain_id.
- absence_check.py: ruleaza pe es-node-1 (timer la 10 min). Trei verificari independente:
  backup `soc-backup OK` > 26 h; `systemctl is-active` soc-orchestrator/soc-llm-tunnel
  != active; canar soc-canary > 12 min. Iesire 1 doar cand ES e de neatins.
- deploy/es-node-1/soc-absence.service (oneshot, User=tiberiu, EnvironmentFile=soc.env).
- deploy/es-node-1/soc-absence.timer (OnCalendar=*:0/10, Persistent).

Diff:
- orchestrator.py: `import notify`; in persist(), dupa scrierea in soc-audit, apel
  notify.maybe_notify_escalation(...) sub try/except (o notificare esuata nu stirbeste
  auditul). Merge si in shadow. Nu ruleaza in dry-run (persist iese devreme fara WRITER).
- soc.env.example / env.sh.example: SOC_DISCORD_WEBHOOK documentat (fara valoare reala).

### B. Comenzi (pe es-node-1; de facut de om intai: webhook Discord in soc.env)
Prerequisit (om): Server Discord -> Settings -> Integrations -> Webhooks -> New Webhook
-> Copy URL. Apoi pe es-node-1, adauga in /home/tiberiu/lab/soc.env:
  SOC_DISCORD_WEBHOOK=https://discord.com/api/webhooks/XXXX/YYYY
Deploy (din copia de dezvoltare, dupa `git pull` pe es-node-1 SAU scp fisierele):
  scp notify.py absence_check.py tiberiu@172.30.6.106:/home/tiberiu/lab/
  scp deploy/es-node-1/soc-absence.{service,timer} tiberiu@172.30.6.106:/tmp/
  scp orchestrator.py tiberiu@172.30.6.106:/home/tiberiu/lab/
Instalare pe es-node-1:
  sudo install -m 644 /tmp/soc-absence.service /etc/systemd/system/soc-absence.service
  sudo install -m 644 /tmp/soc-absence.timer   /etc/systemd/system/soc-absence.timer
  sudo systemctl daemon-reload
  sudo systemctl enable --now soc-absence.timer
  sudo systemctl restart soc-orchestrator   # preia import notify + apelul din persist
Test manual (trimite o notificare reala):
  cd ~/lab && source env.sh && python notify.py "test 0.4 din es-node-1"

### C. Verificare
- python notify.py "..." -> primesti mesajul pe Discord in < 1 min (exit 0).
- fara webhook in mediu: python notify.py -> "SOC_DISCORD_WEBHOOK nesetat ... sarita",
  exit 1, fara exceptie.
- absence: oprire scurta aprobata a unui serviciu de test NU pe productie; in schimb,
  ruleaza o data manual si verifica journalul:
  sudo systemctl start soc-absence.service; journalctl -u soc-absence -n 20 --no-pager
  -> linii "backup OK/vechi", "serviciu ... active", "canar OK/vechi".
- test absenta backup (optional, aprobat): seteaza ABSENCE_BACKUP_MAX_AGE_H=0 intr-o
  rulare manuala -> pagina "Backup vechi" pe Discord (prag artificial, nu schimba timer-ul).
- escaladare critica: la urmatoarea atingere de momeala (0.4 din pasul 3, honeytoken) /
  detectie de senzor, orchestratorul trimite si el o notificare (dedup per case_id).
  Pana la pasul 3, se poate exercita cu un verdict sintetic (vezi testul din conversatie).

### D. Metrica
notifications_sent_24h (linii "notificare trimisa" in journalctl -u soc-absence +
-u soc-orchestrator). Acceptare: notificarea de test ajunge in < 3 min; absence_check
ruleaza la 10 min fara exceptii (exit 0) cand ES e sus; dedup tine (acelasi kind nu se
repeta sub fereastra lui).

### E. Rollback
  ssh -t tiberiu@172.30.6.106 'sudo systemctl disable --now soc-absence.timer; sudo rm -f /etc/systemd/system/soc-absence.service /etc/systemd/system/soc-absence.timer; sudo systemctl daemon-reload'
Scoate SOC_DISCORD_WEBHOOK din soc.env; revert diff orchestrator.py (import notify +
apelul din persist); rm notify.py absence_check.py. Orchestratorul merge si fara webhook
(notify_human devine no-op), deci revert-ul import-ului nu e urgent.

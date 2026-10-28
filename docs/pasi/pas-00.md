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
ssh -t tiberiu@172.30.6.249 'set -e; command -v rrsync; sudo groupadd --system soc-backup; sudo useradd --system --gid soc-backup --shell /bin/sh --home-dir /var/lib/soc-backup --create-home soc-backup; sudo install -o root -g root -m 755 /tmp/soc-backup.sh /usr/local/bin/soc-backup.sh; sudo install -d -m 755 /usr/local/etc; sudo install -o root -g root -m 644 /tmp/soc-backup.exclude /usr/local/etc/soc-backup.exclude; sudo install -o root -g root -m 644 /tmp/soc-backup.service /tmp/soc-backup.timer /etc/systemd/system/; rm /tmp/soc-backup.sh /tmp/soc-backup.exclude /tmp/soc-backup.service /tmp/soc-backup.timer; sudo systemctl daemon-reload'
```
   Asteptat: o cale (`/usr/bin/rrsync`), apoi nimic. Daca rrsync lipseste: stop, imi spui.
3. web-prod — prima rulare:
```
ssh -t tiberiu@172.30.6.249 'sudo systemctl start soc-backup.service; sudo ls -l /var/backups/soc; sudo journalctl -t soc-backup -n 3 --no-pager'
```
   Asteptat: db-<azi>.sql.gz, webroot-<azi>.tar.gz, SHA256SUMS-<azi> (root:soc-backup,
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

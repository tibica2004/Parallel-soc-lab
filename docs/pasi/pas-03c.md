# Pasul 3.C — Honeytokens WordPress/MySQL

EXCLUSIV DEFENSIV: momelile doar detecteaza (nicio blocare). Shadow activ (R4).
Nimic pe hosturi fara OK per comanda (R3). Fara secrete SOC pe web-prod (R16).

## Decizii (abateri de la textul initial, cu motiv)

| Text initial | Ales | Motiv |
|---|---|---|
| H1b `CREATE USER 'wp_backup'` fara GRANT | contul NU se creeaza | un cont fara GRANT se autentifica (USAGE), iar succesul nu apare in jurnalul de erori: momeala ar fi oarba exact la atac. Fara cont, orice incercare = `Access denied` logat. Acelasi tipar ca `svc_deploy` (faza 12). |
| H2 `wp user create backup_admin` | contul NU se creeaza | `wp_login_failed` se declanseaza si pentru utilizatori inexistenti; un cont real ar fi o suprafata in plus. Numele apare doar in momeala `backup.sql` (lantul: descarcare -> incercare login). |
| auditd `-F exe!=a -F exe!=b ...` (A4) | reguli `-a never ... -F exe=X` inaintea regulii `always` | kernelul accepta un singur camp `exe` per regula. |
| backup `wp-config.php.pre-honey.<ts>` in webroot | `/root/soc-pre-honey-<ts>/` | o copie `.php.pre-honey.*` in webroot e servita ca text, cu parola reala a bazei. |
| markerul `soc-honeytoken` in fisiere | doar in `/etc/mysql/.../60-soc-honey.cnf` | in `robots.txt`/`wp-config.php` ar spune atacatorului ca sunt momeli. |
| H1 regula pe text (parola in apache.access) | eliminata (A4) | nu se intampla in practica. |
| H5 `.credentials.txt` | amanat (optional) | — |
| MySQL error log prin integrarea Fleet `mysql` | regula pe `logs-mysql.error-*` SI `logs-system.syslog-*` | pe Ubuntu MariaDB scrie implicit in journald -> syslog; daca deja ajunge acolo, nu mai e nevoie de integrare. |
| verdict preset malicious 100 | podeaua existenta (benign -> suspicious) + escaladare mereu | codul existent (faza 12) decide deja; motivul HONEYTOKEN intra in audit si la Tier 2. |

Limita cunoscuta: un webshell PHP care citeste `wp-config.php` ruleaza in apache2/php-fpm,
exclusi din regula auditd (altfel un eveniment la fiecare cerere). Il prinde momeala MySQL
cand foloseste constantele, plus regulile 3.A (web -> shell). Un `tar` ca root (ca
backup-ul) e exclus din regula wp-config; Defend il vede totusi (calea e in argumente).

## A. Fisiere

Noi:
- `deploy/web-prod/honeytokens-wp.sh` — planteaza H1, H1b (doar log_warnings), H2, H3, H4. Root, o data,
  idempotent, fara restart de servicii, copii in `/root/soc-pre-honey-<ts>/`.
- `deploy/web-prod/soc-honey.php` — mu-plugin; logheaza `SOC_HONEY event=... user=backup_admin ip=<IP valid>`.
  Numele primit nu se logheaza niciodata (date ale atacatorului).
- `tests/test_honeytokens_wp.py` — 39 teste.

Modificate (diff aratat inainte, R12):
- `honeytokens.py` — 6 reguli noi in multimea inchisa, `AUDITD_RULES` (sursa unica), `is_config_error`,
  `escalation_reason`.
- `schemas.py` — `EscalationReason.HONEYTOKEN_CONFIG_ERROR`.
- `orchestrator.py` — momeala de pe IP propriu/benign -> motiv config_error (fara paginare Discord).
- `hunt_path.py` — Tier 2 nu inchide nici config_error.
- `deploy/web-prod/soc-backup.exclude` — `backup.sql` (tar l-ar citi noaptea -> auditd).
- `deploy/web-prod/auditd-fim.md` — regulile noi.

Reguli Kibana (spatiul default, tag `soc-honeytoken`, critical): `soc-honey-wpconfig-read`,
`soc-honey-mysql-user`, `soc-honey-wp-login`, `soc-honey-backup-sql-http`,
`soc-honey-backup-sql-read`, `soc-honey-robots-trap` (+ cele 4 existente = 10).

## B. Comenzi (ordine; fiecare cu OK)

1. web-prod, read-only (descoperire):
   `ssh tiberiu@172.30.6.249 'readlink -f $(command -v apache2 php-fpm8.3 php8.3 tar) ; systemctl is-active php8.3-fpm mariadb mysql ; ls -ld /var/www/html/wp-content/mu-plugins /var/www/html/robots.txt ; id -u www-data'`
2. local -> web-prod (Claude): `scp deploy/web-prod/honeytokens-wp.sh deploy/web-prod/soc-honey.php deploy/web-prod/soc-backup.exclude tiberiu@172.30.6.249:/tmp/`
3. web-prod, root (OMUL, parola sudo):
   `ssh -t tiberiu@172.30.6.249 'sudo bash /tmp/honeytokens-wp.sh /tmp/soc-honey.php && sudo install -m 644 /tmp/soc-backup.exclude /usr/local/etc/soc-backup.exclude && rm /tmp/honeytokens-wp.sh /tmp/soc-honey.php /tmp/soc-backup.exclude'`
   Iesire asteptata: liniile `H1 ... adaugate (root:www-data 640)`, `H1b ...`, `H2 ...`, `H3 ... 644`, `H4 ...`
   si caile reale ale binarelor.
4. Fleet (OMUL): policy web-prod -> auditd_manager -> adauga, IN ORDINE, liniile din
   `python3 -c "import honeytokens; print('\n'.join(honeytokens.AUDITD_RULES))"` (corectate cu
   caile de la pasul 1 daca difera).
5. Deploy cod pe es-node-1 (Claude, scp + sha256): `honeytokens.py schemas.py orchestrator.py hunt_path.py`.
   Adauga in soc.env (G3): `BENIGN_GEN_IPS=192.168.10.150` si
   `WP_SELF_IPS=192.168.10.138,172.30.6.249,127.0.0.1,::1`.
6. Kibana (OMUL, parola elastic): `python3 deploy/kibana/honeytoken_rules.py verifica` apoi `aplica`.
7. (OMUL) `sudo systemctl restart soc-orchestrator` (activeaza si BEHAVIORAL din 3.A).

## C. Verificare

- `verifica` -> cele 10 reguli `soc-honeytoken`/`soc-honey-*` `pornita`.
- Teste (aprobate per comanda, de pe boxa admin 172.20.99.220, NU IP propriu):
  - `curl -s -o /dev/null -w '%{http_code}' http://172.30.6.249/backup.sql` -> 200; in < 2 min alerte
    `soc-honey-backup-sql-http` + `soc-honey-backup-sql-read`, escaladare HONEYTOKEN in soc-audit, Discord.
  - `curl -s -o /dev/null http://172.30.6.249/db-backup/` -> `soc-honey-robots-trap`.
  - login esuat cu `backup_admin` pe `/wp-login.php` (parola gresita) -> `SOC_HONEY event=login_failed`
    in logs-apache.error -> `soc-honey-wp-login`.
  - pe web-prod: `mysql -u wp_backup -pX -e 'select 1'` -> Access denied -> `soc-honey-mysql-user`.
  - pe web-prod: `sudo cat /var/www/html/wp-config.php >/dev/null` -> `soc-honey-wpconfig-read`.
  - config_error: `curl http://127.0.0.1/db-backup/` pe web-prod -> escaladare cu motivul
    `honeytoken_config_error`, fara paginare.
- Asteptat si benign (etichetat o data): 3.A `soc-php-written-in-webroot` la plantare
  (wp-config.php, soc-honey.php).
- `curl -s http://172.30.6.249/robots.txt` nu contine "soc"/"honey".

## D. Metrica (soc-metrics type=detection)

`rules_active_honeytoken` (>= 10), `alerts_honeytoken_24h` (0 in afara testelor),
`time_to_alert_s` per test (< 120). Acceptare: fiecare test de mai sus produce alerta asteptata;
48 h fara teste -> `alerts_honeytoken_24h == 0`; zero config_error neexplicate.

## E. Rollback

- Kibana: sterge regulile `soc-honey-*` (rule_id) din Security -> Rules.
- Fleet: scoate liniile `soc_honey_wpconfig` / `soc_honey_sql` din auditd_manager.
- web-prod (root): `cp -p /root/soc-pre-honey-<ts>/wp-config.php /var/www/html/wp-config.php`;
  `robots.txt` din aceeasi copie (sau `rm` daca n-a existat);
  `rm -r /var/www/html/backup.sql /var/www/html/wp-content/mu-plugins/soc-honey.php /var/www/html/wp-admin-old /var/www/html/db-backup`;
  `rm -f /etc/mysql/mariadb.conf.d/60-soc-honey.cnf` (log_warnings ramane live pana la restart; inofensiv).
- es-node-1: revert la commitul anterior pentru cele 4 fisiere Python; orchestrator restart.

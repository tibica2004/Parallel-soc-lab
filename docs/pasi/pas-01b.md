# Pasul 1b (= 6.2) — soc-reader: SSH read-only al SOC-ului catre web-prod

EXCLUSIV DEFENSIV. Doar citire. Shadow activ.

## Ce face

- Pe web-prod: cont de sistem `soc-reader` (parola blocata, shell /bin/sh), `authorized_keys` al lui
  root cu `restrict,command="/usr/local/bin/soc-reader-gate"`. Gate-ul executa DOAR 11 comenzi
  exacte (argumente fixe din gate, niciodata textul primit) + rsync doar-trimitere prin
  `rrsync -ro /var/www/html` (pentru pasul 2). Orice altceva: `DENIED`, exit 1. Fiecare apel se
  logheaza (`soc-reader-gate`, auth.log -> logs-system.auth-*).
- Pe es-node-1: cheia `~/.ssh/soc-reader` (ed25519, fara parola, 600, a lui tiberiu care ruleaza
  orchestratorul) si `reader.py`: `ReaderCommand` (Enum inchis, aceeasi lista ca gate-ul; test de
  identitate), `run()` cu BatchMode, IdentitiesOnly, StrictHostKeyChecking=yes, timeout 20 s;
  esecul ridica `ReaderError` (R9).
- `wp_inventory.py` nu mai intra prin ssh ca tiberiu@ (D1): citeste SBOM-ul (logs-soc.sbom-*).
  WP-CLI pornea tot WordPress-ul (citea wp-config.php, se conecta la baza).
- Regula Kibana `soc-reader-denied` (senzor, high): un DENIED = bug sau cheia SOC folosita de altcineva.

Comenzile: `ps -eo pid,ppid,user,etimes,cmd`, `ss -tlnp`, `sha256sum` canar (binar + cron) si cron
(`/etc/crontab /etc/cron.d/*`, globul expandat de gate), `cat /etc/passwd`, `ls -la` webroot si
plugins, `stat` pe wp-config.php / .htaccess / backup.sql / robots.txt (stat nu deschide fisierul:
fara auditd pe momele).

## Abateri (cu motiv)

| Text 6.2 | Ales | Motiv |
|---|---|---|
| `--shell /usr/sbin/nologin` | `/bin/sh` + parola blocata + comanda fortata | sshd ruleaza comanda fortata prin shell-ul contului; cu nologin ar refuza-o. Login interactiv imposibil oricum (`restrict` = fara pty, comanda fortata). |
| `/etc/ssh/sshd_config.d/soc-reader.conf` cu `Match User` | nicio schimbare in sshd | un `Match` intr-un drop-in inclus la inceputul sshd_config poate prelua setarile globale de dupa Include; `restrict` + comanda fortata + parola blocata dau acelasi efect fara risc si fara reload. `sshd -T` afisat la instalare. |
| `setfacl ... rX` pe webroot | fara ACL | webroot-ul e deja citibil de oricine, cu exceptia wp-config.php (640), care ramane inaccesibil (secretele nu pleaca de pe web-prod). |
| log in /var/log/soc/reader-gate.log | syslog (`soc-reader-gate`) | contul nu poate scrie in /var/log/soc; jurnalul ajunge oricum in ES. |
| `/etc/soc/keys/soc-reader` | `~/.ssh/soc-reader` (tiberiu) | orchestratorul ruleaza ca tiberiu; /etc/soc nu exista pe es-node-1 (configul e in ~/lab). |
| harness/ablation prin tiberiu@ | neschimbate | unelte de evaluare rulate de om, care GENEREAZA scenarii pe web-prod (au nevoie de shell real); nu sunt cod de productie SOC. |

Urmeaza (1b.2): canar-hash + cron_hash in absence_check prin `reader.run` (deblocate de 1b).

## A. Fisiere

Noi: `deploy/web-prod/soc-reader/{soc-reader-gate,install.sh}`, `reader.py`, `tests/test_reader.py` (27).
Modificate (diff aratat): `wp_inventory.py` (SBOM in loc de ssh), `sensor_rules.py` (regula
soc-reader-denied), `honeytokens.py` (T1021.004 in TACTIC).

## B. Comenzi (fiecare cu OK)

1. (Claude, es-node-1, fara sudo) `ssh-keygen -t ed25519 -N "" -C soc-reader@es-node-1 -f ~/.ssh/soc-reader`;
   verific ca web-prod (192.168.10.138) e in ~/.ssh/known_hosts.
2. (Claude) scp `deploy/web-prod/soc-reader/*` + cheia PUBLICA in /tmp/soc-reader pe web-prod.
3. (OMUL, sudo pe web-prod) `sudo bash /tmp/soc-reader/install.sh /tmp/soc-reader/soc-reader.pub && rm -rf /tmp/soc-reader`.
4. (Claude, de pe es-node-1) testele de la C.
5. (Claude) scp `reader.py wp_inventory.py sensor_rules.py honeytokens.py` pe es-node-1 (.pre-1b);
   (OMUL) `honeytoken_rules.py aplica` (soc-reader-denied) si restart orchestrator.

## C. Verificare

- `ssh -i ~/.ssh/soc-reader soc-reader@192.168.10.138 'cat /etc/passwd'` -> continutul; `'ps -eo ...'` -> procese.
- `... 'ls /'` -> `DENIED`, exit 1; linie `denied cmd=ls /` in logs-system.auth-* -> alerta soc-reader-denied.
- `... ` (fara comanda) -> `DENIED` (fara shell interactiv); `ssh -N -L ...` -> forwarding refuzat.
- `python3 -c "import reader; print(reader.run(reader.ReaderCommand.CANARY_HASH))"` -> doua hash-uri.

## D. Metrica

`reader_gate_denied_24h` (normal 0; > 0 = investigare), din logs-system.auth-* message:denied.

## E. Rollback

web-prod: `sudo userdel soc-reader; sudo rm -rf /var/lib/soc-reader /usr/local/bin/soc-reader-gate`.
es-node-1: `rm ~/.ssh/soc-reader ~/.ssh/soc-reader.pub`; fisierele `.pre-1b`. Kibana: sterge soc-reader-denied.

# Pasul 3.E — AIDE (integritatea fisierelor pe web-prod, G9)

EXCLUSIV DEFENSIV, doar citire si raportare. Shadow activ. Nimic pe hosturi fara OK.

## Ce face

`/usr/local/sbin/soc-aide-check` (root, timer zilnic 03:30) ruleaza AIDE 0.18 cu configuratie
proprie (`/etc/soc-aide/aide.conf`): /etc, /usr/bin, /usr/sbin, /usr/local/{bin,sbin}, /var/www/html
(fara wp-content/uploads|cache|upgrade si fara momelile .env.bak/backup.sql), sha256 + metadate.

- Prima rulare: `aide --init` (baza). Apoi `aide --update` + promovarea bazei noi: fiecare
  schimbare se raporteaza O DATA (nu zilnic la nesfarsit).
- CODUL decide ce e explicat (R5): o cale schimbata e explicata daca `dpkg-query -S` o leaga de un
  pachet instalat de la rularea anterioara (dpkg.log), sau e un fisier generat (ld.so.cache,
  /etc/alternatives, /etc/ssl/certs) si a existat activitate de pachete. Restul = neexplicat.
- Un rand JSON in jurnal (`soc-aide`): aide_ok | aide_init | aide_explained | aide_unexplained |
  aide_error. Regula Kibana `soc-aide-change` (sensor_rules, high, SENSOR_DETECTION -> Tier 1 nu o
  inchide) prinde aide_unexplained si aide_error. Faptele (`aide_facts`) sunt validate si plafonate
  (20 de cai, 200 de caractere): numele de fisiere sunt DATE.

## Abateri (cu motiv)

| Text G9 | Ales | Motiv |
|---|---|---|
| `apt install aide` | `--no-install-recommends aide` (fara aide-common) | aide-common aduce un timer zilnic pe tot discul, cu configuratia distributiei: ar citi momelile (honeytoken in fiecare noapte) si ar dubla munca. |
| re-init dupa fiecare soc-wp-update | promovarea bazei la fiecare rulare + explicatia prin dpkg | soc-wp-update e in mod raport (APPLY=0), nu schimba nimic. Cand se activeaza APPLY=1, schimbarile WordPress vor aparea o data ca neexplicate (corect: un om confirma). |
| excluderea ferestrei de update din benign-ground-truth | explicatie deterministica prin dpkg | benign-ground-truth nu exista inca (pasul 4); dpkg e sursa exacta pentru update-urile de sistem. |
| KQL `message:*changed*` | `message : ("aide_unexplained" or "aide_error")` | o singura alerta pe zi, doar pentru ce nu explica un update; altfel unattended-upgrades ar produce zeci de alerte. |

## A. Fisiere

Noi: `deploy/web-prod/aide/{soc-aide.conf, soc-aide-check, soc-aide-check.service, soc-aide-check.timer,
install.sh}`, `tests/test_aide.py` (21 teste).
Modificate (diff aratat): `sensor_rules.py` (regula soc-aide-change + aide_facts), `honeytokens.py`
(T1554 in TACTIC; regula wp-config exclude si /usr/bin/aide), `tests/test_honeytokens_wp.py`.

## B. Comenzi (ordinea conteaza)

1. (Claude) commit; scp `honeytokens.py sensor_rules.py` pe es-node-1 (copii .pre-3e).
2. (OMUL, parola elastic) `honeytoken_rules.py actualizeaza` (wp-config exclude aide) si apoi
   `aplica` (creeaza soc-aide-change). INAINTE de instalare: `aide --init` citeste wp-config.php.
3. (Claude) `scp -r deploy/web-prod/aide tiberiu@172.30.6.249:/tmp/soc-aide`.
4. (OMUL, sudo pe web-prod) `sudo bash /tmp/soc-aide/install.sh && rm -rf /tmp/soc-aide`
   -> `aide --version` 0.18.6, config-check OK, `{"event": "aide_init"}`, timerul la 03:30.
5. Test (cu OK): `sudo touch /usr/local/bin/soc-aide-test` + `sudo systemctl start soc-aide-check`
   -> aide_unexplained cu calea, alerta soc-aide-change; apoi `sudo rm` + inca o rulare (removed).

## C. Verificare

`journalctl -t soc-aide`; in ES `logs-system.syslog-*` `process.name:soc-aide-check`; alerta
soc-aide-change la test; nicio alerta soc-honey-wpconfig-read de la /usr/bin/aide.

## D. Metrica

Zilnic un rand soc-aide; acceptare: 7 zile fara aide_error; zero alerte neexplicate in afara
schimbarilor facute de om; testul de la B5 produce exact o alerta.

## E. Rollback

`systemctl disable --now soc-aide-check.timer; rm -rf /etc/soc-aide /var/lib/soc-aide
/usr/local/sbin/soc-aide-check /etc/systemd/system/soc-aide-check.*; systemctl daemon-reload;
apt-get purge aide`; Kibana: sterge regula soc-aide-change; es-node-1: `.pre-3e`.

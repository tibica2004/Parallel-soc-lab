# web-prod

Canarul de telemetrie este o copie a lui `true`; fiecare rulare produce un
eveniment de proces vizibil pentru Elastic Defend.

    sudo cp /usr/bin/true /usr/local/bin/soc-canary
    sudo cp soc-canary.cron /etc/cron.d/soc-canary
    sudo chmod 644 /etc/cron.d/soc-canary

## Honeytokens (faza 12)

Momeala `/var/www/html/.env.bak` (credentiale false, generate pe host) se
planteaza o singura data cu `honeytokens.sh`. Caile web `/.env.bak`,
`/admin.old.php` si utilizatorul `svc_deploy` (inexistent pe host) sunt
celelalte momeli. Definitiile regulilor sunt in `honeytokens.py`; regulile se
creeaza in Kibana cu `deploy/kibana/honeytoken_rules.py aplica`, dupa plantare.

Nu crea utilizatorul `svc_deploy` si nu citi `.env.bak` decat ca test: orice
atingere escaladeaza la om.

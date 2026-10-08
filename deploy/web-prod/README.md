# web-prod

Canarul de telemetrie este o copie a lui `true`; fiecare rulare produce un
eveniment de proces vizibil pentru Elastic Defend.

    sudo cp /usr/bin/true /usr/local/bin/soc-canary
    sudo cp soc-canary.cron /etc/cron.d/soc-canary
    sudo chmod 644 /etc/cron.d/soc-canary

#!/bin/bash
# Instaleaza verificarea AIDE pe web-prod (pasul 3.E). O ruleaza OMUL, ca root:
#   scp -r deploy/web-prod/aide tiberiu@172.30.6.249:/tmp/soc-aide
#   ssh -t tiberiu@172.30.6.249 'sudo bash /tmp/soc-aide/install.sh && rm -rf /tmp/soc-aide'
# Doar binarul aide (--no-install-recommends): fara aide-common, deci fara timerul lui zilnic
# pe tot discul (ar citi si momelile). Prima rulare face baza (aide_init).
# Revenire: systemctl disable --now soc-aide-check.timer; rm -rf /etc/soc-aide /var/lib/soc-aide
#           /usr/local/sbin/soc-aide-check /etc/systemd/system/soc-aide-check.*; apt-get purge aide
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd)
apt-get install -y --no-install-recommends aide
aide --version 2>&1 | head -1
install -d -m 755 /etc/soc-aide
install -m 644 "$D/soc-aide.conf" /etc/soc-aide/aide.conf
aide --config=/etc/soc-aide/aide.conf --config-check    # configuratia e valida?
install -m 755 "$D/soc-aide-check" /usr/local/sbin/soc-aide-check
install -m 644 "$D/soc-aide-check.service" "$D/soc-aide-check.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable soc-aide-check.timer
systemctl start soc-aide-check.timer
echo "Baza initiala (dureaza 1-3 min)..."
systemctl start soc-aide-check.service
journalctl -t soc-aide --no-pager -n 3 -o cat || true
ls -l /var/lib/soc-aide/
systemctl list-timers soc-aide-check.timer --no-pager | head -2
echo "Gata. Rezultatele apar cu: journalctl -t soc-aide"

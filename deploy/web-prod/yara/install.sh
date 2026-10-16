#!/bin/bash
# Instaleaza scanarea YARA pe web-prod (faza 12). O ruleaza OMUL:
#   scp -r deploy/web-prod/yara tiberiu@172.20.99.240:/tmp/soc-yara
#   ssh -t tiberiu@172.20.99.240 'sudo bash /tmp/soc-yara/install.sh && rm -rf /tmp/soc-yara'
# Revenire: systemctl disable --now soc-yara-scan.timer soc-yara-scan.path
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd)
apt-get install -y yara
install -d -m 755 /etc/soc-yara
install -m 644 "$D/webshells.yar" /etc/soc-yara/webshells.yar
yara -w /etc/soc-yara/webshells.yar /dev/null    # regulile compileaza?
install -m 755 "$D/soc-yara-scan" /usr/local/sbin/soc-yara-scan
install -m 644 "$D/soc-yara-scan.service" "$D/soc-yara-scan.timer" "$D/soc-yara-scan.path" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now soc-yara-scan.timer soc-yara-scan.path
systemctl start soc-yara-scan.service
systemctl --no-pager status soc-yara-scan.service | head -5
journalctl -t soc-yara --no-pager -n 5 || true
echo "Gata. Potrivirile apar cu: journalctl -t soc-yara"

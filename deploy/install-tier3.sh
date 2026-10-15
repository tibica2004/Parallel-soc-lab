#!/bin/bash
# Instaleaza timerul Tier 3. Ruleaza din ~/lab:  bash deploy/install-tier3.sh
# Opreste totul:  sudo systemctl disable --now soc-tier3.timer
#                 python3 tier3.py --once --opreste-reguli --scrie-kibana
set -e
cd ~/lab

# Acelasi mecanism ca deploy/install.sh: soc.env regenerat din env.sh (aduce si
# KIBANA_TIER3_API_KEY). SHADOW_MODE exclus: il controleaza fisierul de serviciu.
grep '^export ' env.sh | sed 's/^export //' | grep -v '^SHADOW_MODE=' > soc.env
chmod 600 soc.env
grep -q '^KIBANA_TIER3_API_KEY=' soc.env || { echo "KIBANA_TIER3_API_KEY lipseste din env.sh"; exit 1; }
echo "soc.env generat cu $(wc -l < soc.env) variabile (cu cheia Tier 3)"

mkdir -p data/tier3
sudo cp deploy/soc-tier3.service deploy/soc-tier3.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-tier3.timer
echo
systemctl list-timers soc-tier3.timer --no-pager
echo
echo "Prima rulare de proba acum:  sudo systemctl start soc-tier3.service"
echo "Logul:                       journalctl -u soc-tier3 -n 80 --no-pager"

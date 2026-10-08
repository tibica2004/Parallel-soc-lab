#!/bin/bash
# Instaleaza serviciile. Ruleaza din ~/lab:  bash deploy/install.sh
set -e
cd ~/lab

# systemd nu intelege 'export' si 'source': generam un fisier KEY=VALUE din env.sh
# SHADOW_MODE e exclus intentionat: il controleaza doar fisierul de serviciu
grep '^export ' env.sh | sed 's/^export //' | grep -v '^SHADOW_MODE=' > soc.env
chmod 600 soc.env
echo "soc.env generat cu $(wc -l < soc.env) variabile"

sudo cp deploy/soc-llm-tunnel.service deploy/soc-orchestrator.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-llm-tunnel.service
sleep 5
sudo systemctl enable --now soc-orchestrator.service
echo
systemctl is-active soc-llm-tunnel soc-orchestrator
echo
echo "Logul orchestratorului:  journalctl -u soc-orchestrator -f"

#!/bin/bash
# Incarca firewall-ul SOC cu plasa de siguranta (pasul 0.3), pe es-node-1 sau web-prod.
# Inainte de incarcare programeaza `nft delete table inet soc_fw` peste 10 minute. Daca
# dupa incarcare poti deschide o sesiune SSH NOUA, anulezi stergerea:
#     sudo systemctl stop soc-fw-revert.timer
# Altfel nu faci nimic: in 10 minute tabelul dispare si accesul revine ca inainte.
set -euo pipefail

FILE=${1:-/etc/soc/soc-fw.nft}

nft -c -f "$FILE"
systemctl stop soc-fw-revert.timer soc-fw-revert.service >/dev/null 2>&1 || true
systemctl reset-failed soc-fw-revert.timer soc-fw-revert.service >/dev/null 2>&1 || true
systemd-run --quiet --unit=soc-fw-revert --on-active=600 /usr/sbin/nft delete table inet soc_fw
nft -f "$FILE"
logger -t soc-fw "incarcat $FILE; stergere automata programata peste 10 min"
echo "Incarcat $FILE. Tabelul se STERGE SINGUR in 10 minute."
echo "Deschide o sesiune SSH NOUA; daca merge: sudo systemctl stop soc-fw-revert.timer"

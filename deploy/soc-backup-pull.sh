#!/bin/bash
# Copia offsite a backup-ului web-prod, TRASA pe es-node-1 (pasul 0). web-prod nu are
# nicio cheie spre SOC (R16); cheia soc-backup de aici are pe web-prod doar
# `rrsync -ro /var/backups/soc`. Fara --delete: aici se pastreaza 30 de zile, acolo 14.
# Copia de azi se verifica cu sha256; orice esec -> exit != 0 (vizibil in journal).
set -euo pipefail
umask 077

SRC=${SOC_BACKUP_SRC:-soc-backup@192.168.10.138}
KEY=${SOC_BACKUP_KEY:-$HOME/.ssh/soc-backup_ed25519}
DEST=${SOC_BACKUP_DEST:-/var/backups/web-prod}
KEEP_DAYS=30
DAY=$(date +%F)

log() { logger -t soc-backup-pull "$*"; }
trap 'log "EROARE la linia $LINENO"' ERR

rsync -a --no-owner --no-group --chmod=D700,F600 -e "ssh -i $KEY -o BatchMode=yes -o IdentitiesOnly=yes" "$SRC:" "$DEST/"

sums="SHA256SUMS-$DAY"
if [ ! -f "$DEST/$sums" ]; then
    log "EROARE lipseste $sums (backup-ul de azi n-a rulat pe web-prod?)"
    exit 1
fi
(cd "$DEST" && sha256sum --quiet -c "$sums")

find "$DEST" -maxdepth 1 -type f -name '*-20*' -mtime +"$KEEP_DAYS" -delete
log "OK $DAY"

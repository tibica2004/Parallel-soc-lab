#!/bin/bash
# Backup zilnic web-prod (pasul 0): baza de date + webroot + config Apache/PHP.
# Ruleaza ca root (mysqldump prin socketul unix, citire /etc). Nu trimite nimic in
# retea: copia offsite o TRAGE es-node-1 cu o cheie limitata la rrsync -ro (R16:
# web-prod nu tine nicio cheie spre SOC).
#
# Momelile (.env.bak etc.) NU intra in arhiva: tar le-ar citi in fiecare noapte si
# ar declansa regula de citire a momelii. Lista e intr-un fisier separat, nu pe linia
# de comanda: regula de folosire a momelii cauta numele ei in process.command_line.
set -euo pipefail
umask 027

DEST=/var/backups/soc
EXCLUDE=/usr/local/etc/soc-backup.exclude
KEEP_DAYS=14
DAY=$(date +%F)

log() { logger -t soc-backup "$*"; }
trap 'log "EROARE la linia $LINENO"' ERR

install -d -o root -g soc-backup -m 750 "$DEST"
db="$DEST/db-$DAY.sql.gz"
web="$DEST/webroot-$DAY.tar.gz"

mysqldump --single-transaction --routines --events --all-databases | gzip > "$db.tmp"
mv "$db.tmp" "$db"

tar -czf "$web.tmp" --exclude-from="$EXCLUDE" -C / var/www/html etc/apache2 etc/php
mv "$web.tmp" "$web"

# Integritate inainte de a declara OK: arhivele se pot citi cap-coada.
gzip -t "$db"
tar -tzf "$web" >/dev/null
(cd "$DEST" && sha256sum "$(basename "$db")" "$(basename "$web")" > "SHA256SUMS-$DAY")
chgrp soc-backup "$db" "$web" "$DEST/SHA256SUMS-$DAY"
chmod 640 "$db" "$web" "$DEST/SHA256SUMS-$DAY"

find "$DEST" -maxdepth 1 -type f -name '*-20*' -mtime +"$KEEP_DAYS" -delete
log "OK db=$(stat -c%s "$db") web=$(stat -c%s "$web")"

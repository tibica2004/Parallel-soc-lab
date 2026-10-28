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
grants="$DEST/grants-$DAY.sql.gz"
web="$DEST/webroot-$DAY.tar.gz"

# Doar bazele aplicatiei: schema de sistem `mysql` nu se restaureaza sigur peste un
# server pornit (testul din 2026-10-28 a cazut pe ea). Conturile si drepturile merg
# separat, ca CREATE USER/GRANT (--system=users).
mapfile -t dbs < <(mysql -N -e "SHOW DATABASES" | grep -Ev '^(information_schema|performance_schema|mysql|sys)$')
mysqldump --single-transaction --routines --events --databases "${dbs[@]}" | gzip > "$db.tmp"
mv "$db.tmp" "$db"
mysqldump --system=users | gzip > "$grants.tmp"
mv "$grants.tmp" "$grants"

tar -czf "$web.tmp" --exclude-from="$EXCLUDE" -C / var/www/html etc/apache2 etc/php
mv "$web.tmp" "$web"

# Integritate inainte de a declara OK: arhivele se pot citi cap-coada.
gzip -t "$db"
gzip -t "$grants"
tar -tzf "$web" >/dev/null
(cd "$DEST" && sha256sum "$(basename "$db")" "$(basename "$grants")" "$(basename "$web")" > "SHA256SUMS-$DAY")
chgrp soc-backup "$db" "$grants" "$web" "$DEST/SHA256SUMS-$DAY"
chmod 640 "$db" "$grants" "$web" "$DEST/SHA256SUMS-$DAY"

find "$DEST" -maxdepth 1 -type f -name '*-20*' -mtime +"$KEEP_DAYS" -delete
log "OK db=$(stat -c%s "$db") web=$(stat -c%s "$web")"

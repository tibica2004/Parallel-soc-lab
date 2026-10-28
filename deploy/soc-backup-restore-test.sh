#!/bin/bash
# Test de restaurare (pasul 0), pe es-node-1: ultima copie trasa se incarca intr-un
# MariaDB temporar (container fara retea, sters la final) si se verifica ca baza wp si
# webroot-ul sunt intregi. Se ruleaza la mana, lunar; rezultatul merge in syslog.
set -euo pipefail

DIR=${SOC_BACKUP_DEST:-/var/backups/web-prod}
MIN_TABLES=10

db=$(ls -1 "$DIR"/db-*.sql.gz | tail -1)
web=$(ls -1 "$DIR"/webroot-*.tar.gz | tail -1)
name="soc-restore-test-$$"

cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --rm --name "$name" --network none \
    -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 mariadb:10.11 >/dev/null
for _ in $(seq 60); do
    docker exec "$name" mariadb-admin ping --silent >/dev/null 2>&1 && break
    sleep 2
done

zcat "$db" | docker exec -i "$name" mariadb
tables=$(docker exec "$name" mariadb -N -e \
    "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='wp'")
tar -tzf "$web" var/www/html/wp-config.php var/www/html/wp-includes/version.php >/dev/null

if [ "$tables" -lt "$MIN_TABLES" ]; then
    logger -t soc-backup-restore "EROARE doar $tables tabele in wp ($(basename "$db"))"
    echo "EROARE: doar $tables tabele in wp" >&2
    exit 1
fi
logger -t soc-backup-restore "OK tables=$tables db=$(basename "$db") web=$(basename "$web")"
echo "OK: $(basename "$db") -> $tables tabele in wp; $(basename "$web") are wp-config.php si version.php"

#!/bin/bash
# Pasul 3.C — planteaza momelile WordPress/MySQL pe web-prod. Root, O DATA, de om:
#   scp deploy/web-prod/honeytokens-wp.sh deploy/web-prod/soc-honey.php tiberiu@172.30.6.249:/tmp/
#   ssh -t tiberiu@172.30.6.249 'sudo bash /tmp/honeytokens-wp.sh /tmp/soc-honey.php'
#
#   H1  wp-config.php: constante DB_BACKUP_USER/DB_BACKUP_PASSWORD false
#   H1b MySQL: utilizatorul wp_backup NU se creeaza; doar log_warnings>=2, ca orice
#       incercare sa apara ca "Access denied for user 'wp_backup'"
#   H2  mu-plugin soc-honey.php: logheaza incercarile de login cu backup_admin (cont inexistent)
#   H3  backup.sql: momeala inerta (schema falsa + un rand fals cu backup_admin)
#   H4  robots.txt: Disallow /wp-admin-old/ si /db-backup/ + directoare goale
#
# Nu creeaza conturi, nu porneste servicii, nu restarteaza nimic. Fiecare bucata e
# idempotenta (se sare daca exista deja). Copiile de dinainte stau in afara webroot-ului
# (o copie wp-config.php.pre-honey.* in webroot ar fi servita ca text, cu parola reala).
# Ruleaza INAINTE de a crea regulile in Kibana: comenzile de aici ating momelile.
set -euo pipefail

WEB=/var/www/html
CFG=$WEB/wp-config.php
SQL=$WEB/backup.sql
MU=$WEB/wp-content/mu-plugins
PLUGIN_SRC=${1:?folosire: honeytokens-wp.sh /cale/catre/soc-honey.php}
TS=$(date -u +%Y%m%dT%H%M%SZ)
PRE=/root/soc-pre-honey-$TS
# Markerul NU apare in fisierele vizibile atacatorului (robots.txt, wp-config.php): acolo
# idempotenta se verifica dupa continut, iar comentariile arata ca ale unui admin.
MARK="soc-honeytoken (pasul 3.C)"

[ "$(id -u)" -eq 0 ] || { echo "ruleaza ca root" >&2; exit 1; }
[ -f "$CFG" ] || { echo "$CFG lipseste" >&2; exit 1; }
[ -f "$PLUGIN_SRC" ] || { echo "$PLUGIN_SRC lipseste" >&2; exit 1; }
command -v php >/dev/null || { echo "php lipseste (necesar pentru php -l)" >&2; exit 1; }

rnd() { head -c 64 /dev/urandom | base64 -w0 | tr -dc 'A-Za-z0-9' | cut -c1-"$1"; }

install -d -m 700 "$PRE"
cp -p "$CFG" "$PRE/wp-config.php"
[ -f "$WEB/robots.txt" ] && cp -p "$WEB/robots.txt" "$PRE/robots.txt"
echo "copii de siguranta: $PRE"

# ---- H1: constante momeala in wp-config.php ----
if grep -q "'DB_BACKUP_USER'" "$CFG"; then
    echo "H1  wp-config.php: momeala exista deja, neatinsa"
else
    pass=$(rnd 32)
    [ "${#pass}" -eq 32 ] || { echo "generare parola esuata" >&2; exit 1; }
    tmp=$(mktemp)
    # inainte de "That's all, stop editing"; altfel inainte de require wp-settings.php
    awk -v p="$pass" '
        function block() {
            print "/* replica backup (migrare nov 2025) */"
            print "define( '\''DB_BACKUP_USER'\'', '\''wp_backup'\'' );"
            print "define( '\''DB_BACKUP_PASSWORD'\'', '\''" p "'\'' );"
            print ""
            done = 1
        }
        !done && (/stop editing/ || /require_once.*wp-settings\.php/) { block() }
        { print }
        END { if (!done) exit 3 }
    ' "$CFG" > "$tmp" || { rm -f "$tmp"; echo "nu gasesc locul de insertie in wp-config.php" >&2; exit 1; }
    if ! php -l "$tmp" >/dev/null; then
        rm -f "$tmp"; echo "php -l a esuat; wp-config.php neatins" >&2; exit 1
    fi
    cat "$tmp" > "$CFG"     # pastreaza inode, proprietar si mod (root:www-data 640)
    rm -f "$tmp"
    unset pass
    echo "H1  wp-config.php: constante momeala adaugate ($(stat -c '%U:%G %a' "$CFG"))"
fi

# ---- H1b: MySQL logheaza accesul refuzat; contul wp_backup NU exista ----
if command -v mysql >/dev/null && mysql -NBe "SELECT 1" >/dev/null 2>&1; then
    if [ -n "$(mysql -NBe "SELECT 1 FROM mysql.user WHERE user='wp_backup'")" ]; then
        echo "ATENTIE: utilizatorul MySQL wp_backup exista; momeala nu mai e momeala." >&2
    fi
    # @@version (ex. 10.11.14-MariaDB-0ubuntu...); pe Ubuntu @@version_comment e doar "Ubuntu 24.04"
    if mysql -NBe "SELECT @@version" | grep -qi mariadb; then
        lw=$(mysql -NBe "SELECT @@log_warnings")
        if [ "$lw" -lt 2 ]; then
            mysql -e "SET GLOBAL log_warnings=2"
            printf '[mysqld]\n# %s\nlog_warnings = 2\n' "$MARK" > /etc/mysql/mariadb.conf.d/60-soc-honey.cnf
            echo "H1b MariaDB: log_warnings 2 (live + /etc/mysql/mariadb.conf.d/60-soc-honey.cnf)"
        else
            echo "H1b MariaDB: log_warnings=$lw deja (Access denied se logheaza)"
        fi
    else
        echo "H1b MySQL (nu MariaDB): verifica manual log_error_verbosity=3" >&2
    fi
    echo "H1b jurnal erori: $(mysql -NBe 'SELECT @@log_error') (gol/stderr = journald -> syslog)"
else
    echo "H1b mysql lipseste sau root nu are acces prin socket: sarit" >&2
fi

# ---- H2: mu-plugin pentru login ----
[ -d "$MU" ] || install -d -o root -g root -m 755 "$MU"
if [ -f "$MU/soc-honey.php" ]; then
    echo "H2  mu-plugin: exista deja, neatins"
else
    php -l "$PLUGIN_SRC" >/dev/null
    install -o root -g root -m 644 "$PLUGIN_SRC" "$MU/soc-honey.php"
    echo "H2  mu-plugin: $MU/soc-honey.php"
fi

# ---- H3: backup.sql momeala ----
if [ -e "$SQL" ]; then
    echo "H3  backup.sql: exista deja, neatins"
else
    umask 022
    {
        echo "-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)"
        echo "-- Host: localhost    Database: wordpress_old"
        echo "-- ------------------------------------------------------"
        echo "-- Server version	8.0.36"
        echo
        echo "/*!40101 SET NAMES utf8mb4 */;"
        echo "DROP TABLE IF EXISTS \`wp_users\`;"
        echo "CREATE TABLE \`wp_users\` ("
        echo "  \`ID\` bigint(20) unsigned NOT NULL AUTO_INCREMENT,"
        echo "  \`user_login\` varchar(60) NOT NULL DEFAULT '',"
        echo "  \`user_pass\` varchar(255) NOT NULL DEFAULT '',"
        echo "  \`user_email\` varchar(100) NOT NULL DEFAULT '',"
        echo "  \`user_registered\` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',"
        echo "  PRIMARY KEY (\`ID\`)"
        echo ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
        echo
        echo "LOCK TABLES \`wp_users\` WRITE;"
        # hash in format phpass, dar aleator: nu corespunde niciunei parole
        echo "INSERT INTO \`wp_users\` VALUES (2,'backup_admin','\$P\$B$(rnd 30)','backup_admin@localhost','2025-11-03 09:14:52');"
        echo "UNLOCK TABLES;"
        echo
        echo "DROP TABLE IF EXISTS \`wp_options\`;"
        echo "CREATE TABLE \`wp_options\` ("
        echo "  \`option_id\` bigint(20) unsigned NOT NULL AUTO_INCREMENT,"
        echo "  \`option_name\` varchar(191) NOT NULL DEFAULT '',"
        echo "  \`option_value\` longtext NOT NULL,"
        echo "  \`autoload\` varchar(20) NOT NULL DEFAULT 'yes',"
        echo "  PRIMARY KEY (\`option_id\`)"
        echo ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"
        echo
        echo "-- Dump completed on 2025-11-03  9:15:07"
    } > "$SQL"
    chown root:root "$SQL"; chmod 644 "$SQL"
    touch -d '2025-11-03 09:15' "$SQL"
    echo "H3  backup.sql: $(stat -c '%s octeti %U:%G %a' "$SQL")"
fi

# ---- H4: capcane in robots.txt ----
if [ -f "$WEB/robots.txt" ] && grep -q "^Disallow: /db-backup/" "$WEB/robots.txt"; then
    echo "H4  robots.txt: capcanele exista deja, neatins"
else
    if [ ! -f "$WEB/robots.txt" ]; then
        # fisierul fizic inlocuieste robots.txt virtual al WordPress: pastram continutul lui
        printf 'User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n' > "$WEB/robots.txt"
        chown root:root "$WEB/robots.txt"; chmod 644 "$WEB/robots.txt"
    fi
    printf 'Disallow: /wp-admin-old/\nDisallow: /db-backup/\n' >> "$WEB/robots.txt"
    echo "H4  robots.txt: capcane adaugate"
fi
for d in wp-admin-old db-backup; do
    install -d -o root -g root -m 755 "$WEB/$d"
    [ -e "$WEB/$d/index.html" ] || install -o root -g root -m 644 /dev/null "$WEB/$d/index.html"
done

echo
echo "Binare reale (pentru regulile auditd 'never' din honeytokens.AUDITD_RULES):"
for b in apache2 php-fpm8.3 php8.3 tar; do
    p=$(command -v "$b" || true)
    echo "  $b -> ${p:+$(readlink -f "$p")}"
done
echo "uid www-data: $(id -u www-data)"
echo "Momele plantate. Urmeaza: regulile auditd in Fleet, apoi honeytoken_rules.py aplica."

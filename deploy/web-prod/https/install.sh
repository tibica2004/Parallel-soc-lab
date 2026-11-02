#!/usr/bin/env bash
# HTTPS pe web-prod (root). Certificat self-signed (laborator), cheie 600 root; copie /etc/apache2
# inainte; configtest inainte de reload. Idempotent.
set -euo pipefail
SRC="$(dirname "$0")"
PRE=/root/soc-pre-https-$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 700 "$PRE"; cp -a /etc/apache2 "$PRE/"
install -d -o root -g root -m 755 /etc/ssl/soc
if [ ! -f /etc/ssl/soc/web-prod.key ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes \
    -keyout /etc/ssl/soc/web-prod.key -out /etc/ssl/soc/web-prod.crt \
    -subj "/CN=192.168.10.138" -addext "subjectAltName=IP:192.168.10.138,IP:172.30.6.249" 2>/dev/null
  chmod 600 /etc/ssl/soc/web-prod.key; chmod 644 /etc/ssl/soc/web-prod.crt
fi
install -o root -g root -m 644 "$SRC/soc-ssl.conf" /etc/apache2/sites-available/soc-ssl.conf
a2enmod -q ssl
a2ensite -q soc-ssl
apache2ctl configtest
systemctl reload apache2
openssl x509 -in /etc/ssl/soc/web-prod.crt -noout -fingerprint -sha256
echo "HTTPS activ; copie in $PRE"

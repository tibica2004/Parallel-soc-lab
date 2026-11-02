#!/usr/bin/env bash
# Pasul 12b — ModSecurity 2 + OWASP CRS (pachetele Ubuntu, versiuni fixe) in DetectionOnly, pe
# web-prod, ca root. Copie de siguranta a /etc/apache2 si /etc/modsecurity inainte; configtest
# inainte de reload (reload, nu restart). Idempotent.
set -euo pipefail
SRC="$(dirname "$0")"
TS=$(date -u +%Y%m%dT%H%M%SZ)
PRE=/root/soc-pre-modsec-$TS
install -d -m 700 "$PRE"
cp -a /etc/apache2 "$PRE/"
[ -d /etc/modsecurity ] && cp -a /etc/modsecurity "$PRE/"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    libapache2-mod-security2=2.9.7-1build3 modsecurity-crs=3.3.5-2 >/dev/null
[ -f /etc/modsecurity/modsecurity.conf ] || cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
# modsecurity.conf-recommended vine cu DetectionOnly; il fortam oricum (si auditul oprit).
sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/; s/^SecAuditEngine .*/SecAuditEngine Off/' \
    /etc/modsecurity/modsecurity.conf
install -o root -g root -m 644 "$SRC/soc-crs-tuning.conf" /etc/modsecurity/soc-crs-tuning.conf
a2enmod -q security2
apache2ctl configtest
systemctl reload apache2
grep -h "^SecRuleEngine" /etc/modsecurity/*.conf
echo "ModSecurity instalat (DetectionOnly); copie in $PRE"

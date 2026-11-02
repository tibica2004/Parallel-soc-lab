#!/usr/bin/env bash
# Instalarea generatorului pe VM-ul benign-gen (Ubuntu 24.04), ca root (sudo). Idempotent.
# Fisierele benign_gen.py si benign-gen.service sunt copiate inainte in /tmp/soc-benign/.
set -euo pipefail
SRC=/tmp/soc-benign
id soc-benign >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin --home-dir /opt/soc-benign/home soc-benign
install -d -o root -g root -m 755 /opt/soc-benign
install -d -o soc-benign -g soc-benign -m 750 /opt/soc-benign/home
install -d -o root -g soc-benign -m 750 /etc/soc-benign
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv chrony >/dev/null
[ -x /opt/soc-benign/venv/bin/python ] || python3 -m venv /opt/soc-benign/venv
/opt/soc-benign/venv/bin/pip install -q 'playwright==1.47.0' 'requests==2.32.3' 'pillow==10.4.0'
PLAYWRIGHT_BROWSERS_PATH=/opt/soc-benign/browsers /opt/soc-benign/venv/bin/playwright install --with-deps chromium >/dev/null
install -o root -g root -m 644 "$SRC/benign_gen.py" /opt/soc-benign/benign_gen.py
install -o root -g root -m 644 "$SRC/benign-gen.service" /etc/systemd/system/benign-gen.service
[ -f /etc/soc-benign/benign.env ] || install -o root -g soc-benign -m 640 /dev/null /etc/soc-benign/benign.env
systemctl daemon-reload
echo "instalat; lipseste doar /etc/soc-benign/benign.env completat"

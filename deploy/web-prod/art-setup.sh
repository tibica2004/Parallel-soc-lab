#!/usr/bin/env bash
# Pasul 5 — pregatirea testelor Atomic Red Team pe web-prod (root). Idempotent.
#  - depozitul OFICIAL redcanaryco/atomic-red-team la commit fixat, sparse checkout DOAR pe cele
#    20 de tehnici din plan (fara binarele Windows / payload-urile din restul depozitului);
#  - art_runner.py in /opt/soc (root 755);
#  - instantaneul de dinainte (5.7): conturi, cron, chei SSH -> /root/soc-pre-art-<ts>/ (700),
#    ca fiecare cleanup sa poata fi verificat cu diff.
set -euo pipefail
COMMIT=d0cc590bc44b0057562de9089f7f8e01f9d67a3f
TECH="T1053.003 T1136.001 T1098.004 T1003.008 T1070.004 T1070.003 T1082 T1083 T1016 T1049 \
T1057 T1087.001 T1548.001 T1222.002 T1036.005 T1027 T1105 T1048.003 T1046 T1021.004"
DST=/opt/atomic-red-team
SRC="$(dirname "$0")"
if [ ! -d "$DST/.git" ]; then
  git clone --quiet --filter=blob:none --no-checkout https://github.com/redcanaryco/atomic-red-team.git "$DST"
fi
cd "$DST"
git sparse-checkout init --no-cone
printf '%s\n' $(for t in $TECH; do echo "/atomics/$t/"; done) > .git/info/sparse-checkout
git checkout --quiet "$COMMIT"
echo "ART la $(git rev-parse --short HEAD); tehnici: $(ls atomics | wc -l)"
install -d -o root -g root -m 755 /opt/soc
install -o root -g root -m 755 "$SRC/art_runner.py" /opt/soc/art_runner.py
PRE=/root/soc-pre-art-$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 700 "$PRE"
tar -C / -czf "$PRE/etc.tgz" etc/passwd etc/shadow etc/group etc/gshadow etc/sudoers etc/sudoers.d \
    etc/crontab etc/cron.d etc/cron.daily etc/cron.hourly var/spool/cron 2>/dev/null || true
find /root /home -maxdepth 3 -path '*/.ssh/authorized_keys' -exec sha256sum {} \; > "$PRE/authorized_keys.sha256"
sha256sum /etc/passwd /etc/shadow /etc/group /etc/crontab /etc/cron.d/* > "$PRE/etc.sha256" 2>/dev/null || true
echo "instantaneu pre-test: $PRE"

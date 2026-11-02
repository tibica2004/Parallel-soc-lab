#!/usr/bin/env bash
# Pasul 9 (criteriul c8): cheia soc-monitor primeste si citirea starii snapshot-urilor
# (monitor_snapshot, read_slm). Tot doar citire; valoarea cheii NU se schimba (update pe id).
# Pentru OM, cu contul elastic din ~/lab/.env (nu se afiseaza). Idempotent.
set -euo pipefail
cd "$(dirname "$0")/../.."
ES="${ES_URL_ADMIN:-http://localhost:9200}"
PW=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2- | tr -d '"'"'"'')
AUTH=(-u "elastic:$PW")
ID=$(curl -sf "${AUTH[@]}" "$ES/_security/api_key?name=soc-monitor&active_only=true" \
     | python3 -c 'import json,sys; k=json.load(sys.stdin)["api_keys"]; print(k[0]["id"] if k else "")')
[ -n "$ID" ] || { echo "cheia soc-monitor nu exista" >&2; exit 1; }
curl -sf "${AUTH[@]}" -X PUT "$ES/_security/api_key/$ID" -H 'Content-Type: application/json' -d '{
  "role_descriptors": {"m": {"cluster": ["monitor", "monitor_snapshot", "read_slm"], "indices": []}}}'; echo
K=$(grep '^ES_MONITOR_API_KEY=' soc.env | cut -d= -f2-)
echo -n "monitor: _slm/policy/soc-daily (asteptat 200): "
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: ApiKey $K" "$ES/_slm/policy/soc-daily"
echo -n "monitor: citire verdicts-history (asteptat 403): "
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: ApiKey $K" "$ES/verdicts-history/_search"

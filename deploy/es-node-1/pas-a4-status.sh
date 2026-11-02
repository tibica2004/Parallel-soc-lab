#!/usr/bin/env bash
# plann.md A4 — importul dashboard-ului "SOC Status" (deploy/kibana/soc-status.ndjson) in Kibana,
# cu contul elastic din ~/lab/.env (parola nu se afiseaza). Overwrite: reimportul inlocuieste.
set -euo pipefail
cd "$(dirname "$0")/../.."
KB="${KIBANA_URL:-http://localhost:5601}"
PW=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2- | tr -d '"'"'"'')
[ -n "$PW" ] || { echo "ELASTIC_PASSWORD lipsa in .env" >&2; exit 1; }
echo -n "import SOC Status in Kibana: "
curl -sf -u "elastic:$PW" -X POST "$KB/api/saved_objects/_import?overwrite=true" -H 'kbn-xsrf: soc-status' \
  --form file=@deploy/kibana/soc-status.ndjson \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("success" if d.get("success") else "ESEC", d.get("successCount"), "obiecte", d.get("errors", ""))'

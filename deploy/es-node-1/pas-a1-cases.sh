#!/usr/bin/env bash
# plann.md A1 — indexul soc-cases + cheia ES_CASES_WRITER_API_KEY (create_doc/index/read/
# view_index_metadata pe soc-cases; fara delete). Pentru OM, pe es-node-1, cu contul elastic din
# ~/lab/.env (parola si cheia nu se afiseaza). Idempotent. Aceeasi cheie o folosesc orchestratorul
# (deschide/avanseaza cazuri) si interfata de etichetare (inchide, doar omul).
set -euo pipefail
cd "$(dirname "$0")/../.."
ES="${ES_URL_ADMIN:-http://localhost:9200}"
PW=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2- | tr -d '"'"'"'')
[ -n "$PW" ] || { echo "ELASTIC_PASSWORD lipsa in .env" >&2; exit 1; }
AUTH=(-u "elastic:$PW")
if [ "$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$ES/soc-cases")" = 200 ]; then
  echo "soc-cases exista deja, neatins"
else
  curl -sf "${AUTH[@]}" -X PUT "$ES/soc-cases" -H 'Content-Type: application/json' -d '{
    "settings": {"number_of_replicas": 0},
    "mappings": {"dynamic": false, "properties": {
      "case_id": {"type": "keyword"}, "host": {"type": "keyword"}, "state": {"type": "keyword"},
      "origin": {"type": "keyword"}, "opened_at": {"type": "date"}, "updated_at": {"type": "date"},
      "current_tier": {"type": "integer"}, "rule_names": {"type": "keyword"},
      "alert_ids": {"type": "keyword"}, "escalation_reasons": {"type": "keyword"},
      "severity": {"type": "keyword"}, "closed_at": {"type": "date"}, "closed_by": {"type": "keyword"},
      "close_reason": {"type": "keyword"}, "close_notes": {"type": "text"},
      "verdicts": {"type": "object", "enabled": false}, "playbook": {"type": "object", "enabled": false}
    }}}' >/dev/null
  echo "soc-cases creat"
fi
if grep -q '^ES_CASES_WRITER_API_KEY=' soc.env; then
  echo "ES_CASES_WRITER_API_KEY exista deja in soc.env, neatins"
else
  enc=$(curl -sf "${AUTH[@]}" -X POST "$ES/_security/api_key" -H 'Content-Type: application/json' -d '{
    "name": "soc-cases-writer", "role_descriptors": {"w": {"indices": [{"names": ["soc-cases"],
      "privileges": ["create_doc", "index", "read", "view_index_metadata"]}]}}}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["encoded"])')
  printf 'ES_CASES_WRITER_API_KEY=%s\n' "$enc" >> soc.env; chmod 600 soc.env
  echo "ES_CASES_WRITER_API_KEY adaugata in soc.env (valoarea nu se afiseaza)"
fi
K=$(grep '^ES_CASES_WRITER_API_KEY=' soc.env | cut -d= -f2-)
echo -n "cases: citire soc-cases (asteptat 200): "
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: ApiKey $K" "$ES/soc-cases/_count"
echo -n "cases: scriere verdicts-history (asteptat 403): "
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: ApiKey $K" -X POST "$ES/verdicts-history/_doc" \
  -H 'Content-Type: application/json' -d '{"probe": true}'

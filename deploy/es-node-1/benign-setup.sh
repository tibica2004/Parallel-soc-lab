#!/usr/bin/env bash
# Pasul 4 — pentru OM, pe es-node-1, cu contul elastic (ca static-findings-setup.sh).
#  - indexul benign-ground-truth (mapping strict);
#  - cheia soc-benign-writer: DOAR create_doc pe benign-ground-truth (pentru VM-ul benign-gen);
#  - cheia soc-fp-reader: doar citire pe alerte + adevarul benign (pentru fp_rate.py).
# Cheile se scriu in soc.env (600), nu se afiseaza. Idempotent.
set -euo pipefail
cd "$(dirname "$0")/../.."
ES="${ES_URL_ADMIN:-http://localhost:9200}"
PW=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2- | tr -d '"'"'"'')
[ -n "$PW" ] || { echo "ELASTIC_PASSWORD lipsa in .env" >&2; exit 1; }
AUTH=(-u "elastic:$PW")

if [ "$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$ES/benign-ground-truth")" = 200 ]; then
  echo "benign-ground-truth exista deja, neatins"
else
  curl -sf "${AUTH[@]}" -X PUT "$ES/benign-ground-truth" -H 'Content-Type: application/json' -d '{
    "settings": {"number_of_replicas": 0},
    "mappings": {"dynamic": "strict", "properties": {
      "@timestamp": {"type": "date"}, "run_id": {"type": "keyword"},
      "action_id": {"type": "keyword"}, "action": {"type": "keyword"},
      "target": {"type": "keyword"}, "expected_alert": {"type": "boolean"},
      "src_ip": {"type": "ip"}, "phase": {"type": "keyword"},
      "http_status": {"type": "integer"}, "duration_ms": {"type": "integer"},
      "error": {"type": "text"}, "source": {"type": "keyword"}}}}' >/dev/null
  echo "benign-ground-truth creat"
fi

mkkey() {  # nume, variabila, json role_descriptors
  if grep -q "^$2=" soc.env; then echo "$2 exista deja in soc.env, neatins"; return; fi
  enc=$(curl -sf "${AUTH[@]}" -X POST "$ES/_security/api_key" -H 'Content-Type: application/json' \
        -d "{\"name\": \"$1\", \"role_descriptors\": $3}" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["encoded"])')
  [ -n "$enc" ] || { echo "cheia $1 nu s-a creat" >&2; exit 1; }
  printf '%s=%s\n' "$2" "$enc" >> soc.env; chmod 600 soc.env
  echo "$2 adaugata in soc.env (valoarea nu se afiseaza)"
}
mkkey soc-benign-writer ES_BENIGN_WRITER_API_KEY \
  '{"w": {"indices": [{"names": ["benign-ground-truth"], "privileges": ["create_doc"]}]}}'
mkkey soc-fp-reader ES_FP_READER_API_KEY \
  '{"r": {"indices": [{"names": [".alerts-security.alerts-*", "benign-ground-truth", "logs-soc.benign_actions-*"], "privileges": ["read", "view_index_metadata"]}]}}'

W=$(grep '^ES_BENIGN_WRITER_API_KEY=' soc.env | cut -d= -f2-)
R=$(grep '^ES_FP_READER_API_KEY=' soc.env | cut -d= -f2-)
echo -n "writer: citire benign-ground-truth (asteptat 403): "
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: ApiKey $W" "$ES/benign-ground-truth/_search"
echo -n "fp-reader: citire alerte (asteptat 200): "
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: ApiKey $R" "$ES/.alerts-security.alerts-*/_count"
echo -n "fp-reader: scriere benign-ground-truth (asteptat 403): "
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: ApiKey $R" -X POST "$ES/benign-ground-truth/_doc" \
  -H 'Content-Type: application/json' -d '{"phase": "start"}'

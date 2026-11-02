#!/usr/bin/env bash
# Pasul 2 — indexul static-findings + cheia ES_STATIC_WRITER_API_KEY (R8: cheie separata,
# doar pe acest index, fara delete/manage). Se ruleaza de OM pe es-node-1, cu contul elastic
# (CLAUDE.md: codul nu foloseste contul elastic). Parola se citeste din ~/lab/.env si nu se
# afiseaza; cheia noua se scrie direct in ~/lab/soc.env (600) si nu se afiseaza.
#
#   bash deploy/es-node-1/static-findings-setup.sh
#
# Idempotent: indexul existent nu se recreeaza; cheia nu se adauga a doua oara in soc.env.
set -euo pipefail
cd "$(dirname "$0")/../.."
ES="${ES_URL_ADMIN:-http://localhost:9200}"
PW=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2- | tr -d '"'"'"'')
[ -n "$PW" ] || { echo "ELASTIC_PASSWORD lipsa in .env" >&2; exit 1; }
AUTH=(-u "elastic:$PW")

code=$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$ES/static-findings")
if [ "$code" = "200" ]; then
  echo "static-findings exista deja, neatins"
else
  curl -sf "${AUTH[@]}" -X PUT "$ES/static-findings" -H 'Content-Type: application/json' -d '{
    "settings": {"number_of_replicas": 0},
    "mappings": {"dynamic": "strict", "properties": {
      "@timestamp": {"type": "date"},
      "finding_id": {"type": "keyword"}, "host": {"type": "keyword"},
      "rule_id": {"type": "keyword"}, "path": {"type": "keyword"},
      "line": {"type": "integer"}, "snippet_hash": {"type": "keyword"},
      "severity_semgrep": {"type": "keyword"}, "status": {"type": "keyword"},
      "reason": {"type": "keyword"}, "escalate_human": {"type": "boolean"},
      "triage_failed": {"type": "boolean"}, "error": {"type": "text"},
      "prompt_version": {"type": "keyword"}, "prompt_hash": {"type": "keyword"},
      "model_tag": {"type": "keyword"},
      "triage": {"properties": {
        "finding_id": {"type": "keyword"}, "is_true_positive": {"type": "boolean"},
        "confidence": {"type": "integer"}, "description": {"type": "text"},
        "mitigation": {"type": "text"}, "reasoning": {"type": "text"},
        "detection_rule_draft": {"properties": {
          "type": {"type": "keyword"}, "name": {"type": "keyword"},
          "body": {"type": "text"}, "description": {"type": "text"},
          "false_positive_notes": {"type": "text"}}}}}}}}' >/dev/null
  echo "static-findings creat"
fi

if grep -q '^ES_STATIC_WRITER_API_KEY=' soc.env; then
  echo "ES_STATIC_WRITER_API_KEY exista deja in soc.env, neatins"
else
  enc=$(curl -sf "${AUTH[@]}" -X POST "$ES/_security/api_key" -H 'Content-Type: application/json' -d '{
    "name": "soc-static-writer",
    "role_descriptors": {"w": {"indices": [{"names": ["static-findings"],
      "privileges": ["create_doc", "index", "read", "view_index_metadata"]}]}}}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["encoded"])')
  [ -n "$enc" ] || { echo "cheia nu s-a creat" >&2; exit 1; }
  printf 'ES_STATIC_WRITER_API_KEY=%s\n' "$enc" >> soc.env
  chmod 600 soc.env
  echo "ES_STATIC_WRITER_API_KEY adaugata in soc.env (valoarea nu se afiseaza)"
fi

# Verificare cu cheia noua: poate scrie si citi static-findings, nu poate scrie in alt index.
KEY=$(grep '^ES_STATIC_WRITER_API_KEY=' soc.env | cut -d= -f2-)
H=(-H "Authorization: ApiKey $KEY")
echo -n "citire static-findings cu cheia noua: "
curl -s -o /dev/null -w '%{http_code}\n' "${H[@]}" "$ES/static-findings/_count"
echo -n "scriere in verdicts-history cu cheia noua (asteptat 403): "
curl -s -o /dev/null -w '%{http_code}\n' "${H[@]}" -X POST "$ES/verdicts-history/_doc" \
  -H 'Content-Type: application/json' -d '{"probe": true}'

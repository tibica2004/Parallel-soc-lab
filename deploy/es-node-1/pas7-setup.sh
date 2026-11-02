#!/usr/bin/env bash
# Pasul 7 — pentru OM, pe es-node-1, cu contul elastic (codul nu foloseste contul elastic).
#  1. mapping explicit pentru campurile NOI din soc-metrics (type=cycle, type=llm_probe), ca
#     ES sa nu mai extinda singur mapping-ul la scriere (avertismentul auto_put: in versiunea
#     majora urmatoare create_doc/index nu vor mai avea voie). Doar campuri noi: cele existente
#     nu se pot schimba, iar un tip identic e acceptat fara efect.
#  2. importul dashboard-ului "SOC Health" (deploy/kibana/soc-health.ndjson, overwrite).
# Parola se citeste din ~/lab/.env si nu se afiseaza. Idempotent.
set -euo pipefail
cd "$(dirname "$0")/../.."
ES="${ES_URL_ADMIN:-http://localhost:9200}"
KB="${KIBANA_URL:-http://localhost:5601}"
PW=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2- | tr -d '"'"'"'')
[ -n "$PW" ] || { echo "ELASTIC_PASSWORD lipsa in .env" >&2; exit 1; }
AUTH=(-u "elastic:$PW")

echo -n "mapping soc-metrics: "
curl -sf "${AUTH[@]}" -X PUT "$ES/soc-metrics/_mapping" -H 'Content-Type: application/json' -d '{
  "properties": {
    "cycle": {"type": "long"}, "cycle_id": {"type": "keyword"},
    "duration_s": {"type": "float"}, "interval_s": {"type": "long"},
    "queue_depth": {"type": "long"}, "alerts_fetched": {"type": "long"},
    "alerts_processed": {"type": "long"}, "closed_t1": {"type": "long"},
    "escalated_t2": {"type": "long"}, "escalated_human_only": {"type": "long"},
    "honeytoken_hits": {"type": "long"}, "model_timeouts": {"type": "long"},
    "model_errors": {"type": "long"}, "failures": {"type": "object"},
    "llm_calls": {"type": "long"}, "tokens": {"type": "long"}, "llm_ms": {"type": "long"},
    "backlog": {"type": "boolean"}, "sweep_ran": {"type": "boolean"}, "shadow": {"type": "boolean"},
    "model_tag": {"type": "keyword"}, "error": {"type": "text"},
    "latency_ms": {"type": "long"}, "gen_latency_ms": {"type": "long"},
    "gen_eval_count": {"type": "long"}, "ok": {"type": "boolean"},
    "models": {"type": "keyword"}, "consecutive_failures": {"type": "long"}
  }}' >/dev/null && echo OK

echo -n "import SOC Health in Kibana: "
curl -sf "${AUTH[@]}" -X POST "$KB/api/saved_objects/_import?overwrite=true" -H 'kbn-xsrf: soc-health' \
  --form file=@deploy/kibana/soc-health.ndjson \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("success" if d.get("success") else "ESEC", d.get("successCount"), "obiecte", d.get("errors", ""))'

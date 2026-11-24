#!/usr/bin/env bash
# Faza 26 — PROPUS, pentru OM, pe es-node-1, cu contul elastic (codul nu foloseste contul elastic).
# Mapping explicit pentru campurile NOI din soc-metrics type=cycle scrise pe SOC_PIPELINE=intake
# (contabilitatea intrarii), ca ES sa nu le mapeze singur la prima scriere (vezi pas7-setup.sh).
# Doar campuri noi; idempotent. Parola se citeste din .env si nu se afiseaza.
# Fara efect pe SOC_PIPELINE=legacy (campurile nu se scriu acolo, in afara de `pipeline`).
set -euo pipefail
cd "$(dirname "$0")/../.."
ES="${ES_URL_ADMIN:-http://localhost:9200}"
PW=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2- | tr -d '"'"'"'')
[ -n "$PW" ] || { echo "ELASTIC_PASSWORD lipsa in .env" >&2; exit 1; }
AUTH=(-u "elastic:$PW")

echo -n "mapping soc-metrics (faza 26): "
curl -sf "${AUTH[@]}" -X PUT "$ES/soc-metrics/_mapping" -H 'Content-Type: application/json' -d '{
  "properties": {
    "pipeline": {"type": "keyword"},
    "flood_cases": {"type": "long"},
    "intake": {"properties": {
      "citite": {"type": "long"}, "consumate": {"type": "long"}, "amanate": {"type": "long"},
      "cazuri": {"type": "long"}, "grupate": {"type": "long"}, "in_potop": {"type": "long"},
      "incidente_potop": {"type": "long"}, "critice": {"type": "long"},
      "critice_notificate": {"type": "long"}, "respinse": {"type": "long"},
      "pagini": {"type": "long"}, "trunchiat": {"type": "boolean"}
    }}
  }}' >/dev/null && echo OK

#!/usr/bin/env bash
# Pasul 6.3 — snapshot-uri zilnice ale memoriei SOC + test de restaurare. Pe es-node-1, ca
# tiberiu (grupul docker), cu contul elastic din ~/lab/.env (parola nu se afiseaza).
#
#  1. recreeaza containerul es01 cu volumul essnapshots + path.repo (ES indisponibil ~1-2 min:
#     orchestratorul trece ciclul cu eroare si continua; NU rula in timpul harness-ului);
#  2. depozitul soc_local (fs, comprimat) + politica SLM soc-daily (02:00 UTC, 30 zile, 7-45);
#  3. ruleaza politica o data, restaureaza verdicts-history ca restored-verdicts-history,
#     compara numarul de documente, sterge DOAR copia restaurata.
# Idempotent. Copia off-host a directorului de snapshot e separata (host ales de om).
set -euo pipefail
cd "$(dirname "$0")/../.."
ES="${ES_URL_ADMIN:-http://localhost:9200}"
PW=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2- | tr -d '"'"'"'')
[ -n "$PW" ] || { echo "ELASTIC_PASSWORD lipsa in .env" >&2; exit 1; }
AUTH=(-u "elastic:$PW")
J=(-H 'Content-Type: application/json')
REPO_PATH=/usr/share/elasticsearch/snapshots

if docker exec es01 test -d "$REPO_PATH" 2>/dev/null; then
  echo "es01 are deja $REPO_PATH, nu recreez containerul"
else
  echo "recreez es01 cu volumul de snapshot..."
  docker compose up -d es01
  for i in $(seq 1 60); do
    curl -s "${AUTH[@]}" "$ES/_cluster/health" | grep -qE '"status":"(green|yellow)"' && break
    sleep 5
  done
  curl -s "${AUTH[@]}" "$ES/_cluster/health?filter_path=status"; echo
fi
docker exec -u 0 es01 chown 1000:0 "$REPO_PATH"
curl -s "${AUTH[@]}" "$ES/_nodes/settings?filter_path=nodes.*.settings.path.repo"; echo

echo -n "depozit soc_local: "
curl -sf "${AUTH[@]}" "${J[@]}" -X PUT "$ES/_snapshot/soc_local" -d "{
  \"type\": \"fs\", \"settings\": {\"location\": \"$REPO_PATH\", \"compress\": true}}"; echo
echo -n "verificare depozit: "
curl -sf "${AUTH[@]}" -X POST "$ES/_snapshot/soc_local/_verify" | head -c 200; echo

echo -n "politica SLM soc-daily: "
curl -sf "${AUTH[@]}" "${J[@]}" -X PUT "$ES/_slm/policy/soc-daily" -d '{
  "schedule": "0 0 2 * * ?", "name": "<soc-{now/d}>", "repository": "soc_local",
  "config": {"indices": ["verdicts-history", "soc-audit", "soc-incidents", "soc-traces",
                         "soc-metrics", "soc-state", "asset-vulns", "asset-inventory",
                         "static-findings", "benign-ground-truth", "baseline-entity-parentchild",
                         "baseline-rarity", "attack-emulation-ground-truth"],
             "ignore_unavailable": true, "include_global_state": false},
  "retention": {"expire_after": "30d", "min_count": 7, "max_count": 45}}'; echo

echo "rulez politica o data..."
SNAP=$(curl -sf "${AUTH[@]}" -X POST "$ES/_slm/policy/soc-daily/_execute" \
       | python3 -c 'import json,sys; print(json.load(sys.stdin)["snapshot_name"])')
for i in $(seq 1 60); do
  ST=$(curl -s "${AUTH[@]}" "$ES/_snapshot/soc_local/$SNAP" \
       | python3 -c 'import json,sys; s=json.load(sys.stdin).get("snapshots"); print(s[0]["state"] if s else "PENDING")')
  [ "$ST" = SUCCESS ] && break
  [ "$ST" = FAILED ] && { echo "snapshot $SNAP FAILED" >&2; exit 1; }
  sleep 5
done
echo "snapshot $SNAP: $ST"
curl -s "${AUTH[@]}" "$ES/_snapshot/soc_local/$SNAP?filter_path=snapshots.indices,snapshots.shards"; echo

echo "test de restaurare: verdicts-history -> restored-verdicts-history"
curl -s "${AUTH[@]}" -X DELETE "$ES/restored-verdicts-history" >/dev/null 2>&1 || true
curl -sf "${AUTH[@]}" "${J[@]}" -X POST "$ES/_snapshot/soc_local/$SNAP/_restore?wait_for_completion=true" -d '{
  "indices": "verdicts-history", "rename_pattern": "(.+)", "rename_replacement": "restored-$1",
  "include_global_state": false}' >/dev/null
# originalul poate creste intre snapshot si acum: comparam cu numarul din snapshot (la momentul lui)
ORIG=$(curl -s "${AUTH[@]}" "$ES/verdicts-history/_count" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
REST=$(curl -s "${AUTH[@]}" "$ES/restored-verdicts-history/_count" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')
echo "verdicts-history acum: $ORIG; restaurat din snapshot: $REST (asteptat: egal sau putin mai mic)"
curl -sf "${AUTH[@]}" -X DELETE "$ES/restored-verdicts-history" >/dev/null && echo "copia restaurata stearsa"
curl -s "${AUTH[@]}" "$ES/_slm/policy/soc-daily?filter_path=*.last_success,*.next_execution"; echo

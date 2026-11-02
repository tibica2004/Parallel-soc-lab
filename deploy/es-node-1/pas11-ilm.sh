#!/usr/bin/env bash
# Pasul 11 — retentia logurilor + cheia de monitorizare. Pe es-node-1, cu contul elastic din
# ~/lab/.env (parola si cheia nu se afiseaza). Idempotent.
#
# Azi (masurat 2026-11-02): toate fluxurile logs-* folosesc logs@lifecycle (rollover, FARA
# stergere); 6.3 GB. Dupa:
#   soc-logs-30d: apache, suricata, syslog, logurile agentului        -> sterse la 30 de zile
#   soc-logs-45d: endpoint (proces/fisier/retea/alerte), auditd, auth  -> 45 de zile (dovezile)
#   soc-logs-180d: soc.sbom (mic; istoria inventarului pentru N-day)
# Aplicat prin sabloanele <flux>@custom (calea suportata de Fleet; supravietuieste upgrade-urilor
# integrarilor) + pe indicii existenti. Indicii memoriei SOC (verdicts-history, soc-audit, ...)
# NU primesc stergere: sunt mici si au snapshot zilnic (pasul 6.3).
# Plus cheia soc-monitor (doar cluster:monitor) -> ES_MONITOR_API_KEY in soc.env, pentru alertele
# de disc / heap / cluster rosu din absence_check.
set -euo pipefail
cd "$(dirname "$0")/../.."
ES="${ES_URL_ADMIN:-http://localhost:9200}"
PW=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2- | tr -d '"'"'"'')
[ -n "$PW" ] || { echo "ELASTIC_PASSWORD lipsa in .env" >&2; exit 1; }
AUTH=(-u "elastic:$PW")
J=(-H 'Content-Type: application/json')

policy() {  # nume, zile pana la stergere
  echo -n "politica $1: "
  curl -sf "${AUTH[@]}" "${J[@]}" -X PUT "$ES/_ilm/policy/$1" -d "{\"policy\": {\"phases\": {
    \"hot\": {\"actions\": {\"rollover\": {\"max_age\": \"7d\", \"max_primary_shard_size\": \"20gb\"}}},
    \"delete\": {\"min_age\": \"$2d\", \"actions\": {\"delete\": {}}}}}}"; echo
}
policy soc-logs-30d 30
policy soc-logs-45d 45
policy soc-logs-180d 180

apply() {  # flux, politica
  local ds="$1" pol="$2" tpl="$1@custom"
  # sablonul @custom poate exista (gol, creat de Fleet, sau cu setari ale omului): le pastram
  local cur
  cur=$(curl -s "${AUTH[@]}" "$ES/_component_template/$tpl" \
        | python3 -c 'import json,sys
d=json.load(sys.stdin).get("component_templates") or []
print(json.dumps(d[0]["component_template"]["template"] if d else {}))')
  local body
  body=$(POL="$pol" CUR="$cur" python3 -c 'import json,os
t=json.loads(os.environ["CUR"]) or {}
s=t.setdefault("settings", {})
s.setdefault("index", {})
s["index"].setdefault("lifecycle", {})["name"]=os.environ["POL"]
print(json.dumps({"template": t, "_meta": {"managed_by": "soc-pas11"}}))')
  curl -sf "${AUTH[@]}" "${J[@]}" -X PUT "$ES/_component_template/$tpl" -d "$body" >/dev/null
  # indicii existenti ai fluxului (setarea se aplica si celor vechi)
  curl -sf "${AUTH[@]}" "${J[@]}" -X PUT "$ES/$ds-*/_settings" \
       -d "{\"index\": {\"lifecycle\": {\"name\": \"$pol\"}}}" >/dev/null
  echo "  $ds -> $pol"
}
for ds in logs-apache.access logs-apache.error logs-suricata.eve logs-system.syslog \
          logs-elastic_agent logs-elastic_agent.auditbeat logs-elastic_agent.endpoint_security \
          logs-elastic_agent.filebeat logs-elastic_agent.fleet_server logs-elastic_agent.metricbeat; do
  apply "$ds" soc-logs-30d
done
for ds in logs-endpoint.events.process logs-endpoint.events.file logs-endpoint.events.network \
          logs-endpoint.alerts logs-auditd_manager.auditd logs-system.auth; do
  apply "$ds" soc-logs-45d
done
apply logs-soc.sbom soc-logs-180d

echo "verificare (ilm_policy per flux):"
curl -s "${AUTH[@]}" "$ES/_data_stream/logs-*" | python3 -c 'import json,sys
for s in json.load(sys.stdin)["data_streams"]: print("  ", s["name"], "->", s.get("ilm_policy"))'
echo "explain pe un indice apache:"
curl -s "${AUTH[@]}" "$ES/logs-apache.access-*/_ilm/explain?filter_path=indices.*.policy,indices.*.phase" | head -c 300; echo

if grep -q '^ES_MONITOR_API_KEY=' soc.env; then
  echo "ES_MONITOR_API_KEY exista deja in soc.env, neatins"
else
  enc=$(curl -sf "${AUTH[@]}" "${J[@]}" -X POST "$ES/_security/api_key" -d '{
    "name": "soc-monitor", "role_descriptors": {"m": {"cluster": ["monitor"], "indices": []}}}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["encoded"])')
  printf 'ES_MONITOR_API_KEY=%s\n' "$enc" >> soc.env; chmod 600 soc.env
  echo "ES_MONITOR_API_KEY adaugata in soc.env (valoarea nu se afiseaza)"
fi
K=$(grep '^ES_MONITOR_API_KEY=' soc.env | cut -d= -f2-)
echo -n "monitor: _cluster/health (asteptat 200): "
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: ApiKey $K" "$ES/_cluster/health"
echo -n "monitor: citire verdicts-history (asteptat 403): "
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: ApiKey $K" "$ES/verdicts-history/_search"

#!/usr/bin/env bash
# Completari (2026-11-03), pentru OM, cu contul elastic din ~/lab/.env (nu se afiseaza). Idempotent.
#  1. replici 0 pe nodul unic: ES ramane galben cu 70 de shard-uri nealocate (replici = 1);
#     un template de componenta + setarea pe indicii existenti.
#  2. cheia soc-reader (ES_READER_API_KEY) primeste citire si pe benign-ground-truth si soc-cases
#     (indici creati dupa cheie; valoarea cheii NU se schimba: update pe id).
#  3. instaleaza testul lunar de restore (service + timer) — cere sudo (parola la tastatura).
# Cheia Kibana pentru check_agent (fleet:read) se face in UI (vezi docs/pasi/pas-13-completari.md).
set -euo pipefail
cd "$(dirname "$0")/../.."
ES="${ES_URL_ADMIN:-http://localhost:9200}"
PW=$(grep -E '^ELASTIC_PASSWORD=' .env | head -1 | cut -d= -f2- | tr -d '"'"'"'')
AUTH=(-u "elastic:$PW")
J=(-H 'Content-Type: application/json')

echo "== 1. replici 0 (nod unic)"
# template de componenta cu prioritate mica: se aplica fluxurilor noi prin <flux>@custom (pasul 11)
# NU e necesar — Fleet seteaza deja replici 0 pe logs-*; indicii SOC (creati de om) au replici 1.
SOC_IDX="verdicts-history,soc-audit,soc-incidents,soc-traces,soc-state,soc-metrics,soc-hunts,asset-vulns,static-findings,benign-ground-truth,baseline-entity-parentchild,asset-inventory,soc-cases,soc-labels"
curl -s "${AUTH[@]}" -X PUT "$ES/$SOC_IDX/_settings?ignore_unavailable=true" "${J[@]}" \
     -d '{"index":{"number_of_replicas":0}}'; echo
echo -n "shard-uri nealocate dupa: "
curl -s "${AUTH[@]}" "$ES/_cluster/health" | python3 -c 'import json,sys; h=json.load(sys.stdin); print(h["status"], h["unassigned_shards"])'
echo "(daca mai raman nealocate: GET _cat/shards?v&h=index,prirep,state | grep UNASSIGNED si repeta PUT pe acei indici)"

echo "== 2. cheia soc-reader: + benign-ground-truth, soc-cases (citire)"
ID=$(curl -sf "${AUTH[@]}" "$ES/_security/api_key?name=soc-reader&active_only=true" \
     | python3 -c 'import json,sys; k=json.load(sys.stdin)["api_keys"]; print(k[0]["id"] if k else "")')
[ -n "$ID" ] || { echo "cheia soc-reader nu exista" >&2; exit 1; }
BODY=$(curl -sf "${AUTH[@]}" "$ES/_security/api_key/$ID" | python3 -c '
import json,sys
k=json.load(sys.stdin)["api_keys"][0]
rd=k["role_descriptors"]; name=next(iter(rd)); r=rd[name]
for idx in r["indices"]:
    if "read" in idx["privileges"] and "soc-metrics" in idx["names"]:
        for n in ("benign-ground-truth","soc-cases"):
            if n not in idx["names"]: idx["names"].append(n)
        break
else:
    r["indices"].append({"names":["benign-ground-truth","soc-cases"],"privileges":["read","view_index_metadata"]})
print(json.dumps({"role_descriptors": rd}))')
curl -sf "${AUTH[@]}" -X PUT "$ES/_security/api_key/$ID" "${J[@]}" -d "$BODY"; echo
K=$(grep '^ES_READER_API_KEY=' soc.env | cut -d= -f2-)
for i in benign-ground-truth soc-cases; do
    echo -n "reader: $i/_count (asteptat 200): "
    curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: ApiKey $K" "$ES/$i/_count"
done

echo "== 3. testul lunar de restore (sudo)"
sudo install -o root -g root -m 755 deploy/soc-backup-restore-test.sh /usr/local/bin/
sudo install -o root -g root -m 644 deploy/soc-backup-restore-test.service deploy/soc-backup-restore-test.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now soc-backup-restore-test.timer
systemctl list-timers soc-backup-restore-test.timer --no-pager
echo "ruleaza acum, o data, ca sa existe stamp-ul: sudo systemctl start soc-backup-restore-test.service && cat /var/backups/web-prod/.restore-test-ok"

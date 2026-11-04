#!/usr/bin/env bash
# Completari (2026-11-03), pentru OM, cu contul elastic din ~/lab/.env (nu se afiseaza). Idempotent.
#  1. replici 0 pe nodul unic: ES ramane galben cu 70 de shard-uri nealocate (replici = 1);
#     pe indicii existenti nealocati + logs@custom/metrics@custom pentru rollover.
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
# (a) indicii memoriei SOC (creati de om, replici 1)
SOC_IDX="verdicts-history,soc-audit,soc-incidents,soc-traces,soc-state,soc-metrics,soc-hunts,asset-vulns,static-findings,benign-ground-truth,baseline-entity-parentchild,asset-inventory,soc-cases,soc-labels"
curl -sf "${AUTH[@]}" -X PUT "$ES/$SOC_IDX/_settings?ignore_unavailable=true" "${J[@]}" \
     -d '{"index":{"number_of_replicas":0}}' >/dev/null
# (b) restul indicilor cu shard-uri nealocate, cititi din _cluster/health (masurat 2026-11-04: fluxurile
#     Fleet logs-*/metrics-* au tot replici 1, plus indicii Kibana entity store / liste / risk-score)
UNASSIGNED=$(curl -sf "${AUTH[@]}" "$ES/_cluster/health?level=indices&filter_path=indices.*.unassigned_shards" \
  | python3 -c 'import json,sys
d=json.load(sys.stdin).get("indices",{})
print("\n".join(n for n,v in d.items() if v.get("unassigned_shards")))')
# cate o cerere per indice: lista intreaga intr-un URL depaseste limita de 4 KB a liniei HTTP
n_ok=0; n_err=0
for idx in $UNASSIGNED; do
  if curl -sf "${AUTH[@]}" -X PUT "$ES/$idx/_settings" "${J[@]}" \
       -d '{"index":{"number_of_replicas":0}}' >/dev/null; then n_ok=$((n_ok+1))
  else n_err=$((n_err+1)); echo "  esec: $idx" >&2; fi
done
echo "indici nealocati trecuti pe replici 0: $n_ok ok, $n_err esec"
# (c) indicii viitori ai fluxurilor Fleet (rollover): logs@custom / metrics@custom, setarile existente pastrate
for tpl in logs@custom metrics@custom; do
  cur=$(curl -s "${AUTH[@]}" "$ES/_component_template/$tpl" | python3 -c 'import json,sys
d=json.load(sys.stdin).get("component_templates") or []
c=d[0]["component_template"] if d else {}
print(json.dumps(c))')
  body=$(CUR="$cur" python3 -c 'import json,os
c=json.loads(os.environ["CUR"]) or {}
t=c.setdefault("template", {})
t.setdefault("settings", {}).setdefault("index", {})["number_of_replicas"]=0
c.setdefault("_meta", {})["replicas_by"]="soc-pas13"
print(json.dumps(c))')
  curl -sf "${AUTH[@]}" "${J[@]}" -X PUT "$ES/_component_template/$tpl" -d "$body" >/dev/null
  echo "  $tpl: number_of_replicas 0"
done
echo -n "dupa: "
curl -s "${AUTH[@]}" "$ES/_cluster/health" | python3 -c 'import json,sys; h=json.load(sys.stdin); print(h["status"], h["unassigned_shards"], "nealocate")'
echo "(indicii zilnici ai entity store-ului Kibana pot reveni cu replici 1; se vad maine in health)"

echo "== 2. cheia soc-reader: + benign-ground-truth, soc-cases (citire)"
# ID-ul cheii folosite efectiv (din soc.env, prin _authenticate): exista mai multe chei active
# numite soc-reader (create la reluari pe 2026-10-29), dupa nume s-ar alege una la intamplare.
K=$(grep '^ES_READER_API_KEY=' soc.env | cut -d= -f2-)
ID=$(curl -sf -H "Authorization: ApiKey $K" "$ES/_security/_authenticate" \
     | python3 -c 'import json,sys; print((json.load(sys.stdin).get("api_key") or {}).get("id",""))')
[ -n "$ID" ] || { echo "ES_READER_API_KEY din soc.env nu se autentifica" >&2; exit 1; }
echo "cheia folosita: id $ID"
BODY=$(curl -sf "${AUTH[@]}" "$ES/_security/api_key?id=$ID" | python3 -c '
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

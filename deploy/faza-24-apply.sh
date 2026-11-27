#!/usr/bin/env bash
# =================================================================================================
# Faza 24 (decizia invatata din etichete, in stil Arcanna) — SCRIPTUL DE APLICARE, pentru OM.
#
# Se ruleaza O SINGURA DATA, pe es-node-1, din checkout-ul de productie (~/lab) adus pe ramura fazei,
# DUPA revizuirea pull request-ului:
#
#     cd ~/lab && git stash push -m "inainte de faza 24"   # ~/lab are modificari locale necomise
#     git fetch origin && git checkout faza-24-decizie-invatata
#     bash deploy/faza-24-apply.sh            # cere sudo pentru systemd
#
# (La 2026-11-27, ~/lab avea necomise: orchestrator.py, cycle_metrics.py, docs/pasi/pas-10-12.md si
# comentarii in deploy/soc-orchestrator.service; ExecStart-ul instalat e acelasi cu cel din depozit.)
#
# Ce face (toate pasii sunt idempotenti: a doua rulare nu schimba nimic din ce exista deja):
#   1. verificari (fara efecte): suntem in depozit, testele unitare trec, prompturile la zi,
#      ExecStart-ul orchestratorului neschimbat fata de depozit;
#   2. indicii noi soc-buckets si soc-learning-audit + campuri noi in verdicts-history / soc-metrics;
#   3. cheile noi: ES_LEARNING_WRITER_API_KEY (grupuri) si KIBANA_ALERT_TAGS_API_KEY (etichete pe
#      alerte prin API-ul Kibana); valorile merg direct in soc.env, NU se afiseaza;
#   4. setarile noi in soc.env: T1_CASCADE=shadow (cascada porneste in UMBRA), SOC_BUS=inprocess;
#   5. data/models (registrul modelelor);
#   6. unitatile systemd noi (soc-learn, soc-learn-guard, soc-learn-gold) — unitati NOI, nicio
#      linie ExecStart existenta nu se atinge;
#   7. repornirea soc-orchestrator (ca sa citeasca soc.env) si verificarea ca ruleaza in umbra.
#
# Ce NU face: nu iese din shadow mode (SHADOW_MODE ramane fortat in ExecStart), nu activeaza niciun
# model (o face controlorul, din etichete umane, dupa conditiile din docs/pasi/pas-24.md), nu atinge
# web-prod, nu sterge nimic. Revenire: deploy/faza-24-rollback.sh.
#
# Parola contului elastic se citeste din ~/lab/.env (ELASTIC_PASSWORD), ca la celelalte scripturi
# din deploy/es-node-1/; codul SOC-ului nu foloseste contul elastic (L7).
# =================================================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
ES="${ES_URL_ADMIN:-http://localhost:9200}"
KB="${KIBANA_URL_ADMIN:-http://localhost:5601}"
PY="$ROOT/venv/bin/python"
ENVF="$ROOT/soc.env"

say() { printf '\n== %s\n' "$*"; }
ok()  { printf '   OK  %s\n' "$*"; }
die() { printf '   EROARE  %s\n' "$*" >&2; exit 1; }

# set_env CHEIE VALOARE: adauga sau inlocuieste linia CHEIE=... in soc.env (600). Valoarea nu se
# afiseaza (poate fi o cheie). Idempotent: aceeasi valoare -> fisierul ramane identic.
set_env() {
  "$PY" - "$ENVF" "$1" "$2" <<'PYEOF'
import os, sys
path, key, val = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(path, encoding="utf-8").read().splitlines() if os.path.exists(path) else []
out, done = [], False
for l in lines:
    if l.split("=", 1)[0].strip() == key:
        if not done:
            out.append(f"{key}={val}")
            done = True
        continue
    out.append(l)
if not done:
    out.append(f"{key}={val}")
new = "\n".join(out) + "\n"
if not os.path.exists(path) or open(path, encoding="utf-8").read() != new:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(new)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
PYEOF
}
has_env() { grep -qE "^$1=." "$ENVF"; }

# ---------------------------------------------------------------------------------------------
say "1. Verificari (fara efecte)"
# Depozitul e cel asteptat si contine fisierele fazei.
[ -f "$ROOT/config/pipelines.yml" ] && [ -f "$ROOT/elasticlab/tier1/cascade.py" ] \
  || die "nu sunt pe ramura fazei 24 (lipsesc config/pipelines.yml / elasticlab/tier1/cascade.py)"
[ -f "$ENVF" ] || die "lipseste $ENVF"
[ -x "$PY" ] || die "lipseste venv-ul de productie ($PY)"
# Fara modificari locale necomise pe fisierele urmarite: altfel nu stim ce cod ruleaza.
[ -z "$(git status --porcelain --untracked-files=no)" ] || die "modificari locale necomise in $ROOT (git stash)"
# Parola elastic, citita fara afisare.
PW=$(grep -E '^ELASTIC_PASSWORD=' "$ROOT/.env" | head -1 | cut -d= -f2- | tr -d '"'"'"'')
[ -n "$PW" ] || die "ELASTIC_PASSWORD lipsa in .env"
AUTH=(-u "elastic:$PW")
# Testele unitare (fara ES si fara model): o regresie de cod opreste aplicarea.
ES_API_KEY=x "$PY" -m pytest -q -p no:cacheprovider tests >/tmp/faza24-pytest.txt 2>&1 \
  || die "testele unitare pica (vezi /tmp/faza24-pytest.txt); nu aplic nimic"
ok "teste unitare: $(tail -1 /tmp/faza24-pytest.txt)"
# Hash-ul prompturilor trebuie sa fie cel din MANIFEST (L9).
ES_API_KEY=x "$PY" prompts.py --check >/dev/null || die "prompturile nu corespund MANIFEST-ului (L9)"
ok "prompturi la zi"
# ExecStart-ul orchestratorului din depozit e acelasi cu cel instalat (L1: nu se modifica).
want=$(grep '^ExecStart=' deploy/soc-orchestrator.service)
have=$(grep '^ExecStart=' /etc/systemd/system/soc-orchestrator.service 2>/dev/null || true)
[ "$want" = "$have" ] || die "ExecStart instalat difera de cel din depozit; nu continui"
echo "$want" | grep -q 'SHADOW_MODE=true' || die "ExecStart fara SHADOW_MODE=true"
ok "ExecStart neschimbat, shadow fortat"

# ---------------------------------------------------------------------------------------------
say "2. Indicii si campurile noi"
# soc-buckets: un document per grup (_id = bucket_id). Mapping explicit: identificatorii si valorile
# punctelor de decizie sunt keyword (interogari term), voturile si exemplele nu se indexeaza.
if [ "$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$ES/soc-buckets")" = 200 ]; then
  ok "soc-buckets exista, neatins"
else
  curl -sf "${AUTH[@]}" -X PUT "$ES/soc-buckets" -H 'Content-Type: application/json' -d '{
    "settings": {"number_of_replicas": 0},
    "mappings": {"dynamic": false, "properties": {
      "bucket_id": {"type": "keyword"}, "pipeline": {"type": "keyword"}, "dp_version": {"type": "integer"},
      "values": {"type": "object", "dynamic": true},
      "count": {"type": "long"}, "first_seen": {"type": "date"}, "last_seen": {"type": "date"},
      "consensus": {"type": "keyword"}, "votes_attack": {"type": "integer"}, "votes_benign": {"type": "integer"},
      "labeled_at": {"type": "date"}, "cascade_closed": {"type": "long"}, "control_samples": {"type": "long"},
      "last_closed_at": {"type": "date"},
      "system": {"properties": {"step": {"type": "keyword"}, "decision": {"type": "keyword"},
        "confidence": {"type": "integer"}, "p_attack": {"type": "float"}, "outlier": {"type": "boolean"},
        "model_hash": {"type": "keyword"}, "model_state": {"type": "keyword"}, "mode": {"type": "keyword"},
        "would_close": {"type": "boolean"}, "applied": {"type": "boolean"}, "control_sample": {"type": "boolean"},
        "at": {"type": "date"}}},
      "votes": {"type": "object", "enabled": false}, "examples": {"type": "object", "enabled": false},
      "tier2_summary": {"type": "object", "enabled": false}
    }}}' >/dev/null && ok "soc-buckets creat"
fi
# Valorile punctelor de decizie: keyword dinamic (sunt categorii scurte, din multimi inchise).
curl -sf "${AUTH[@]}" -X PUT "$ES/soc-buckets/_mapping" -H 'Content-Type: application/json' -d '{
  "dynamic_templates": [{"dp_values": {"path_match": "values.*", "mapping": {"type": "keyword"}}}]}' >/dev/null \
  && ok "soc-buckets: values.* keyword"
# soc-learning-audit: auditul buclei de invatare (tranzitiile modelelor), doar adaugare.
if [ "$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "$ES/soc-learning-audit")" = 200 ]; then
  ok "soc-learning-audit exista, neatins"
else
  curl -sf "${AUTH[@]}" -X PUT "$ES/soc-learning-audit" -H 'Content-Type: application/json' -d '{
    "settings": {"number_of_replicas": 0},
    "mappings": {"properties": {"@timestamp": {"type": "date"}, "type": {"type": "keyword"},
      "pipeline": {"type": "keyword"}, "model_hash": {"type": "keyword"}, "from_state": {"type": "keyword"},
      "to_state": {"type": "keyword"}, "actor": {"type": "keyword"}, "reason": {"type": "text"}}}}' >/dev/null \
    && ok "soc-learning-audit creat"
fi
# verdicts-history: campul `cascade` (doar cu T1_CASCADE != off) si bucket_id, ca keyword/boolean.
# PUT _mapping doar ADAUGA campuri; daca exista deja cu acelasi tip, e fara efect.
curl -sf "${AUTH[@]}" -X PUT "$ES/verdicts-history/_mapping" -H 'Content-Type: application/json' -d '{
  "properties": {"bucket_id": {"type": "keyword"},
    "cascade": {"properties": {"mode": {"type": "keyword"}, "pipeline": {"type": "keyword"},
      "dp_version": {"type": "integer"}, "bucket_id": {"type": "keyword"}, "step": {"type": "keyword"},
      "would_close": {"type": "boolean"}, "applied": {"type": "boolean"}, "control_sample": {"type": "boolean"},
      "reasons": {"type": "keyword"}, "applied_reasons": {"type": "boolean"}, "consensus": {"type": "keyword"},
      "pipeline_active": {"type": "boolean"}, "model_state": {"type": "keyword"},
      "model_hash": {"type": "keyword"}, "source": {"type": "keyword"}, "decision": {"type": "keyword"},
      "confidence": {"type": "integer"}, "outlier": {"type": "boolean"}, "error": {"type": "keyword"}}}}}' \
  >/dev/null && ok "verdicts-history: cascade.* mapat"
# soc-metrics: rezumatul cascadei pe ciclu si documentele buclei de invatare.
curl -sf "${AUTH[@]}" -X PUT "$ES/soc-metrics/_mapping" -H 'Content-Type: application/json' -d '{
  "properties": {"cascade": {"properties": {"mode": {"type": "keyword"}, "would_close": {"type": "long"},
      "closed": {"type": "long"}, "control": {"type": "long"}, "errors": {"type": "long"},
      "outliers": {"type": "long"}, "steps": {"type": "object", "dynamic": true}}},
    "pipeline_id": {"type": "keyword"}, "model_hash": {"type": "keyword"},
    "from_state": {"type": "keyword"}, "to_state": {"type": "keyword"}, "actor": {"type": "keyword"},
    "active_hash": {"type": "keyword"}, "shadow_hash": {"type": "keyword"}, "passed": {"type": "boolean"}}}' \
  >/dev/null && ok "soc-metrics: campurile fazei 24 mapate"

# ---------------------------------------------------------------------------------------------
say "3. Cheile noi (valorile merg direct in soc.env, nu se afiseaza)"
# ES_LEARNING_WRITER_API_KEY: grupurile (citire + scriere, fara delete), auditul invatarii (doar
# adaugare) si citirea verdictelor / metricilor de care are nevoie controlorul.
if has_env ES_LEARNING_WRITER_API_KEY; then
  ok "ES_LEARNING_WRITER_API_KEY exista in soc.env, neatinsa"
else
  enc=$(curl -sf "${AUTH[@]}" -X POST "$ES/_security/api_key" -H 'Content-Type: application/json' -d '{
    "name": "soc-learning-writer", "role_descriptors": {"learn": {"indices": [
      {"names": ["soc-buckets"], "privileges": ["read", "create_doc", "index", "view_index_metadata"]},
      {"names": ["soc-learning-audit"], "privileges": ["create_doc", "read"]},
      {"names": ["verdicts-history", "soc-metrics"], "privileges": ["read"]}]}}}' \
    | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["encoded"])')
  set_env ES_LEARNING_WRITER_API_KEY "$enc"; unset enc
  ok "ES_LEARNING_WRITER_API_KEY adaugata"
fi
# KIBANA_ALERT_TAGS_API_KEY: doar API-ul Kibana de etichete pe alerte (POST
# /api/detection_engine/signals/tags). Privilegiul de functie al Security Solution se ia din
# GET /api/features al versiunii instalate (id-ul difera intre versiuni: siem, siemV2, ...).
# Kibana actualizeaza etichetele cu drepturile cheii, deci cheia are write pe indexul de alerte
# al spatiului default; codul SOC-ului o foloseste DOAR prin API-ul de etichete (ops/kibana_tags.py).
if has_env KIBANA_ALERT_TAGS_API_KEY; then
  ok "KIBANA_ALERT_TAGS_API_KEY exista in soc.env, neatinsa"
else
  feat=$(curl -sf "${AUTH[@]}" "$KB/api/features" | "$PY" -c '
import json, re, sys
ids = [f["id"] for f in json.load(sys.stdin) if re.fullmatch(r"siem(V\d+)?", f.get("id", ""))]
ids.sort(key=lambda i: int(i[5:] or 1))
print(ids[-1] if ids else "")')
  [ -n "$feat" ] || die "nu gasesc functia Security Solution in /api/features"
  enc=$(curl -sf "${AUTH[@]}" -X POST "$ES/_security/api_key" -H 'Content-Type: application/json' -d '{
    "name": "soc-alert-tags", "role_descriptors": {"tags": {
      "indices": [{"names": [".alerts-security.alerts-default", ".internal.alerts-security.alerts-default-*"],
                   "privileges": ["read", "write", "view_index_metadata", "maintenance"]}],
      "applications": [{"application": "kibana-.kibana", "privileges": ["feature_'"$feat"'.all"],
                        "resources": ["space:default"]}]}}}' \
    | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["encoded"])')
  set_env KIBANA_ALERT_TAGS_API_KEY "$enc"; unset enc
  ok "KIBANA_ALERT_TAGS_API_KEY adaugata (functia $feat)"
fi
# Verificari de drept minim (coduri HTTP asteptate, fara continut).
LK=$(grep '^ES_LEARNING_WRITER_API_KEY=' "$ENVF" | cut -d= -f2-)
printf '   cheia de invatare: citire soc-buckets (asteptat 200): %s\n' \
  "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: ApiKey $LK" "$ES/soc-buckets/_count")"
printf '   cheia de invatare: scriere verdicts-history (asteptat 403): %s\n' \
  "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: ApiKey $LK" -X POST "$ES/verdicts-history/_doc" \
     -H 'Content-Type: application/json' -d '{"probe": true}')"
unset LK

# ---------------------------------------------------------------------------------------------
say "4. Setarile noi in soc.env (L1: in soc.env, nu in ExecStart)"
# Cascada porneste in UMBRA: calculeaza si inregistreaza, nu inchide nimic. T1_CASCADE=off = oprire.
set_env T1_CASCADE shadow;            ok "T1_CASCADE=shadow"
# Magistrala in proces (implicita); RabbitMQ ramane dezactivat.
set_env SOC_BUS inprocess;            ok "SOC_BUS=inprocess"
# Oprirea de urgenta fara repornire: `touch data/cascade-off` -> off de la urmatorul ciclu.
set_env CASCADE_KILL_FILE "$ROOT/data/cascade-off"; ok "CASCADE_KILL_FILE=data/cascade-off"
set_env SOC_MODELS_DIR "$ROOT/data/models";         ok "SOC_MODELS_DIR=data/models"

# ---------------------------------------------------------------------------------------------
say "5. Registrul modelelor"
install -d -m 750 "$ROOT/data/models" && ok "data/models (750)"

# ---------------------------------------------------------------------------------------------
say "6. Unitatile systemd noi (cer sudo)"
for u in soc-learn soc-learn-guard soc-learn-gold; do
  for ext in service timer; do
    # install e idempotent: acelasi continut -> acelasi fisier.
    sudo install -m 644 "deploy/$u.$ext" "/etc/systemd/system/$u.$ext"
  done
done
sudo systemctl daemon-reload
sudo systemctl enable --now soc-learn.timer soc-learn-guard.timer soc-learn-gold.timer
ok "timere: $(systemctl list-timers --no-pager 'soc-learn*' | grep -c soc-learn) active"

# ---------------------------------------------------------------------------------------------
say "7. Repornirea orchestratorului (citeste soc.env; ExecStart neatins)"
sudo systemctl restart soc-orchestrator
sleep 20
systemctl is-active --quiet soc-orchestrator || die "soc-orchestrator nu ruleaza dupa repornire"
have2=$(systemctl cat soc-orchestrator | grep '^ExecStart=')
[ "$have2" = "$want" ] || die "ExecStart s-a schimbat (nu ar trebui)"
ok "soc-orchestrator activ; ExecStart identic; SHADOW_MODE fortat"
# O rulare uscata a buclei de invatare (fara --scrie): arata etichetele si conditiile de activare.
( set -a; . "$ENVF"; set +a; SHADOW_MODE=true "$PY" tier3.py --once --invatare --iesire data/tier3 ) \
  | tail -3 || true

say "Gata. Cascada ruleaza in UMBRA. Urmatorii pasi ai omului:"
cat <<'EOT'
   - (optional) mai multi oameni in interfata: `python3 label_ui.py --hash-parola NUME`, apoi
     LABEL_UI_USERS="nume:sare:hash,..." in soc.env si repornirea label_ui;
   - eticheteaza grupuri: http://LABEL_UI_HOST:8088/buckets (repornit label_ui pe ramura fazei);
   - oprire imediata: `touch ~/lab/data/cascade-off` (sau T1_CASCADE=off + restart);
   - revenire la un model anterior: `python3 tier3.py --once --model-revenire PIPELINE HASH`;
   - modul `on` (inchideri reale pe pipeline-urile pe care controlorul le activeaza) se pune DOAR de
     om, dupa ce soc-metrics type=cascade_metrics arata "blockers": [] pentru un pipeline:
     T1_CASCADE=on in soc.env + `sudo systemctl restart soc-orchestrator`.
EOT

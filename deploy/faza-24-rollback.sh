#!/usr/bin/env bash
# =================================================================================================
# Faza 24 — REVENIREA, pentru OM, pe es-node-1, din ~/lab. Idempotenta (a doua rulare nu mai
# schimba nimic). Inversul lui deploy/faza-24-apply.sh, fara stergeri ireversibile:
#
#   1. oprirea imediata a cascadei: data/cascade-off + T1_CASCADE=off in soc.env;
#   2. oprirea si scoaterea unitatilor soc-learn* (unitatile existente nu se ating);
#   3. invalidarea celor doua chei create de faza (soc-learning-writer, soc-alert-tags) si scoaterea
#      lor din soc.env (valorile nu se afiseaza);
#   4. repornirea orchestratorului (ExecStart neatins) si verificarea ca ruleaza.
#
# Ce NU face: nu sterge indicii soc-buckets / soc-learning-audit si nici data/models (etichetele
# omului si istoricul modelelor raman; stergerea, daca se vrea, e o comanda separata, manuala:
#   curl -u elastic -X DELETE localhost:9200/soc-buckets   # IREVERSIBIL — doar daca esti sigur).
# Dupa revenire, codul de pe ramura cu T1_CASCADE=off produce verdictele de dinainte (L5); pentru
# codul vechi: `git checkout <ramura anterioara>` in ~/lab si restartul orchestratorului.
# =================================================================================================
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
ES="${ES_URL_ADMIN:-http://localhost:9200}"
ENVF="$ROOT/soc.env"
PY="$ROOT/venv/bin/python"
say() { printf '\n== %s\n' "$*"; }
ok()  { printf '   OK  %s\n' "$*"; }

# del_env CHEIE: scoate linia CHEIE=... din soc.env (fara afisare). Idempotent.
del_env() {
  "$PY" - "$ENVF" "$1" <<'PYEOF'
import os, sys
path, key = sys.argv[1], sys.argv[2]
if not os.path.exists(path):
    sys.exit(0)
lines = open(path, encoding="utf-8").read().splitlines()
keep = [l for l in lines if l.split("=", 1)[0].strip() != key]
if keep != lines:
    tmp = path + ".tmp"
    open(tmp, "w", encoding="utf-8").write("\n".join(keep) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
PYEOF
}

say "1. Oprirea cascadei"
# Fisierul de oprire are efect de la urmatorul ciclu, chiar fara repornire.
install -d -m 750 "$ROOT/data" && touch "$ROOT/data/cascade-off" && ok "data/cascade-off"
del_env T1_CASCADE && printf 'T1_CASCADE=off\n' >> "$ENVF" && chmod 600 "$ENVF" && ok "T1_CASCADE=off"
del_env SOC_BUS && ok "SOC_BUS scos (implicit: in proces)"

say "2. Unitatile soc-learn*"
for u in soc-learn soc-learn-guard soc-learn-gold; do
  # disable --now pe o unitate inexistenta nu e eroare de oprire (|| true).
  sudo systemctl disable --now "$u.timer" 2>/dev/null || true
  sudo rm -f "/etc/systemd/system/$u.timer" "/etc/systemd/system/$u.service"
done
sudo systemctl daemon-reload
ok "soc-learn* oprite si scoase"

say "3. Cheile fazei"
PW=$(grep -E '^ELASTIC_PASSWORD=' "$ROOT/.env" | head -1 | cut -d= -f2- | tr -d '"'"'"'')
if [ -n "$PW" ]; then
  for name in soc-learning-writer soc-alert-tags; do
    # Invalidarea dupa nume e idempotenta (a doua oara: 0 chei invalidate).
    n=$(curl -sf -u "elastic:$PW" -X DELETE "$ES/_security/api_key" -H 'Content-Type: application/json' \
          -d "{\"name\": \"$name\"}" | "$PY" -c 'import json,sys; print(len(json.load(sys.stdin).get("invalidated_api_keys", [])))' || echo "?")
    ok "cheia $name: $n invalidate"
  done
else
  echo "   ATENTIE: ELASTIC_PASSWORD lipsa in .env; cheile nu au fost invalidate (fa-o manual)"
fi
del_env ES_LEARNING_WRITER_API_KEY && del_env KIBANA_ALERT_TAGS_API_KEY && ok "cheile scoase din soc.env"

say "4. Repornirea orchestratorului"
sudo systemctl restart soc-orchestrator
sleep 20
systemctl is-active --quiet soc-orchestrator && ok "soc-orchestrator activ" \
  || { echo "   EROARE: soc-orchestrator nu ruleaza" >&2; exit 1; }
systemctl cat soc-orchestrator | grep -q '^ExecStart=/usr/bin/env SHADOW_MODE=true ' && ok "SHADOW_MODE fortat in ExecStart"
say "Gata: cascada oprita, bucla de invatare oprita, etichetele si modelele pastrate."

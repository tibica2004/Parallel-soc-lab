#!/usr/bin/env bash
# POARTA DE REGRESIE, fara make (nu e instalat pe es-node-1). O ruleaza OMUL, in tmux, pe es-node-1.
# Inainte: benign-gen oprit de cel putin 5 minute, regula TCP 80 de la 172.30.6.133 scoasa din
# victim-sg, fara OpenClaw. Scriptul nu poate verifica asta singur; intreaba si asteapta "da".
#
#   deploy/poarta.sh --verifica                    # doar verifica mediul si importurile, nu ruleaza nimic
#   deploy/poarta.sh fast dev validation injection suita   # poarta completa (ordinea din B1)
#   deploy/poarta.sh dev validation injection      # poarta pentru o schimbare pe Tier 2
#
# Merge si dintr-un worktree al altei ramuri (ex. ~/lab-faza23): secretele se INCARCA din
# $SOC_LAB (implicit ~/lab), nu se copiaza; data/, soc/ si .env se leaga simbolic (sunt in .gitignore).
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
REPO=$PWD
SOC_LAB=${SOC_LAB:-$HOME/lab}
PY=$SOC_LAB/venv/bin/python
[ -x "$PY" ] || { echo "lipseste $PY" >&2; exit 2; }
for f in soc.env env.sh; do [ -r "$SOC_LAB/$f" ] || { echo "lipseste $SOC_LAB/$f" >&2; exit 2; }; done
if [ "$REPO" != "$(readlink -f "$SOC_LAB")" ]; then
    for d in data soc .env; do
        [ -e "$REPO/$d" ] || { [ -e "$SOC_LAB/$d" ] && ln -s "$SOC_LAB/$d" "$REPO/$d"; }
    done
fi
set -a; . "$SOC_LAB/soc.env"; set +a
# shellcheck disable=SC1091
source "$SOC_LAB/env.sh" >/dev/null 2>&1
mkdir -p results
COMMIT=$(git rev-parse --short HEAD)

if [ "${1:-}" = "--verifica" ]; then
    "$PY" -c "import harness, hunt_path, fast_path, prompt_injection, prompts; print(\"importuri ok; prompt_set\", prompts.prompt_set(prompts.current()))"
    for s in scenarios_fast.yml scenarios.yml scenarios_validation.yml scenarios_injection.yml; do
        [ -r "$s" ] && echo "ok $s" || { echo "LIPSESTE $s"; exit 2; }
    done
    echo "cod: $REPO @ $COMMIT; date: $(readlink -f data 2>/dev/null || echo "LIPSESTE data/")"
    exit 0
fi

[ $# -gt 0 ] || { echo "ce seturi? (fast dev validation injection suita)" >&2; exit 2; }
declare -A FILES=([fast]=scenarios_fast.yml [dev]=scenarios.yml [validation]=scenarios_validation.yml [injection]=scenarios_injection.yml)
for s in "$@"; do [ "$s" = suita ] || [ -n "${FILES[$s]:-}" ] || { echo "set necunoscut: $s" >&2; exit 2; }; done

echo "Cod: $REPO @ $COMMIT. Seturi: $*"
read -r -p "benign-gen e oprit de >= 5 minute, regula 80 de la atacator e scoasa, OpenClaw nu ruleaza? (da) " ok
[ "$ok" = "da" ] || { echo "nimic rulat"; exit 1; }

TS=$(date -u +%F-%H%M)
for s in "$@"; do
    if [ "$s" = suita ]; then
        "$PY" -u prompt_injection.py 2>&1 | tee "results/poarta-$COMMIT-injection48-$TS.txt"
    else
        SCENARIOS=${FILES[$s]} VERBOSE=1 "$PY" -u harness.py 2>&1 | tee "results/poarta-$COMMIT-$s-$TS.txt"
    fi
done
echo GATA > "results/poarta-$COMMIT-gata-$TS"
echo "GATA: results/poarta-$COMMIT-*-$TS.txt. Acum: regula 80 la loc si benign-gen pornit."

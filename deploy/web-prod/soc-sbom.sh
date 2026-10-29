#!/usr/bin/env bash
# COLECTOR SBOM (pas 1) — ruleaza PE web-prod, ca user neprivilegiat soc-sbom.
#
# Aduna componentele instalate (Apache, PHP, WordPress core, plugin-uri, teme, module
# Apache, extensii PHP) + SHA256 pe fisierul principal al fiecarui plugin (pentru a
# detecta modificari intre rulari). Scrie O SINGURA linie NDJSON in /var/log/soc/sbom.ndjson.
#
# R16/G4: NU scrie in Elasticsearch si NU face niciun request de retea. Linia NDJSON e
# preluata de integrarea Fleet "Custom Logs" (dataset soc.sbom) -> logs-soc.sbom-*.
# nday_watch.py (pe es-node-1) o citeste de acolo.
#
# Numele componentelor vin din sistemul de fisiere (date, nu instructiuni): serializarea
# JSON o face python3 (json.dumps), nu concatenare de siruri, ca sa nu se poata produce
# NDJSON invalid dintr-un nume cu caractere speciale.
set -euo pipefail

WEBROOT="${SBOM_WEBROOT:-/var/www/html}"
OUT="${SBOM_OUT:-/var/log/soc/sbom.ndjson}"
HOST="$(hostname)"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Fiecare componenta ca o linie TSV: tip <TAB> nume <TAB> versiune <TAB> sha256(optional).
# TAB-ul evita ambiguitatile; valorile nu contin tab-uri.
emit() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-}"; }

# Primul header "Version:" dintr-un fisier (plugin .php sau style.css al temei).
hdr_version() { grep -m1 -ioP '^[[:space:]]*Version:[[:space:]]*\K[0-9][0-9A-Za-z._\-]*' "$1" 2>/dev/null || true; }

collect() {
    local v
    v="$(apache2 -v 2>/dev/null | grep -oP 'Apache/\K[0-9.]+' || true)"
    [ -n "$v" ] && emit apache apache "$v"

    v="$(php -r 'echo PHP_VERSION;' 2>/dev/null || true)"
    [ -n "$v" ] && emit php php "$v"

    v="$(grep -oP "\\\$wp_version = '\K[^']+" "$WEBROOT/wp-includes/version.php" 2>/dev/null || true)"
    [ -n "$v" ] && emit wp_core wordpress "$v"

    local d f slug ver main sha
    for d in "$WEBROOT"/wp-content/plugins/*/; do
        [ -d "$d" ] || continue
        slug="$(basename "$d")"
        ver=""; main=""
        for f in "$d"*.php; do
            [ -f "$f" ] || continue
            ver="$(hdr_version "$f")"
            if [ -n "$ver" ]; then main="$f"; break; fi
        done
        [ -n "$ver" ] || continue
        sha="$(sha256sum "$main" 2>/dev/null | awk '{print $1}' || true)"
        emit plugin "$slug" "$ver" "$sha"
    done

    for d in "$WEBROOT"/wp-content/themes/*/; do
        [ -d "$d" ] || continue
        slug="$(basename "$d")"
        ver="$(hdr_version "$d/style.css")"
        [ -n "$ver" ] || continue
        emit theme "$slug" "$ver"
    done

    # Module Apache; fallback (A12) daca apache2ctl -M nu merge ca neprivilegiat.
    local mods
    mods="$(apache2ctl -M 2>/dev/null | awk '{print $1}' | sed 's/_module$//' || true)"
    if [ -z "$mods" ]; then
        mods="$(ls /etc/apache2/mods-enabled/*.load 2>/dev/null | xargs -r -n1 basename | sed 's/\.load$//' || true)"
    fi
    local m
    for m in $mods; do emit apache_module "$m" ""; done

    local e
    for e in $(php -m 2>/dev/null | grep -vE '^\[|^$' || true); do emit php_ext "$e" ""; done
}

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
collect > "$TMP"

# Scriptul python vine din heredoc-ul de pe stdin, deci TSV-ul se da ca ARGUMENT
# (fisier), nu pe stdin: altfel `< "$TMP"` ar fi suprascris de `<<'PY'`.
python3 - "$HOST" "$TS" "$TMP" >> "$OUT" <<'PY'
import sys, json
host, ts, src = sys.argv[1], sys.argv[2], sys.argv[3]
comps = []
with open(src, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        p = line.rstrip("\n").split("\t")
        if len(p) < 3 or not p[1]:
            continue
        c = {"type": p[0], "name": p[1], "version": p[2]}
        if len(p) > 3 and p[3]:
            c["sha256"] = p[3]
        comps.append(c)
print(json.dumps({"host": host, "ts": ts, "components": comps}, ensure_ascii=False,
                 separators=(",", ":")))
PY

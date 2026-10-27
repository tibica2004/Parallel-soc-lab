#!/usr/bin/env bash
# gen_sbom.sh — colecteaza SBOM-ul de pe web-prod. EXCLUSIV read-only.
# Ruleaza ca user soc-reader (NU root). Singurul output: /tmp/sbom.json.
# Nu modifica nimic pe host. Livrat pentru revizie; se copiaza pe web-prod
# doar dupa CONFIRM PASUL 1.
set -euo pipefail

WEBROOT="${WEBROOT:-/var/www/html}"
OUT="${OUT:-/tmp/sbom.json}"

if [ "$(id -u)" -eq 0 ]; then
  echo "refuz sa rulez ca root (ruleaza ca soc-reader)" >&2
  exit 1
fi

# Serializarea o face python3 ca sa nu improvizez escaping JSON in bash.
# Preferam parsarea din fisiere (fara DB, fara credentiale) pentru plugin/theme;
# wp-cli e folosit doar daca exista si raspunde fara eroare.
python3 - "$WEBROOT" "$OUT" <<'PY'
import json, subprocess, sys, shutil, os, re, socket
from datetime import datetime, timezone

webroot, out = sys.argv[1], sys.argv[2]
host = socket.gethostname()
now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
comps = []

def run(cmd, timeout=60):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""

def add(t, name, version, active=True):
    name = (name or "").strip()
    if name:
        comps.append({"type": t, "name": name,
                      "version": (version or "").strip() or "unknown",
                      "active": bool(active)})

# --- apache ---
m = re.search(r"Apache/(\S+)", run(["apache2", "-v"]))
add("apache", "apache2", m.group(1) if m else "unknown")

# --- php ---
m = re.search(r"PHP (\S+)", run(["php", "-v"]))
add("php", "php", m.group(1) if m else "unknown")
for line in run(["php", "-m"]).splitlines():
    line = line.strip()
    if line and not line.startswith("["):
        add("php-module", line, "bundled")

# --- wordpress core (din versiune fisier, fara DB) ---
ver_file = os.path.join(webroot, "wp-includes", "version.php")
wp_core = "unknown"
try:
    txt = open(ver_file, encoding="utf-8", errors="replace").read()
    mm = re.search(r"\$wp_version\s*=\s*'([^']+)'", txt)
    if mm:
        wp_core = mm.group(1)
except Exception:
    pass
add("wp-core", "wordpress", wp_core)

# --- plugins/teme: parsare header din fisiere (nu cere DB/credentiale) ---
def parse_header(path, field):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            head = f.read(8192)
        mm = re.search(rf"{field}\s*:\s*(.+)", head)
        return mm.group(1).strip() if mm else ""
    except Exception:
        return ""

def scan(subdir, main_glob, ctype):
    base = os.path.join(webroot, "wp-content", subdir)
    if not os.path.isdir(base):
        return
    for entry in sorted(os.listdir(base)):
        d = os.path.join(base, entry)
        if not os.path.isdir(d):
            continue
        # plugin: orice .php cu header; tema: style.css
        cand = []
        if ctype == "wp-theme":
            cand = [os.path.join(d, "style.css")]
        else:
            cand = [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".php")]
        name = entry
        version = ""
        for c in cand:
            if not os.path.isfile(c):
                continue
            nm = parse_header(c, "Plugin Name") or parse_header(c, "Theme Name")
            vr = parse_header(c, "Version")
            if vr:
                name = nm or entry
                version = vr
                break
        add(ctype, name, version or "unknown", active=True)

scan("plugins", "*.php", "wp-plugin")
scan("themes", "style.css", "wp-theme")

# wp-cli, optional, doar daca merge (completeaza statusul activ real)
wp = shutil.which("wp")
if wp:
    try:
        out_pl = run([wp, "plugin", "list", "--format=json", "--path=" + webroot], timeout=30)
        active = {it.get("name") for it in json.loads(out_pl or "[]") if it.get("status") == "active"}
        for c in comps:
            if c["type"] == "wp-plugin":
                c["active"] = c["name"] in active or c["name"].lower() in active
    except Exception:
        pass

# --- pachete debian relevante ---
for line in run(["dpkg", "-l"]).splitlines():
    parts = line.split()
    if len(parts) >= 3 and parts[0] in ("ii", "hi") and \
       re.search(r"apache2|^php|libssl|openssh|mariadb|mysql", parts[1]):
        add("deb", parts[1], parts[2])

doc = {"host": host, "generated_at": now, "components": comps}
with open(out, "w") as f:
    json.dump(doc, f, indent=2)
print(f"SBOM: {len(comps)} componente -> {out}")
PY

# Pasul 1 — SBOM + N-day watch (ramura faza-22-nday)

Doua bucati:
- 1.A SBOM agent (aici, gata): soc-sbom.sh pe web-prod -> NDJSON -> Fleet Custom Logs
  -> logs-soc.sbom-*. Fara chei ES, fara retea pe web-prod (R16/G4).
- 1.B nday_watch.py (urmeaza): pe es-node-1, citeste logs-soc.sbom-*, interogheaza
  OSV/NVD (apache/php/core) + WPScan (plugin-uri), scrie asset-vulns + hunt/patch_request.

Corectii aplicate: A1 (dataset soc.sbom -> logs-soc.sbom-*, NU asset-inventory),
A12 (fallback mods-enabled daca apache2ctl -M pica neprivilegiat).

## 1.A SBOM agent (web-prod)

### A. Fisiere (noi, in deploy/web-prod/)
- soc-sbom.sh -> /usr/local/bin/soc-sbom.sh (owner root, 755, rulat ca soc-sbom):
  Apache (apache2 -v), PHP (PHP_VERSION), WP core (version.php), plugin-uri (header
  Version din *.php din radacina pluginului + SHA256 pe fisierul principal), teme
  (Version din style.css), module Apache (apache2ctl -M, fallback mods-enabled),
  extensii PHP (php -m). O singura linie NDJSON in /var/log/soc/sbom.ndjson. Serializare
  prin python3 json.dumps (numele din FS = date; fara concatenare de siruri).
  NU scrie in ES, NU face retea.
- soc-sbom.service: Type=oneshot, User=soc-sbom, ProtectSystem=strict,
  ReadWritePaths=/var/log/soc, NoNewPrivileges, PrivateTmp.
- soc-sbom.timer: OnCalendar=*-*-* 03:00:00, Persistent.
- soc-sbom.logrotate -> /etc/logrotate.d/soc-sbom: daily, rotate 14, compress,
  create 0640 soc-sbom adm.

Testat local (fake webroot): o linie NDJSON valida, components = core + plugin-uri
(cu sha256) + tema; bash -n OK.

### B. Comenzi
Prerequisit de om pe web-prod (root, o singura data):
  sudo useradd --system --shell /usr/sbin/nologin --home /nonexistent soc-sbom
  sudo mkdir -p /var/log/soc && sudo chown soc-sbom:adm /var/log/soc && sudo chmod 750 /var/log/soc
  sudo setfacl -R -m u:soc-sbom:rX /var/www/html
  sudo setfacl -R -d -m u:soc-sbom:rX /var/www/html   # fisierele noi mostenesc rX
Deploy:
  scp deploy/web-prod/soc-sbom.sh deploy/web-prod/soc-sbom.service deploy/web-prod/soc-sbom.timer deploy/web-prod/soc-sbom.logrotate tiberiu@172.30.6.249:/tmp/
  ssh -t tiberiu@172.30.6.249 '
    sudo install -o root -g root -m 755 /tmp/soc-sbom.sh /usr/local/bin/soc-sbom.sh &&
    sudo install -m 644 /tmp/soc-sbom.service /etc/systemd/system/soc-sbom.service &&
    sudo install -m 644 /tmp/soc-sbom.timer   /etc/systemd/system/soc-sbom.timer &&
    sudo install -m 644 /tmp/soc-sbom.logrotate /etc/logrotate.d/soc-sbom &&
    sudo systemctl daemon-reload &&
    sudo systemctl enable --now soc-sbom.timer &&
    sudo systemctl start soc-sbom.service &&
    rm -f /tmp/soc-sbom.*'
Fleet (om, in Kibana -> Fleet -> policy web-prod -> Add integration "Custom Logs"):
  - Log file path: /var/log/soc/sbom.ndjson
  - Dataset name: soc.sbom
  - Custom configurations (procesor): decode_json_fields pe message, target "", add_error_key.
  Rezultat: data stream logs-soc.sbom-default.

### C. Verificare
Pe web-prod (rulare ca soc-sbom + linie valida cu > 10 componente):
  ssh tiberiu@172.30.6.249 'sudo -u soc-sbom /usr/local/bin/soc-sbom.sh; tail -1 /var/log/soc/sbom.ndjson | jq ".components | length"'  -> numar > 10
In ES (de pe es-node-1), dupa ce Fleet a preluat linia:
  ssh tiberiu@172.30.6.106 'cd ~/lab && source env.sh && curl -s -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/logs-soc.sbom-*/_search?sort=@timestamp:desc&size=1" -H "Content-Type: application/json" -d "{\"_source\":[\"@timestamp\",\"components\",\"host\"]}" | jq ".hits.hits[0]._source.components | length"' -> > 10
  journalctl -u soc-sbom -> exit 0.

### D. Metrica
components_total (din ultima linie SBOM). Acceptare: timer soc-sbom ruleaza cu exit 0;
linie NDJSON valida cu > 10 componente; logs-soc.sbom-* primeste documente (dataset
soc.sbom). Metrica formala (soc-metrics) vine la 1c.

### E. Rollback
  ssh -t tiberiu@172.30.6.249 'sudo systemctl disable --now soc-sbom.timer; sudo rm -f /etc/systemd/system/soc-sbom.{service,timer} /usr/local/bin/soc-sbom.sh /etc/logrotate.d/soc-sbom; sudo systemctl daemon-reload; sudo setfacl -R -x u:soc-sbom /var/www/html; sudo setfacl -R -d -x u:soc-sbom /var/www/html; sudo userdel soc-sbom'
  (/var/log/soc il lasi; il sterge separat daca vrei: sudo rm -r /var/log/soc)
  Fleet: scoate integrarea "Custom Logs" (soc.sbom) din policy.

## 1.B nday_watch.py — URMEAZA (chunk 2)

nday_watch.py pe es-node-1: load_latest_sbom din logs-soc.sbom-*; OSV querybatch +
NVD (CPE) doar apache/php/wordpress core; WPScan (cache 24h) + Wordfence feed pentru
plugin-uri/teme (A2); VulnRecord Pydantic (extra=forbid); _id fix = sha256(host+cve+comp);
upsert idempotent; hunt_request (cvss>=7 sau patch_available) + patch_request (B2) in
soc-incidents; BENIGN_GEN_IPS in soc.env (G3). Reutilizeaza exposure.parse_version/in_range.
Prerequisite de om: index asset-vulns (mapping 1.4), chei ES_VULNS_WRITER + ES_INCIDENTS_WRITER,
WPSCAN_API_KEY. Se livreaza dupa ce SBOM-ul curge in logs-soc.sbom-*.

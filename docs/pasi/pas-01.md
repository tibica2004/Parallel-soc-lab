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
Prerequisit pe web-prod (root, o singura data) — APLICAT 2026-10-29:
  sudo useradd --system --shell /usr/sbin/nologin --home /nonexistent soc-sbom
  sudo mkdir -p /var/log/soc && sudo chown soc-sbom:adm /var/log/soc && sudo chmod 750 /var/log/soc
  # ACL NU e necesar: /var/www/html e deja world-readable (drwxr-xr-x www-data), soc-sbom
  # citeste version.php/plugin *.php/style.css, iar wp-config.php ramane 640 (denied). Daca
  # pe viitor se restrang drepturile webroot-ului, adauga ACL atunci (pachetul acl + setfacl
  # -R -m u:soc-sbom:rX /var/www/html), NU adauga soc-sbom in grupul www-data (ar vedea wp-config).
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
  ssh tiberiu@172.30.6.249 'sudo systemctl disable --now soc-sbom.timer; sudo rm -f /etc/systemd/system/soc-sbom.{service,timer} /usr/local/bin/soc-sbom.sh /etc/logrotate.d/soc-sbom; sudo systemctl daemon-reload; sudo userdel soc-sbom'
  (fara setfacl: n-am aplicat ACL. /var/log/soc il lasi; sudo rm -r /var/log/soc daca vrei)
  (/var/log/soc il lasi; il sterge separat daca vrei: sudo rm -r /var/log/soc)
  Fleet: scoate integrarea "Custom Logs" (soc.sbom) din policy.

## 1.B nday_watch.py (es-node-1)

nday_watch.py: load_latest_sbom din logs-soc.sbom-* (A1); OSV querybatch + NVD (CPE)
DOAR apache/php/wordpress core (A2); WPScan (cache local 24h) pentru plugin-uri/teme,
slug necunoscut -> needs_review, NU se arunca (A2); VulnRecord Pydantic (extra=forbid,
fara exploit/poc/payload — E2); _id fix = sha256(host+cve+component) -> upsert idempotent;
hunt_request (cvss>=7 sau patch_available) + patch_request (B2) in soc-incidents.
Reutilizeaza exposure.parse_version/in_range. Retea DOAR de pe es-node-1, catre baze
publice (R16/G4). Niciun model implicat (cod pur de corelatie).

### A. Fisiere
- nday_watch.py (nou, radacina ~/lab): modulul descris mai sus. Functii pure separate
  de I/O (testabile fara retea/ES): cvss_to_severity, vuln_id, to_cpe, to_purl,
  osv_affects, is_update_available, build_core_records, build_plugin_records.
- tests/test_nday_watch.py (nou): 13 teste pe functiile pure. Verifica: praguri cvss,
  _id idempotent (case-insensitive), CPE/purl doar pentru core, potrivirea de interval
  OSV (inclusiv versiune neparsabila/tip de range necunoscut -> needs_review), E2
  (exploit/poc/payload respinse de extra=forbid), severitate/tip invalide respinse.
- deploy/soc-nday.service (nou): oneshot, User=tiberiu, WorkingDirectory ~/lab,
  EnvironmentFile soc.env, ExecStart venv/bin/python nday_watch.py, TimeoutStartSec=20min.
- deploy/soc-nday.timer (nou): OnCalendar=*-*-* 04:00:00 (dupa SBOM-ul de la 03:00),
  RandomizedDelaySec=5min, Persistent.

Verificat local: `python -m pytest tests/test_nday_watch.py` -> 13/13; import OK cu
NDAY_OFFLINE=1 (fara retea). Nimic nu s-a atins pe hosturi.

### B. Comenzi (de om; OK per comanda)

> Constatari verificate 2026-10-29 (sesiunea pe boxa veche):
> - SBOM OK: logs-soc.sbom-default primeste documente (ultimul = 77 componente; core
>   intact: apache 2.4.58, php 8.3.6, wp_core/wordpress 7.1.3).
> - **ES_API_KEY (read-only) are `read:false` pe asset-vulns SI pe soc-incidents**
>   (confirmat cu _has_privileges; `read:true` doar pe logs-soc.sbom-* si verdicts-history).
>   Deci verificarile din §C care folosesc $ES_API_KEY pe aceste doua indici dau 403, iar
>   tier3/dashboards nu pot citi hunt_request din soc-incidents cu acea cheie. -> Prerequisit 0.
> - Cheile de scriere trebuie puse in **/home/tiberiu/lab/soc.env** (EnvironmentFile al
>   soc-nday.service), NU in env.sh. env.sh e pentru rulari manuale si nu are cheile de
>   scriere; prima rulare se face prin systemd (vezi mai jos).

Prerequisit 0 — largeste rolul cheii read-only (ES_API_KEY) sa citeasca si indicii noi
(altfel §C da 403 si tier3 nu vede hunturile). In Dev Tools, cu contul elastic, adauga
`asset-vulns` si `soc-incidents` la privilegiile de `read` ale rolului folosit de
ES_API_KEY (sau emite o cheie read-only noua care include si aceste pattern-uri):
```
POST /_security/api_key {"name":"soc-reader","role_descriptors":{"r":{"indices":[
  {"names":["logs-*",".alerts-security.alerts-*","verdicts-history","soc-audit",
            "soc-incidents","soc-metrics","asset-vulns","asset-inventory"],
   "privileges":["read","view_index_metadata"]}]}}}
```

Prerequisit 1 — indexul asset-vulns (creat cu contul tau, nu din cod; mapping 1.4 +
needs_review). De pe es-node-1, cu credentialul tau privilegiat:
```
curl -s -X PUT "$ES_URL/asset-vulns" -H "Content-Type: application/json" -d '{
  "mappings": {"properties": {
    "cve":{"type":"keyword"}, "component_type":{"type":"keyword"},
    "component_name":{"type":"keyword"}, "installed_version":{"type":"keyword"},
    "fixed_version":{"type":"keyword"}, "cvss":{"type":"float"},
    "severity":{"type":"keyword"}, "patch_available":{"type":"boolean"},
    "first_seen":{"type":"date"}, "last_seen":{"type":"date"},
    "resolved":{"type":"boolean"}, "resolved_at":{"type":"date"},
    "source":{"type":"keyword"}, "summary":{"type":"text"},
    "references":{"type":"keyword"}, "host":{"type":"keyword"},
    "hunt_requested":{"type":"boolean"}, "needs_review":{"type":"boolean"}
  }}
}'
```

Prerequisit 2 — chei API cu drept minim (fara delete, fara manage; 1.5/R8). Creeaza-le
cu contul tau si pune valorile in soc.env pe es-node-1 (NU in repo, NU pe web-prod):
```
# ES_VULNS_WRITER_API_KEY
POST /_security/api_key {"name":"soc-vulns-writer","role_descriptors":{"w":{
  "indices":[{"names":["asset-vulns"],
    "privileges":["create_doc","index","read","view_index_metadata"]}]}}}
# ES_INCIDENTS_WRITER_API_KEY
POST /_security/api_key {"name":"soc-incidents-writer","role_descriptors":{"w":{
  "indices":[{"names":["soc-incidents"],"privileges":["create_doc","index"]}]}}}
# ES_METRICS_WRITER_API_KEY  (indexul soc-metrics se face la 1c; cheia acum, optionala)
POST /_security/api_key {"name":"soc-metrics-writer","role_descriptors":{"w":{
  "indices":[{"names":["soc-metrics"],"privileges":["create_doc","index"]}]}}}
```
In **/home/tiberiu/lab/soc.env** (es-node-1, chmod 600): adauga valoarea `encoded` din
raspunsul fiecarui `POST /_security/api_key` (acela e valoarea headerului `ApiKey`, nu
perechea `id:api_key`), cate una pe linie:
```
ES_VULNS_WRITER_API_KEY=<encoded>
ES_INCIDENTS_WRITER_API_KEY=<encoded>
ES_METRICS_WRITER_API_KEY=<encoded>
# optional:
NVD_API_KEY=<...>
WPSCAN_API_KEY=<...>
```
Fara WPSCAN_API_KEY, toate pluginurile ies needs_review (corect, nu fals-negativ).
nday_watch face hard-fail (exit 1) daca lipseste ES_VULNS/INCIDENTS_WRITER_API_KEY — NU
mai cade tacut pe ES_API_KEY (ar primi 403 si ar scrie in gol). ES_METRICS lipsa =
metricile se sar, rularea continua.

Prerequisit 3 — soc-incidents trebuie sa existe (il folosesc si alte bucati). Daca nu:
`curl -X PUT "$ES_URL/soc-incidents"` (mapping dinamic e suficient aici).

Deploy (es-node-1):
```
sudo cp deploy/soc-nday.service /etc/systemd/system/soc-nday.service
sudo cp deploy/soc-nday.timer   /etc/systemd/system/soc-nday.timer
sudo systemctl daemon-reload
sudo systemctl enable --now soc-nday.timer
```
Prima rulare (dupa ce logs-soc.sbom-* are cel putin un document de la 1.A). Prin systemd,
ca sa se incarce EnvironmentFile=soc.env (cheile de scriere) — rularea `source env.sh`
NU are cheile de scriere:
```
sudo systemctl start soc-nday.service
journalctl -u soc-nday.service -n 30 --no-pager   # "nday gata: {...}", exit 0
```
(Varianta manuala echivalenta, daca vrei fara systemd:
`cd ~/lab && set -a && . ./soc.env && . ./env.sh && set +a && ./venv/bin/python nday_watch.py`)

### C. Verificare
Interogarile pe asset-vulns/soc-incidents cu $ES_API_KEY merg DOAR dupa Prerequisit 0
(largirea rolului read-only). Pana atunci, pentru asset-vulns poti folosi cheia de scriere
(are `read`): `-H "Authorization: ApiKey $ES_VULNS_WRITER_API_KEY"`.
```
# a rulat si a scris vulnerabilitati
curl -s -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/asset-vulns/_count" | jq .count   # >= 1
# idempotent: a doua rulare NU dubleaza (count unic pe cve == count total)
sudo systemctl start soc-nday.service      # a doua oara, prin systemd (incarca soc.env)
curl -s -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/asset-vulns/_search?size=0" \
  -H 'Content-Type: application/json' -d '{"aggs":{"u":{"cardinality":{"field":"cve"}}}}' \
  | jq '.hits.total.value, .aggregations.u.value'   # cele doua numere egale
# hunt pentru fiecare CVE cvss>=7
curl -s -H "Authorization: ApiKey $ES_API_KEY" \
  "$ES_URL/soc-incidents/_search?q=type:hunt_request+AND+source:nday_watch" | jq '.hits.total.value'
systemctl status soc-nday.service   # exit 0
```

### D. Metrica
soc-metrics type=nday: components_total, vulns_open, vulns_critical,
vulns_patch_available, vulns_resolved_today, needs_review_count, api_errors,
hunt_candidates, hunts_requested, patch_requests.

Confirmare NVD + plafon hunt (decizie 2026-10-29): NVD nu mai iese totul needs_review.
`nvd_affects()` parseaza intervalele din configurations[].cpeMatch[]
(versionStart/EndIncluding/Excluding + versiune exacta in CPE); daca versiunea instalata
e confirmat in interval -> needs_review=false, fixed_version din versionEndExcluding,
patch_available. Ce nu putem parsa ramane needs_review (prudent). Hunt-urile se creeaza
DOAR pentru inregistrari noi SAU nou-confirmate (needs_review: true->false, inca nevanate),
nevulnerabilitate confirmata, cvss >= NDAY_HUNT_MIN_CVSS (implicit 9.0 = critical), si
doar cele mai severe NDAY_HUNT_MAX (implicit 10) per rulare, ca sa nu inunde tier3.
hunt_requested=true inseamna exact "exista un hunt_request". Ambele praguri sunt reglabile
din soc.env.

Acceptare (verificat pe host 2026-10-29): timer ruleaza cu exit 0; zero duplicate in
asset-vulns (a doua rulare nu creste countul); un hunt_request pentru cele mai severe
cvss>=9 (plafonat la 10). Stare reala: 224 vulns (118 confirmate / 106 needs_review),
114 cu patch, 10 hunt_request + 10 patch_request, idempotent. Metrica formala soc-metrics
devine completa la 1c.

### E. Rollback
```
sudo systemctl disable --now soc-nday.timer
sudo rm -f /etc/systemd/system/soc-nday.{service,timer}
sudo systemctl daemon-reload
curl -s -X DELETE "$ES_URL/asset-vulns"                 # doar daca vrei sa stergi datele
# invalideaza cheile: POST /_security/api_key/_invalidate {"name":["soc-vulns-writer",...]}
# scoate cheile din soc.env; hunt/patch_request din soc-incidents raman (source=nday_watch)
```
Fisierele nday_watch.py / tests raman in repo (nu se sterg; CLAUDE.md).

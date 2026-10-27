# soc/ — Pasul 1: Inventar + N-day watch

Cod defensiv. Nimic de aici nu atinge o tinta; vulnwatch coreleaza versiuni
instalate cu CVE publice (OSV / NVD / CISA KEV / Wordfence-optional).

## Fisiere
- `sbom/gen_sbom.sh` — colector SBOM pe web-prod, read-only, ca `soc-reader`. Output: `/tmp/sbom.json`. **Livrat pentru revizie; NU rulat pe web-prod fara CONFIRM PASUL 1.**
- `sbom/push_sbom.py` — valideaza (Pydantic) si indexeaza SBOM-ul in `asset-inventory` (doc_id `host:data`).
- `vulnwatch/schemas.py` — `Sbom`, `SbomComponent`, `VulnRecord` (toate `extra="forbid"`).
- `vulnwatch/sources.py` — clienti OSV / NVD / CISA KEV / Wordfence; fiecare esueaza gratios.
- `vulnwatch/vulnwatch.py` — jobul principal: SBOM -> CVE -> `asset-vulns`.
- `vulnwatch/cve_hunt.py` — punte spre Tier 3: CVE (cvss>=7 sau KEV) -> job de hunt (ipoteza fixa). Cod pur.
- `vulnwatch/asset-vulns.mapping.json` + `asset-vulns.ilm.json` — mapping strict + ILM 90z.
- `vulnwatch/soc-vulnwatch.{service,timer}` — job zilnic 03:00 (Persistent).

## Decizii / abateri de la spec (de confirmat)
1. **Wordfence**: feed-ul `.../production` din spec intoarce **410** (URL invechit). `sources.query_wordfence` esueaza gratios (sare, nu opreste jobul). Alternative: setezi `WORDFENCE_FEED_URL` corect in `/etc/soc/env`, sau adaugam WPScan API (cheie). OSV acopera deja o parte din pluginurile WP.
2. **SBOM fara DB**: `gen_sbom.sh` parseaza versiunile de plugin/tema din headerele fisierelor (nu cere credentiale WP/DB). `wp-cli`, daca exista, doar completeaza flagul `active`. Asa ramane strict read-only pentru `soc-reader`.
3. **cve_hunt** nu modifica `tier3.py` automat. Hook-ul minim propus e mai jos.

## Comenzi GATED (nu le-am rulat — iti cer aprobarea)

### A. Index + ILM + cheie dedicata (pe es-node-1)
```bash
# ILM 90z
curl -s -X PUT "$ES_URL/_ilm/policy/asset-vulns-ilm" \
  -H "Authorization: ApiKey $ES_ELASTIC_ADMIN" -H 'Content-Type: application/json' \
  -d @soc/vulnwatch/asset-vulns.ilm.json
# index cu mapping strict
curl -s -X PUT "$ES_URL/asset-vulns" \
  -H "Authorization: ApiKey $ES_ELASTIC_ADMIN" -H 'Content-Type: application/json' \
  -d @soc/vulnwatch/asset-vulns.mapping.json
# cheie min-priv: doar write/create pe asset-vulns + read asset-inventory
curl -s -X POST "$ES_URL/_security/api_key" \
  -H "Authorization: ApiKey $ES_ELASTIC_ADMIN" -H 'Content-Type: application/json' -d '{
    "name": "ES_ASSET_VULNS_WRITER_KEY",
    "role_descriptors": { "vulnwatch_writer": {
      "indices": [
        {"names":["asset-vulns"],"privileges":["create_index","create_doc","index","write","read"]},
        {"names":["asset-inventory"],"privileges":["read"]}
      ]}}}'
# -> encoded din raspuns in /etc/soc/env ca ES_ASSET_VULNS_WRITER_KEY
```
(La fel, o cheie `ES_ASSET_INVENTORY_WRITER_KEY` pentru push_sbom, doar write pe asset-inventory.)

### B. Rulare SBOM pe web-prod (dupa CONFIRM PASUL 1)
```bash
# pe web-prod, ca soc-reader:
bash /path/gen_sbom.sh
# pe es-node-1:
scp soc-reader@192.168.10.138:/tmp/sbom.json /tmp/sbom.json
/home/tiberiu/lab/venv/bin/python soc/sbom/push_sbom.py /tmp/sbom.json
/home/tiberiu/lab/venv/bin/python soc/vulnwatch/vulnwatch.py
```

### C. Instalare timer (schimbare systemd — cu aprobare)
```bash
sudo cp soc/vulnwatch/soc-vulnwatch.service soc/vulnwatch/soc-vulnwatch.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now soc-vulnwatch.timer
```

## Hook propus in tier3.py (1.5) — de aplicat cu aprobarea ta
La inceputul ciclului Tier 3, inainte de vanatorile pe ipoteze ATT&CK:
```python
from soc.vulnwatch import cve_hunt
_cve_jobs = cve_hunt.pending_cve_hunts()
for _j in _cve_jobs:
    # foloseste HuntRunner-ul existent; rezultatul -> soc-incidents cu ref cve_id
    run_hypothesis_hunt(_j["hypothesis"], host=_j["host"],
                        origin="cve-watch", ref=_j["cve_id"])
if _cve_jobs:
    cve_hunt.mark_hunted(_cve_jobs)
```
(`run_hypothesis_hunt` = wrapper peste fluxul de hunt existent; il mapez exact
pe semnatura reala din tier3.py dupa ce confirmi.)

# Mutarea laboratorului pe alta masina

`git clone` aduce doar codul. Restul se muta separat sau se reface.

## Ce NU e in git (si de ce)

| ce | unde | cum se muta |
|---|---|---|
| secretele | env.sh, soc.env, .env | manual (scp/manager de parole), din *.example; niciodata pe GitHub |
| datele Elasticsearch (alerte, verdicts-history cu etichetele umane, soc-audit, baseline, asset-inventory, soc-wp-inventory, soc-hunts) | volumul Docker lab_esdata (~3.9 GB) | snapshot ES sau copia volumului cu stack-ul oprit |
| starea locala Tier 3 (incidente, reguli, vanatoare) | data/ | scp/rsync; se poate si reconstrui |
| mediul Python | venv/ | se reface: python3 -m venv venv && venv/bin/pip install -r requirements.txt |
| serviciile systemd | /etc/systemd/system/soc-* | din deploy/ (install.sh, install-tier3.sh) |
| istoricul proiectarii | ~/claude/ (in afara repo-ului) | scp separat |

Etichetele umane (ground_truth, label_source=human) traiesc doar in verdicts-history:
fara snapshot sau volum se pierd, si cu ele absolvirea executorului si metricile.

## Ce se schimba pe masina noua

- HOST_IP din .env, ES_URL daca nu mai e localhost.
- Elastic Agent de pe web-prod e inrolat in Fleet Server-ul de pe 172.20.99.220:
  trebuie reinrolat pe noul Fleet (token nou) sau masina noua trebuie sa poata ajunge in reteaua laboratorului.
- web-prod (172.20.99.240) si GPU-ul (172.30.6.231) sunt in reteaua privata:
  masina din cloud are nevoie de VPN/tunel catre ele (WEB_PROD_HOST, soc-llm-tunnel).
- Cheile API (ES_API_KEY, ES_WRITER_API_KEY, KIBANA_TIER3_API_KEY) sunt legate de cluster:
  raman valide doar daca muti datele (snapshot/volum); pe un cluster nou se recreeaza cu aceleasi drepturi.
- Licenta: trial-ul Elastic a expirat; un cluster nou porneste cu un trial nou de 30 de zile.

## Verificare dupa mutare

1. `source env.sh && python3 -m pytest -q tests` (fara ES, fara model).
2. orchestrator `--once` pe ultimele 60 de minute.
3. harness fast, apoi dev (porti: 4/4, 14/14).

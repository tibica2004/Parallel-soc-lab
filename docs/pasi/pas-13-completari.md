# Completari la plan (2026-11-03): ce lipsea dupa verificarea pasilor 0-12b

Verificarea din 2026-11-03 (stare.md, sectiunea "verifica daca e complet") a gasit: o restanta
vie a cozii (2 h 40 min), trei bucati de plan neimplementate (3.1 e/f/g, 3.4 check_agent, G8),
un timer lipsa (B1 restore lunar), un bug SBOM si doua chei/SG de strans. Totul e cod + comenzi
pentru om; nimic rulat pe hosturi din sesiune.

## A. Fisiere

| Fisier | Ce s-a schimbat | De ce |
|---|---|---|
| orchestrator.py | `take_until_cap()` (pur) + `--fetch-limit` (implicit 500, env FETCH_LIMIT); `--limit` = cazuri NOI judecate per ciclu; cursorul avanseaza la ultima alerta consumata | duplicatele consumau plafonul de 50/ciclu: 1797 alerte din auto-atac tineau cursorul 2 h 40 min in urma; un atac real ar fi fost vazut abia dupa. ExecStart neatins (`--limit 50` isi schimba sensul, nu valoarea) |
| behavioral_rules.py, honeytokens.py | regulile 3.1 e/f/g: `soc-sensitive-file-change` (critical), `soc-account-or-cron-manipulation` (high), `soc-suid-or-capability-set` (critical); tactici T1098/T1136.001/T1548.001 | persistenta/escaladarea se vedeau doar la vanatoarea orara Tier 3 (hunt.py); acum in timp real, tag shadow-review 7 zile |
| absence_check.py | `check_key_rotation` (G8, SOC_KEYS_ROTATED_ON, prag 95 z), `check_restore_test` (stamp, prag 35 z), `check_agent` (Fleet API, cheie optionala KIBANA_FLEET_API_KEY), `agent_problems`/`days_since` pure | G8 nu exista; 3.4 check_agent era amanat; un backup netestat nu e backup |
| deploy/soc-backup-restore-test.{sh,service,timer} | stamp `.restore-test-ok` la succes; timer lunar (ziua 1, 03:00, User=tiberiu, grup docker) | B1 cerea test lunar; exista doar scriptul manual |
| deploy/web-prod/soc-sbom.sh | `awk '$1 ~ /_module$/'` | antetul "Loaded Modules:" aparea ca modul Apache "Loaded" (bug notat la 3.B) |
| elastic_tools.py | `is_robots_trap()`; `sweep_new_url_paths` sare momelile din robots.txt | dublura cu regula soc-honey-robots-trap; apareau ca "expuneri" la auto-atac |
| deploy/es-node-1/pas13-setup.sh | om: replici 0, cheia soc-reader + benign-ground-truth/soc-cases, instalare timer restore | ES galben cu 70 shard-uri; ES_READER primea 403 pe benign-ground-truth |
| tests/ | +13 teste (dedup/cap, reguli e/f/g, absence, sweeps) | 1099 verzi local |

## B. Comenzi (om)

1. Poarta pentru orchestrator (atinge bucla; benign-gen OPRIT inainte):
   `ssh ubuntu@172.30.6.210 'sudo systemctl stop benign-gen'`, apoi pe es-node-1 fast + dev
   (`SCENARIOS=scenarios_fast.yml VERBOSE=1 python3 -u harness.py | tee results/completari-fast-$(date +%F-%H%M).txt`,
   la fel cu scenarios.yml), apoi `start` benign-gen.
2. Deploy cod pe es-node-1 (scp orchestrator.py absence_check.py behavioral_rules.py honeytokens.py
   elastic_tools.py, cu copii `.pre-13`), `sudo systemctl restart soc-orchestrator`.
3. `bash deploy/es-node-1/pas13-setup.sh` (cont elastic + sudo).
4. In soc.env pe es-node-1: `SOC_KEYS_ROTATED_ON=2026-10-29` (data crearii cheilor; G8). Optional
   `KIBANA_FLEET_API_KEY=<cheie Kibana cu rol doar fleet:read>` (Stack Management -> API keys ->
   rol personalizat Kibana: Fleet = Read, nimic altceva); fara ea verificarea e sarita, nu esueaza.
5. Kibana (cont elastic): `python3 deploy/kibana/honeytoken_rules.py verifica` apoi `aplica`
   (cele 3 reguli noi) — intra in shadow-review 7 zile.
6. web-prod: `scp deploy/web-prod/soc-sbom.sh tiberiu@172.30.6.249:/tmp/ && ssh -t tiberiu@172.30.6.249
   'sudo install -o root -g root -m 755 /tmp/soc-sbom.sh /usr/local/bin/soc-sbom.sh && sudo systemctl
   start soc-sbom.service && tail -1 /var/log/soc/sbom.ndjson | jq -c "[.components[] | select(.type==\"apache_module\") | .name]"'`
   -> fara "Loaded".
7. FACUT 2026-11-04 (verificat cu conexiuni noi). OpenStack (de pe boxa sesiunii; ID-urile citite 2026-11-03):
   - victim-sg: SSH de la atacator nu are ce cauta: `openstack security group rule delete 657f6172-8d5c-40c2-b5af-2a892525d1ef`
   - es-sg 9200 doar web-prod + benign-gen (lab-sink e tinta ART, nu trebuie sa vada ES):
     `openstack security group rule create --protocol tcp --dst-port 9200 --remote-ip 192.168.10.138/32 es-sg`
     `openstack security group rule create --protocol tcp --dst-port 9200 --remote-ip 192.168.10.150/32 es-sg`
     `openstack security group rule delete 4b5b78b3-346f-4fb5-957e-6bffc3761d3a` (9200 din /24)
     `openstack security group rule delete 8a829e58-db9e-4bc9-9de5-034d9a10414b` (9200 de la boxa veche; forward_guard o taia oricum)
   - es-sg 8220 doar web-prod: `openstack security group rule create --protocol tcp --dst-port 8220 --remote-ip 192.168.10.138/32 es-sg`
     apoi `openstack security group rule delete cd826ea9-41ff-4fc1-98c1-c4982cd613b3`.
     (agentul de pe benign-gen? NU exista agent pe benign-gen; daca apare, +.150.)
   Ordinea: intai create, apoi delete, ca telemetria sa nu se rupa nicio secunda.
8. Fleet UI: Custom Logs `soc.benign_actions` pe policy web-prod (pas-04.md, punctul 4) — inca 0 docs.
9. `make determinism` (GPU; benign-gen oprit; ~40 alerte x 2) — nu cere etichete.

## C. Verificare

- Unitare: `python3 -m pytest tests -q` -> 1099 passed (local, 2026-11-03).
- Coada: dupa restart, in jurnal `ciclu N: X alerte ... (+Y ramase)` scade la 0 in cateva cicluri;
  `soc-metrics type=cycle` fara `backlog` sustinut; cursorul (`soc-state`) la < 5 min de prezent.
- Reguli: `honeytoken_rules.py verifica` -> 9 reguli soc-behavioral pornite. Test aprobat (web-prod):
  `sudo touch /etc/cron.d/soc-test-e && sudo rm /etc/cron.d/soc-test-e` -> soc-sensitive-file-change
  (si cron_changed din absence_check la minutul 10); `crontab -l` NU alerteaza.
- absence_check: `journalctl -u soc-absence -n 30` arata `chei: rotite acum N zile`, `restore test:
  acum N zile`, `fleet agent web-prod: online` (sau "sarita" fara cheie).
- SBOM: ultimul doc fara modul "Loaded"; sbom_drift va raporta O DATA "removed Loaded" (asteptat).
- ES: `_cluster/health` green, 0 nealocate; `ES_READER` 200 pe benign-ground-truth.

## D. Metrica

soc-metrics type=cycle: `queue_depth`/`alerts_fetched` + jurnal "ramase"; type=integrity_check
ages: `key_rotation_days`, `restore_test_days`, `agent_ok`. Acceptare: restanta cursorului < 5 min
in 24 h fara harness; 3 reguli noi 7 zile shadow-review cu fp_rate < 0.05 sau pe lista de
recalibrare; restore stamp < 35 z; ES green.

## E. Rollback (doar la cerere)

```
cd ~/lab && for f in orchestrator.py absence_check.py behavioral_rules.py honeytokens.py elastic_tools.py; do cp -p $f.pre-13 $f; done; sudo systemctl restart soc-orchestrator
sudo systemctl disable --now soc-backup-restore-test.timer; sudo rm /etc/systemd/system/soc-backup-restore-test.*
# Kibana: sterge cele 3 reguli noi dupa rule_id; ES: PUT _settings number_of_replicas 1 (nu recomand)
# OpenStack: recreeaza regulile sterse cu --remote-ip 192.168.10.0/24
```

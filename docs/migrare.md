# Mutarea laboratorului in cloud (elastic-lab + web-prod; GPU ramane pe loc)

`git clone` aduce doar codul. Restul (secrete, datele ES, WordPress, senzorii de pe
web-prod, legatura cu GPU-ul) se muta sau se reface dupa pasii de mai jos.

## Ce NU e in git

| ce | unde | cum se muta |
|---|---|---|
| secretele | env.sh, soc.env, .env | scp direct intre masini, din *.example daca se refac; niciodata pe GitHub |
| datele Elasticsearch (alerte, verdicts-history cu etichetele umane, soc-audit, baseline, asset-inventory, soc-wp-inventory, soc-hunts, regulile si dashboard-urile Kibana, politicile Fleet) | volumul Docker lab_esdata (~3.9 GB) | arhiva volumului, cu stack-ul oprit (aceeasi versiune 9.5.1) |
| starea locala Tier 3 | data/ | scp/rsync |
| mediul Python | venv/ | se reface din requirements.txt |
| WordPress (fisiere + baza de date) | web-prod: /var/www/html + MariaDB | imaginea VM sau copie + mysqldump |
| istoricul proiectarii | ~/claude/ | scp separat |

Etichetele umane (ground_truth, label_source=human) exista DOAR in verdicts-history.
Fara volum se pierd, si cu ele absolvirea executorului si metricile pe etichete.

## Decizii de luat inainte

1. **IP-urile private.** Recomandat: subnet 172.20.99.0/24 in cloud, cu IP-uri private
   statice 172.20.99.220 (elastic-lab) si 172.20.99.240 (web-prod). Atunci nu se schimba
   nimic in cod si nici in Fleet. Altfel trebuie schimbate: HOST_IP (.env), WEB_PROD_HOST,
   WP_SSH_TARGET, WP_SELF_IPS, label_ui --host, URL-ul Fleet Server, bpf-filter si
   threshold.config in Suricata, CLAUDE.md.
2. **Legatura cu GPU-ul** (172.30.6.231, ramane in reteaua de acum). Din cloud nu se vede.
   Variante, in ordinea preferintei:
   - VPN WireGuard/Tailscale intre GPU si elastic-lab: soc-llm-tunnel ramane `ssh -L`,
     doar cu IP-ul de VPN al GPU-ului.
   - tunel invers pornit DE PE GPU (doar SSH de iesire din reteaua GPU-ului):
     `autossh -M 0 -N -R 127.0.0.1:11434:localhost:11434 tiberiu@<IP public elastic-lab>`;
     pe elastic-lab codul vede tot localhost:11434, iar soc-llm-tunnel nu mai e necesar.
   - host de salt accesibil din internet in reteaua GPU-ului: `ssh -J`.
   GPU-ul e partajat: orice serviciu instalat acolo se cere administratorului.
   Portul 11434 (si 11435 pentru RedSage) NU se expune niciodata public.
3. **web-prod: imagine sau reconstruire.** Recomandat: export VirtualBox (OVA) si import
   ca imagine in cloud, pentru ca WordPress-ul (core 7.1.3, pluginuri) si senzorii nu sunt in git.
   Daca providerul nu accepta import de imagini, reconstruiesti (pasul 14b).

## Pasul 0 — pe laboratorul vechi

1. Merge-ul ramurii de migrare si push: `git switch main && git merge faza-19-migrare-cloud && git push origin --all`.
2. Noteaza starea de referinta: `curl -s -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/_cat/indices?h=index,docs.count&s=index" > ~/indici-inainte.txt`
   (cu `source env.sh`), plus ultimul rezultat dev/fast din results/.

## Pasul 1 — infrastructura in cloud

3. VPC + subnet 172.20.99.0/24 (decizia 1).
4. VM-uri Debian 13 (kernel cu BTF, pentru Defend eBPF):
   - elastic-lab: 8 vCPU, 16-24 GB RAM, 80 GB disc (ca acum: 8 vCPU, 21 GB, 29 GB folositi);
   - web-prod: 2 vCPU, 2-4 GB RAM, 20 GB disc.
   Hostname-uri identice: `elastic-lab`, `web-prod` (host.name apare in interogari si in asset-inventory).
5. Firewall (security group):
   - SSH 22 doar de la IP-ul tau (si de la GPU, daca folosesti tunelul invers);
   - 9200 si 8220 doar de la web-prod, in subnet;
   - Kibana 5601 si label_ui 8088 nepublice: le deschizi cu `ssh -L 5601:localhost:5601 -L 8088:172.20.99.220:8088`;
   - web-prod:80 doar din subnet si de la IP-ul tau. WordPress-ul e vulnerabil intentionat
     si nu se expune pe internet.
6. Citeste politica providerului despre testele de securitate pe propriile VM-uri
   (harness-ul genereaza atacuri reale pe web-prod).

## Pasul 2 — oprirea si copierea datelor

7. Pe elastic-lab vechi:
   ```
   sudo systemctl stop soc-tier3.timer soc-orchestrator
   cd ~/lab && docker compose stop
   docker run --rm -v lab_esdata:/v -v ~/:/b debian tar czf /b/esdata.tgz -C /v .
   tar czf ~/lab-local.tgz -C ~/lab env.sh soc.env .env data
   sha256sum ~/esdata.tgz ~/lab-local.tgz
   ```
8. Copiaza `esdata.tgz`, `lab-local.tgz` si (optional) `~/claude` direct pe noul elastic-lab
   (`scp`/`rsync`) si verifica sha256.
9. Opreste VM-urile vechi, dar NU le sterge, ca sa ramana backup pana trec portile.
   Nu le porni in paralel cu cele noi: acelasi agent Fleet ar raporta de doua ori.

## Pasul 3 — noul elastic-lab

10. Pachete: Docker din depozitul oficial (docker-ce + docker-compose-plugin, ca acum), `git python3-venv autossh curl`;
    `vm.max_map_count=262144` in /etc/sysctl.d/ (cerut de ES); utilizatorul `tiberiu`
    (serviciile folosesc /home/tiberiu/lab).
11. `git clone git@github.com:tibica2004/Parallel-soc-lab.git ~/lab`, apoi
    `tar xzf ~/lab-local.tgz -C ~/lab && chmod 600 ~/lab/{env.sh,soc.env,.env}`.
12. Datele ES:
    ```
    docker volume create lab_esdata
    docker run --rm -v lab_esdata:/v -v ~/:/b debian tar xzf /b/esdata.tgz -C /v
    cd ~/lab && docker compose up -d
    ```
    Compara `_cat/indices` cu `~/indici-inainte.txt`. Cheile API, regulile Kibana,
    dashboard-ul si politicile Fleet vin odata cu volumul.
13. `python3 -m venv venv && venv/bin/pip install -r requirements.txt`, apoi
    `source env.sh && python3 -m pytest -q tests` (693 de teste, fara ES si fara model).
14. Fleet Server: Kibana -> Fleet -> Add Fleet Server, pe acelasi URL `http://172.20.99.220:8220`
    (agent instalat pe host, nu in Docker).
15. GPU-ul, conform deciziei 2. Verificare: `curl -s localhost:11434/api/tags` intoarce qwen3:14b.
    Schimbarea lui deploy/soc-llm-tunnel.service se face pe ramura, cu aprobare.
16. Serviciile: `bash deploy/install.sh` si `bash deploy/install-tier3.sh`, dupa ce le citesti.
    ExecStart-ul din soc-orchestrator.service ramane neschimbat (shadow fortat).

## Pasul 4 — noul web-prod

17a. Cu imagine: import OVA, IP-ul .240, hostname web-prod. Agentul ramane inrolat (acelasi
     URL Fleet). Verifica interfata de retea in suricata.yaml (in cloud nu mai e enp0s3)
     si `audit=1` in linia de boot.
17b. Fara imagine, reconstruire din deploy/web-prod (README.md):
     - Apache 2.4 + PHP 8.4, `000-default.conf`, `index.html`;
     - WordPress: copie /var/www/html + `mysqldump` din VM-ul vechi, WP-CLI pentru wp_inventory.py;
     - utilizatorul tiberiu cu cheia SSH a lui elastic-lab;
     - Elastic Agent: `elastic-agent install --url=http://172.20.99.220:8220 --enrollment-token=<din Kibana> --insecure`
       in politica web-prod (Defend, system, apache, Auditd Manager, Suricata);
     - suricata.md (interfata noua!), auditd-fim.md (`audit=1`), `yara/install.sh`,
       `honeytokens.sh`, `soc-canary.cron`.
18. Din politica Fleet veche, agentul vechi ramane "offline": il scoti din Fleet dupa ce trec portile.

## Pasul 5 — verificare (portile)

19. Fluxul de date: documente noi de la host.name=web-prod in logs-endpoint.events.*,
    logs-apache.*, logs-suricata.eve-*, logs-auditd_manager.*; canarul apare (canary_check.py).
20. `python3 tier3.py --once --expunere` in dry-run: inventarul WordPress (core 7.1.3, akismet, hello).
21. Orchestratorul `--once` pe ultimele 60 de minute fara erori.
22. Harness-urile (lente, in fundal): fast 4/4, dev 14/14, validare 8/8.
    La reconstruire baseline-ul vechi nu mai descrie exact noul web-prod, deci in primele
    zile pot aparea findings rare noi. O regresie se raporteaza; nu se ajusteaza scenariile
    sau pragurile.
23. Abia dupa porti: opresti definitiv VM-urile vechi (pastreaza OVA-urile) si actualizezi
    CLAUDE.md daca s-a schimbat ceva in infrastructura.

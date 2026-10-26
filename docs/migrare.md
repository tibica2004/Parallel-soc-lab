# Ghid: mutarea laboratorului in cloud

Se muta: elastic-lab (tot ce e in ~/lab + Elasticsearch/Kibana/Fleet) si web-prod.
Ramane pe loc: GPU-ul 172.30.6.231 (Ollama qwen3:14b).

Ordinea: Partea 0 (pregatire) -> Partea 1 (elastic-lab) -> Partea 2 (web-prod)
-> Partea 3 (legatura cu GPU-ul) -> Partea 4 (servicii si porti) -> Partea 5 (inchidere).
Intre Partea 1 si Partea 4 laboratorul nu functioneaza: alege o zi in care nu ai nevoie de el.

`<IP-ELASTIC>` si `<IP-WEB>` = IP-urile PUBLICE ale VM-urilor noi (pentru SSH de la tine).
IP-urile PRIVATE raman 172.20.99.220 si 172.20.99.240 (vezi 0.3).

---

## Ce NU e in git (si cum ajunge in cloud)

| ce | unde | cum |
|---|---|---|
| secretele | ~/lab/env.sh, soc.env, .env | arhiva + scp (pasul 1.4) |
| datele Elasticsearch: alerte, verdicts-history (etichetele tale umane!), soc-audit, baseline, inventare, soc-hunts, regulile si dashboard-ul Kibana, politicile Fleet, cheile API | volumul Docker lab_esdata (~3.9 GB) | arhiva volumului (pasul 1.4) |
| starea Tier 3 | ~/lab/data/ | arhiva + scp |
| istoricul proiectarii | ~/claude/ | arhiva + scp |
| mediul Python | ~/lab/venv/ | se reface din requirements.txt |
| WordPress (fisiere + baza `wp`) | web-prod: /var/www/html + MariaDB | arhiva + mysqldump (pasul 2.2) |
| configurarea senzorilor | web-prod: /etc/suricata, /etc/soc-yara, cron, grub | arhiva + scripturile din deploy/web-prod |

---

## Partea 0 — Pregatire

**0.1 Codul pe GitHub** (pe elastic-lab vechi):

    cd ~/lab
    git switch main
    git merge faza-19-migrare-cloud
    git push origin --all
    git status            # "up to date with origin/main", nimic de comis

**0.2 Politica providerului.** Citeste regulile despre teste de securitate pe propriile
VM-uri: harness-ul lanseaza atacuri reale (reverse shell, webshell, recon) pe web-prod.

**0.3 Reteaua.** In cloud: o retea privata (VPC) cu subnetul 172.20.99.0/24.
Cu IP-uri private statice .220 si .240 nu se schimba nimic in cod, in Fleet
(http://172.20.99.220:8220), in Suricata (bpf-filter, threshold.config) sau in
WP_SELF_IPS. Daca providerul nu permite subnetul asta, OPRESTE-TE si cere lista de
schimbari: adresele sunt scrise in ~10 locuri.

**0.4 Doua VM-uri Debian 13** (kernel cu BTF, pentru Defend eBPF):

| VM | vCPU | RAM | disc | IP privat | hostname |
|---|---|---|---|---|---|
| elastic-lab | 8 | 16-24 GB | 80 GB | 172.20.99.220 | elastic-lab |
| web-prod | 2 | 2-4 GB | 20 GB | 172.20.99.240 | web-prod |

Hostname-urile trebuie sa fie exact acestea (host.name apare in interogari si in asset-inventory).
Pe ambele: utilizatorul `tiberiu` cu sudo.

**0.5 Firewall (security group).**

| port | elastic-lab | web-prod |
|---|---|---|
| 22 SSH | doar IP-ul tau | doar IP-ul tau + 172.20.99.220 |
| 9200, 8220 | doar 172.20.99.240 | — |
| 5601 Kibana, 8088 etichetare | inchise (le deschizi prin tunel SSH) | — |
| 80 HTTP | — | doar 172.20.99.220 + IP-ul tau |

WordPress-ul e vulnerabil intentionat (core 7.1.3, hello 1.7.2): NU il expune pe internet.

---

## Partea 1 — elastic-lab

**1.1 Pachete** (pe elastic-lab NOU):
- Docker din depozitul oficial, ca pe vechi (docker-ce + docker-compose-plugin):
  ghidul "Install Docker Engine on Debian" de pe docs.docker.com.
- restul:

      sudo apt install git python3-venv autossh curl
      sudo usermod -aG docker tiberiu          # apoi iesi si intra din nou
      echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-elasticsearch.conf
      sudo sysctl --system

**1.2 Cheia SSH a masinii noi** (repo-ul e privat; aceeasi cheie va intra pe web-prod):

    ssh-keygen -t ed25519
    cat ~/.ssh/id_ed25519.pub     # o adaugi in GitHub: Settings -> SSH keys

**1.3 Reperul** (pe elastic-lab VECHI):

    cd ~/lab && source env.sh
    curl -s -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/_cat/indices?h=index,docs.count&s=index" > ~/indici-inainte.txt

**1.4 Oprire si arhive** (pe elastic-lab VECHI). De aici laboratorul vechi e oprit.

    sudo systemctl stop soc-tier3.timer soc-orchestrator
    cd ~/lab && docker compose stop
    docker run --rm -v lab_esdata:/v -v ~/:/b debian tar czf /b/esdata.tgz -C /v .
    tar czf ~/lab-local.tgz -C ~/lab env.sh soc.env .env data
    tar czf ~/claude.tgz -C ~ claude
    sha256sum ~/esdata.tgz ~/lab-local.tgz ~/claude.tgz > ~/sume.txt

Fleet Server-ul vechi (agent pe host, nu in Docker) il opresti si pe el, ca agentul
de pe web-prod sa nu mai trimita la vechi: `sudo systemctl stop elastic-agent`.

**1.5 Copierea** (de pe elastic-lab VECHI):

    scp ~/esdata.tgz ~/lab-local.tgz ~/claude.tgz ~/sume.txt ~/indici-inainte.txt tiberiu@<IP-ELASTIC>:~

Pe elastic-lab NOU: `sha256sum -c ~/sume.txt` -> OK la toate trei.

**1.6 Clone si restaurare** (pe elastic-lab NOU):

    git clone git@github.com:tibica2004/Parallel-soc-lab.git ~/lab
    tar xzf ~/lab-local.tgz -C ~/lab
    chmod 600 ~/lab/env.sh ~/lab/soc.env ~/lab/.env
    tar xzf ~/claude.tgz -C ~
    docker volume create lab_esdata
    docker run --rm -v lab_esdata:/v -v ~/:/b debian tar xzf /b/esdata.tgz -C /v
    cd ~/lab && docker compose up -d

**1.7 Verificarea datelor** (dupa 1-2 minute):

    cd ~/lab && source env.sh
    curl -s -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/_cluster/health?pretty" | grep status
    curl -s -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/_cat/indices?h=index,docs.count&s=index" > ~/indici-dupa.txt
    diff ~/indici-inainte.txt ~/indici-dupa.txt && echo IDENTIC

`green` sau `yellow` e in regula (un singur nod). Daca lipseste un indice intreg: stop.

**1.8 Python si teste:**

    python3 -m venv venv && venv/bin/pip install -r requirements.txt
    source env.sh && python3 -m pytest -q tests        # 693 passed

**1.9 Kibana prin tunel** (de la tine):

    ssh -L 5601:localhost:5601 tiberiu@<IP-ELASTIC>

http://localhost:5601: regulile, dashboard-ul soc-metrici-, verdictele sunt acolo.

**1.10 Fleet Server** (pe elastic-lab NOU): Kibana -> Fleet -> Settings: Fleet Server host
`http://172.20.99.220:8220` (vine din volum). Fleet -> Add Fleet Server -> copiezi comanda de
instalare generata (contine tokenul) si o rulezi pe elastic-lab nou. Agentul vechi de
Fleet Server apare "offline": il scoti (Unenroll) dupa ce noul e "healthy".

---

## Partea 2 — web-prod

Pe web-prod vechi: Apache 2.4 + PHP 8.4, MariaDB (baza `wp`), WordPress in /var/www/html
(117 MB), WP-CLI in /usr/local/bin/wp, Suricata 7.0.10, YARA (/etc/soc-yara + timer),
canarul (/etc/cron.d/soc-canary), `audit=1` la boot, Elastic Agent + Defend.

**2.1 Pachete** (pe web-prod NOU):

    sudo apt install apache2 php8.4 php8.4-mysql php8.4-cli php8.4-opcache mariadb-server \
                     suricata suricata-update yara curl

**2.2 Arhivele** (pe web-prod VECHI). Atentie: `.env.bak` e o MOMEALA. Citirea ei (inclusiv
de tar) declanseaza alerta honeytoken prin auditd. O excluzi si o replantezi pe noul host (2.6).

    sudo tar czf /tmp/www.tgz -C /var/www --exclude=html/.env.bak html
    sudo mysqldump --single-transaction wp | gzip > /tmp/wp.sql.gz
    sudo tar czf /tmp/etc.tgz /etc/apache2/sites-available/000-default.conf \
        /etc/suricata/suricata.yaml /etc/suricata/threshold.config /etc/cron.d/soc-canary
    sudo cp /usr/local/bin/wp /tmp/wp-cli && sudo chown tiberiu /tmp/*.tgz /tmp/wp.sql.gz /tmp/wp-cli
    cd /tmp && sha256sum www.tgz wp.sql.gz etc.tgz wp-cli > sume-web.txt

Copierea (de la tine, prin masina ta, sau direct daca web-prod vechi iese pe internet):

    scp tiberiu@172.20.99.240:/tmp/{www.tgz,wp.sql.gz,etc.tgz,wp-cli,sume-web.txt} .
    scp www.tgz wp.sql.gz etc.tgz wp-cli sume-web.txt tiberiu@<IP-WEB>:/tmp/

Pe web-prod NOU: `cd /tmp && sha256sum -c sume-web.txt`.

**2.3 WordPress** (pe web-prod NOU):

    sudo tar xzf /tmp/www.tgz -C /var/www
    sudo install -m 755 /tmp/wp-cli /usr/local/bin/wp
    sudo mysql -e "CREATE DATABASE wp; CREATE USER 'wp'@'localhost' IDENTIFIED BY '<parola din wp-config.php>'; GRANT ALL ON wp.* TO 'wp'@'localhost';"
    zcat /tmp/wp.sql.gz | sudo mysql wp
    sudo tar xzf /tmp/etc.tgz -C /    # 000-default.conf, suricata.yaml, threshold.config, soc-canary
    sudo systemctl restart apache2
    curl -s -o /dev/null -w "%{http_code}\n" http://localhost/      # 200
    sudo -u www-data wp --path=/var/www/html core version           # 7.1.3

Parola bazei o citesti din /var/www/html/wp-config.php (DB_PASSWORD) — nu o copia altundeva.

**2.4 Acces de pe elastic-lab** (harness-ul si wp_inventory.py intra prin ssh):

    # pe elastic-lab NOU:
    ssh-copy-id tiberiu@172.20.99.240
    ssh tiberiu@172.20.99.240 hostname        # web-prod

Configureaza sudo pentru tiberiu ca pe web-prod vechi (compara `sudo -l` pe vechi si pe nou).

**2.5 Senzori pe host.**
- `audit=1` la boot (auditd-fim.md):

      sudo sed -i 's/^GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="audit=1 /' /etc/default/grub
      sudo update-grub && sudo reboot
      grep -o audit=1 /proc/cmdline       # dupa reboot

- Suricata: suricata.yaml a venit la 2.3. Interfata din cloud NU mai e enp0s3:

      ip -br a                                     # numele interfetei cu 172.20.99.240 (ex. ens5)
      grep -n "interface: enp0s3" /etc/suricata/suricata.yaml      # linia 622
      sudo sed -i '622s/- interface: enp0s3/- interface: <NUME>/' /etc/suricata/suricata.yaml
      sudo suricata-update
      sudo suricata -T -c /etc/suricata/suricata.yaml
      sudo systemctl enable --now suricata
      free -m | head -2                            # ET Open ia 400-600 MB

- YARA (din repo, de pe elastic-lab NOU):

      scp -r ~/lab/deploy/web-prod/yara tiberiu@172.20.99.240:/tmp/soc-yara
      ssh -t tiberiu@172.20.99.240 'sudo bash /tmp/soc-yara/install.sh && rm -rf /tmp/soc-yara'

- Canarul (soc-canary.cron a venit la 2.3):

      sudo cp /usr/bin/true /usr/local/bin/soc-canary
      sudo chmod 644 /etc/cron.d/soc-canary

**2.6 Honeytokens** (de pe elastic-lab NOU; replanteaza .env.bak exclusa la 2.2):

    scp ~/lab/deploy/web-prod/honeytokens.sh tiberiu@172.20.99.240:/tmp/
    ssh -t tiberiu@172.20.99.240 'sudo bash /tmp/honeytokens.sh && rm /tmp/honeytokens.sh'

Regulile din Kibana exista deja (au venit cu volumul).

**2.7 Elastic Agent.** Politica web-prod (Defend, system, apache, Auditd Manager, Suricata)
e in Fleet, a venit cu volumul. Kibana -> Fleet -> Enrollment tokens -> tokenul politicii web-prod.
Descarci Elastic Agent 9.5.1 (aceeasi versiune ca stack-ul) si pe web-prod NOU:

    sudo ./elastic-agent install --url=http://172.20.99.220:8220 --enrollment-token=<TOKEN> --insecure

In Fleet: agentul nou `web-prod` -> Healthy; agentul vechi `web-prod` -> offline -> Unenroll.

---

## Partea 3 — Legatura cu GPU-ul

Pe vechi: soc-llm-tunnel = `ssh -L 11434:localhost:11434 tiberiu@172.30.6.231` (GPU-ul era
in aceeasi retea). Din cloud GPU-ul nu se vede. Variante (GPU-ul e partajat: ce instalezi
acolo ceri administratorului; 11434/11435 NU se expun niciodata public):

1. **VPN (WireGuard/Tailscale)** intre GPU si elastic-lab: soc-llm-tunnel ramane, doar cu
   IP-ul de VPN al GPU-ului in loc de 172.30.6.231.
2. **Tunel invers pornit de pe GPU** (doar SSH de iesire din reteaua GPU-ului):

       autossh -M 0 -N -R 127.0.0.1:11434:localhost:11434 tiberiu@<IP-ELASTIC>

   Pe elastic-lab codul vede tot localhost:11434; soc-llm-tunnel nu mai porneste.
   Port 22 pe elastic-lab trebuie deschis si pentru IP-ul public al retelei GPU-ului.
3. **Host de salt** din reteaua GPU-ului, accesibil din internet: `-J tiberiu@<salt>` in soc-llm-tunnel.

Schimbarea lui deploy/soc-llm-tunnel.service se face pe ramura, dupa ce alegi varianta.
Verificare: `curl -s localhost:11434/api/tags` pe elastic-lab NOU arata qwen3:14b.

---

## Partea 4 — Servicii si porti

**4.1 Fluxul de date** (pe elastic-lab NOU, dupa ~10 minute):

    cd ~/lab && source env.sh
    for i in 'logs-endpoint.events.*' 'logs-apache.*' 'logs-suricata.eve-*' 'logs-auditd_manager.*'; do
      printf "%-28s " "$i"
      curl -s -H "Authorization: ApiKey $ES_API_KEY" -H 'Content-Type: application/json' \
        "$ES_URL/$i/_count" -d '{"query":{"bool":{"filter":[{"term":{"host.name":"web-prod"}},{"range":{"@timestamp":{"gte":"now-15m"}}}]}}}'
      echo
    done
    python3 canary_check.py

Toate patru > 0 si canarul vazut. Daca Defend lipseste, verifica in Fleet starea Endpoint.

**4.2 Serviciile** (citeste scripturile inainte):

    bash deploy/install.sh          # soc-llm-tunnel + soc-orchestrator (shadow fortat in ExecStart)
    bash deploy/install-tier3.sh    # soc-tier3.timer
    systemctl is-active soc-llm-tunnel soc-orchestrator soc-tier3.timer

La varianta 2 din Partea 3, nu activa soc-llm-tunnel.

**4.3 Verificari rapide:**

    SHADOW_MODE=true python3 orchestrator.py --minutes 60   # rulare manuala, fara erori
    python3 wp_inventory.py arata       # core 7.1.3, akismet, hello
    python3 tier3.py --once --expunere  # dry-run

**4.4 Portile** (lente, in fundal, timeout mare):

    SCENARIOS=scenarios_fast.yml VERBOSE=1 python3 -u harness.py | tee results/migrare-fast-$(date +%F-%H%M).txt
    SCENARIOS=scenarios.yml VERBOSE=1 python3 -u harness.py | tee results/migrare-dev-$(date +%F-%H%M).txt
    SCENARIOS=scenarios_validation.yml VERBOSE=1 python3 -u harness.py | tee results/migrare-val-$(date +%F-%H%M).txt

Referinta: fast 4/4, dev 14/14 (recall 100%), validare 8/8. Baseline-ul vechi descrie
web-prod vechi: primele zile pot aparea findings rare noi (ex. alte nume de interfata,
alte procese ale providerului de cloud). O regresie se raporteaza, nu se ajusteaza
scenariile sau pragurile.

---

## Partea 5 — Inchidere

- Dupa ce trec portile: opresti VM-urile vechi. Nu le sterge cateva saptamani (exporta-le
  ca OVA din VirtualBox) si nu le porni in paralel cu cele noi.
- Arhivele (esdata.tgz, lab-local.tgz cu secretele, www.tgz, wp.sql.gz) le stergi de pe
  masinile intermediare, inclusiv de pe a ta, dupa ce totul merge.
- Actualizezi CLAUDE.md (sectiunea Infrastructura) daca s-a schimbat ceva, de exemplu legatura cu GPU-ul.

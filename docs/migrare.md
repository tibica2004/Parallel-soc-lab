# Ghid: mutarea laboratorului pe OpenStack (es-node-1 + web-prod)

Laboratorul vechi (VirtualBox): elastic-lab 172.20.99.220, web-prod 172.20.99.240 (Debian 13).
Tinta (OpenStack, Ubuntu 24.04):

| VM | IP privat (es-net) | IP flotant | rol |
|---|---|---|---|
| es-node-1 | 192.168.10.121 | 172.30.6.106 | ES + Kibana + Fleet Server + orchestrator (fostul elastic-lab) |
| web-prod | 192.168.10.138 | 172.30.6.249 | Apache + PHP + WordPress + senzori |
| atacator | 10.10.0.220 | 172.30.6.133 | nefolosit in ghid (atacuri din exterior, mai tarziu) |

GPU-ul (172.30.6.231) ramane pe loc; e in aceeasi retea cu IP-urile flotante.

Comenzile se ruleaza de pe **elastic-lab VECHI**, daca nu scrie altfel: el vede si masinile
vechi (172.20.99.x), si pe cele noi (172.30.6.x), iar security group-urile il permit.
Intre pasul 4 si pasul 11 laboratorul nu functioneaza.

---

## Pasul 0 — codul la zi pe GitHub (elastic-lab vechi)

```
cd ~/lab
git switch main
git merge faza-19-migrare-cloud
git push origin --all
mv ~/lab/inventar-openstack.txt ~/ 2>/dev/null; git status
```

## Pasul 1 — security groups si (optional) RAM mai mult (elastic-lab vechi)

es-node-1 trebuie sa intre pe web-prod prin SSH (harness, wp_inventory) si HTTP:

```
openstack security group rule create --protocol tcp --dst-port 22 --remote-ip 192.168.10.121/32 victim-sg
openstack security group rule create --protocol tcp --dst-port 80 --remote-ip 192.168.10.121/32 victim-sg
openstack security group rule list victim-sg
```

es-node-1 are 8 GB (vechiul avea 21 GB; ES are heap 4 GB). Daca exista un flavor cu 16 GB:

```
openstack flavor list
openstack server resize --flavor <flavor cu 16 GB> es-node-1
openstack server show es-node-1 -c status        # astepti VERIFY_RESIZE
openstack server resize confirm es-node-1
```

## Pasul 2 — utilizatorul tiberiu pe ambele VM-uri (elastic-lab vechi)

Serviciile folosesc /home/tiberiu/lab, iar regulile auditd urmaresc /home/tiberiu/.ssh.
Imaginile Ubuntu vin cu utilizatorul `ubuntu` si cheia lab-key.

```
ssh ubuntu@172.30.6.106 hostname
ssh ubuntu@172.30.6.249 hostname
```

Daca nu intra, cheia lab-key nu e pe elastic-lab vechi: rulezi pasul de pe masina care o are.

```
for h in 172.30.6.106 172.30.6.249; do
  ssh ubuntu@$h 'sudo adduser --disabled-password --gecos "" tiberiu && sudo usermod -aG sudo tiberiu &&
    sudo install -d -m 700 -o tiberiu -g tiberiu /home/tiberiu/.ssh &&
    sudo install -m 600 -o tiberiu -g tiberiu ~/.ssh/authorized_keys /home/tiberiu/.ssh/authorized_keys'
  cat ~/.ssh/id_ed25519.pub | ssh ubuntu@$h 'sudo tee -a /home/tiberiu/.ssh/authorized_keys >/dev/null'
done
ssh -t ubuntu@172.30.6.106 'sudo passwd tiberiu'
ssh ubuntu@172.30.6.249 'echo "tiberiu ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/tiberiu && sudo chmod 440 /etc/sudoers.d/tiberiu'
ssh tiberiu@172.30.6.106 hostname
ssh tiberiu@172.30.6.249 'hostname; sudo -n true && echo sudo-ok'
```

web-prod primeste sudo fara parola (harness-ul ruleaza `sudo` prin ssh, ca pe vechi);
es-node-1 primeste parola (ca elastic-lab vechi). Hostname-ul lui web-prod trebuie sa fie `web-prod`.

## Pasul 3 — es-node-1: pachete si chei

```
ssh tiberiu@172.30.6.106
```

Pe es-node-1:

```
sudo apt-get update
sudo apt-get install -y ca-certificates curl git python3-venv autossh
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $UBUNTU_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker tiberiu
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-elasticsearch.conf
sudo sysctl --system
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519
cat ~/.ssh/id_ed25519.pub
exit
```

Cheia afisata o adaugi in GitHub (Settings -> SSH and GPG keys). Inapoi pe elastic-lab vechi,
o pui pe web-prod nou si pe GPU (contul tau de acolo; tunelul spre Ollama o foloseste):

```
ssh tiberiu@172.30.6.106 cat .ssh/id_ed25519.pub | ssh tiberiu@172.30.6.249 'cat >> ~/.ssh/authorized_keys'
ssh tiberiu@172.30.6.106 cat .ssh/id_ed25519.pub | ssh tiberiu@172.30.6.231 'cat >> ~/.ssh/authorized_keys'
ssh tiberiu@172.30.6.106 'ssh -o StrictHostKeyChecking=accept-new tiberiu@192.168.10.138 hostname; ssh -o StrictHostKeyChecking=accept-new tiberiu@172.30.6.231 hostname'
```

Ultima comanda afiseaza `web-prod` si numele GPU-ului. Daca GPU-ul nu raspunde: stop,
tunelul trebuie facut altfel.

## Pasul 4 — oprirea laboratorului vechi si arhivele (elastic-lab vechi)

De aici laboratorul vechi e oprit.

```
cd ~/lab && source env.sh
curl -s -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/_cat/indices?h=index,docs.count&s=index" > ~/indici-inainte.txt
sudo systemctl stop soc-tier3.timer soc-orchestrator
docker compose stop
sudo systemctl stop elastic-agent
ssh -t tiberiu@172.20.99.240 'sudo systemctl stop elastic-agent'
docker run --rm -v lab_esdata:/v -v ~/:/b debian tar czf /b/esdata.tgz -C /v .
tar czf ~/lab-local.tgz -C ~/lab env.sh soc.env .env data
tar czf ~/claude.tgz -C ~ claude
cd ~ && sha256sum esdata.tgz lab-local.tgz claude.tgz > sume.txt
scp ~/esdata.tgz ~/lab-local.tgz ~/claude.tgz ~/sume.txt ~/indici-inainte.txt tiberiu@172.30.6.106:~
```

## Pasul 5 — es-node-1: restaurare si adrese noi

```
ssh tiberiu@172.30.6.106
```

Pe es-node-1:

```
cd ~ && sha256sum -c sume.txt
git clone git@github.com:tibica2004/Parallel-soc-lab.git ~/lab
tar xzf ~/lab-local.tgz -C ~/lab
chmod 600 ~/lab/env.sh ~/lab/soc.env ~/lab/.env
tar xzf ~/claude.tgz -C ~
cd ~/lab
sed -i 's/^HOST_IP=.*/HOST_IP=192.168.10.121/' .env
sed -i 's/^export WEB_PROD_HOST=.*/export WEB_PROD_HOST=tiberiu@192.168.10.138/' env.sh
printf '\n# OpenStack: adresele noi\nexport WP_SSH_TARGET=tiberiu@192.168.10.138\nexport WP_SELF_IPS=192.168.10.138,172.30.6.249,127.0.0.1,::1\nexport LABEL_UI_HOST=192.168.10.121\n' >> env.sh
grep -E "HOST_IP|WEB_PROD|WP_|LABEL_UI_HOST" .env env.sh
docker volume create lab_esdata
docker run --rm -v lab_esdata:/v -v ~/:/b debian tar xzf /b/esdata.tgz -C /v
docker compose up -d
sleep 120
python3 -m venv venv && venv/bin/pip install -r requirements.txt
source env.sh
curl -s -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/_cluster/health?pretty" | grep status
curl -s -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/_cat/indices?h=index,docs.count&s=index" > ~/indici-dupa.txt
diff ~/indici-inainte.txt ~/indici-dupa.txt && echo IDENTIC
python3 -m pytest -q tests
free -m | head -2
exit
```

Asteptat: OK la sume, `green`/`yellow`, IDENTIC (sau diferente mici la indici de sistem),
`693 passed`. Ubuntu 24.04 are Python 3.12 (vechiul avea 3.13): daca `pip install` da eroare, stop.
`free -m`: daca "available" e sub ~1 GB, e nevoie de flavor mai mare (pasul 1).

## Pasul 6 — Kibana si Fleet Server

De pe calculatorul tau, prin elastic-lab vechi (singurul permis de es-sg pe 22):

```
ssh -J tiberiu@172.20.99.220 -L 5601:localhost:5601 tiberiu@172.30.6.106
```

In http://localhost:5601:
1. Fleet -> Settings: Fleet Server host `http://192.168.10.121:8220` si output `http://192.168.10.121:9200`
   (vin din HOST_IP). Daca apare tot 172.20.99.220, le corectezi acolo.
2. Fleet -> Add Fleet Server -> copiezi comanda generata si o rulezi in fereastra SSH deschisa.
3. Astepti "Healthy". Fleet -> Enrollment tokens -> copiezi tokenul politicii web-prod (pasul 9).

## Pasul 7 — arhivele de pe web-prod vechi (elastic-lab vechi)

`.env.bak` e momeala: tar n-are voie s-o citeasca (alerta honeytoken prin auditd); o replantezi la pasul 10.

```
ssh -t tiberiu@172.20.99.240 'sudo tar czf /tmp/www.tgz -C /var/www --exclude=html/.env.bak html && sudo mysqldump --single-transaction wp | gzip > /tmp/wp.sql.gz && sudo tar czf /tmp/etc.tgz /etc/apache2/sites-available/000-default.conf /etc/suricata/suricata.yaml /etc/suricata/threshold.config /etc/cron.d/soc-canary && sudo cp /usr/local/bin/wp /tmp/wp-cli && sudo chown tiberiu /tmp/www.tgz /tmp/wp.sql.gz /tmp/etc.tgz /tmp/wp-cli'
mkdir -p ~/web && scp tiberiu@172.20.99.240:/tmp/{www.tgz,wp.sql.gz,etc.tgz,wp-cli} ~/web/
cd ~/web && sha256sum www.tgz wp.sql.gz etc.tgz wp-cli > sume-web.txt
scp ~/web/* tiberiu@172.30.6.249:/tmp/
```

## Pasul 8 — web-prod nou: WordPress si senzori

```
ssh tiberiu@172.30.6.249
```

Pe web-prod (Ubuntu 24.04: PHP 8.3 in loc de 8.4, Suricata 7.0.x din Ubuntu):

```
cd /tmp && sha256sum -c sume-web.txt
sudo apt-get update
sudo apt-get install -y apache2 libapache2-mod-php php php-mysql php-cli mariadb-server suricata suricata-update yara curl
sudo tar xzf /tmp/www.tgz -C /var/www
sudo install -m 755 /tmp/wp-cli /usr/local/bin/wp
DBPASS=$(sudo sed -n "s/.*'DB_PASSWORD', *'\([^']*\)'.*/\1/p" /var/www/html/wp-config.php)
sudo mysql -e "CREATE DATABASE wp; CREATE USER 'wp'@'localhost' IDENTIFIED BY '$DBPASS'; GRANT ALL ON wp.* TO 'wp'@'localhost'; FLUSH PRIVILEGES;"
unset DBPASS
zcat /tmp/wp.sql.gz | sudo mysql wp
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.ubuntu
sudo tar xzf /tmp/etc.tgz -C /
sudo systemctl restart apache2
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/
sudo -u www-data wp --path=/var/www/html core version
```

Asteptat: `200`, apoi `7.1.3`.

Suricata: interfata noua si IP-ul nou al lui ES (bpf-filter si threshold.config):

```
IFACE=$(ip -o -4 addr show | awk '/192\.168\.10\.138/{print $2}'); echo $IFACE
sudo sed -i "s/- interface: enp0s3/- interface: $IFACE/" /etc/suricata/suricata.yaml
sudo sed -i 's/172\.20\.99\.220/192.168.10.121/g' /etc/suricata/suricata.yaml /etc/suricata/threshold.config
grep -n "interface: $IFACE\|192.168.10.121" /etc/suricata/suricata.yaml /etc/suricata/threshold.config
suricata --build-info | grep -i -E "^This is|ja4"
sudo suricata-update
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo systemctl enable suricata
sudo systemctl restart suricata
free -m | head -2
```

Daca `suricata -T` da eroare (fisierul vine de la 7.0.10, Ubuntu are alta versiune) sau
`--build-info` nu arata JA4: stop si trimite iesirea. Revenire:
`sudo cp /etc/suricata/suricata.yaml.ubuntu /etc/suricata/suricata.yaml` + modificarile din deploy/web-prod/suricata.md.

Canarul si audit=1:

```
sudo cp /usr/bin/true /usr/local/bin/soc-canary
sudo chmod 644 /etc/cron.d/soc-canary
echo 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit=1"' | sudo tee /etc/default/grub.d/99-audit.cfg
sudo update-grub
sudo reboot
```

## Pasul 9 — web-prod nou: Elastic Agent

```
ssh tiberiu@172.30.6.249
grep -o audit=1 /proc/cmdline
systemctl is-active suricata apache2 mariadb
cd /tmp
curl -LO https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.5.1-linux-x86_64.tar.gz
tar xzf elastic-agent-9.5.1-linux-x86_64.tar.gz
cd elastic-agent-9.5.1-linux-x86_64
sudo ./elastic-agent install --url=http://192.168.10.121:8220 --enrollment-token=<TOKEN de la pasul 6> --insecure
exit
```

## Pasul 10 — es-node-1: YARA, honeytokens, verificarea datelor

```
ssh tiberiu@172.30.6.106
cd ~/lab
scp -r deploy/web-prod/yara tiberiu@192.168.10.138:/tmp/soc-yara
ssh -t tiberiu@192.168.10.138 'sudo bash /tmp/soc-yara/install.sh && rm -rf /tmp/soc-yara'
scp deploy/web-prod/honeytokens.sh tiberiu@192.168.10.138:/tmp/
ssh -t tiberiu@192.168.10.138 'sudo bash /tmp/honeytokens.sh && rm /tmp/honeytokens.sh'
```

Dupa ~10 minute:

```
source env.sh
for i in 'logs-endpoint.events.*' 'logs-apache.*' 'logs-suricata.eve-*' 'logs-auditd_manager.*'; do printf "%-28s " "$i"; curl -s -H "Authorization: ApiKey $ES_API_KEY" -H 'Content-Type: application/json' "$ES_URL/$i/_count" -d '{"query":{"bool":{"filter":[{"term":{"host.name":"web-prod"}},{"range":{"@timestamp":{"gte":"now-15m"}}}]}}}'; echo; done
python3 canary_check.py
python3 wp_inventory.py arata
```

Asteptat: toate patru contoarele > 0, canarul vazut, core 7.1.3.
In Kibana -> Fleet: web-prod vechi si Fleet Server vechi apar offline -> Unenroll.

## Pasul 11 — GPU, servicii, porti (es-node-1)

```
bash deploy/install.sh
bash deploy/install-tier3.sh
sleep 10
curl -s localhost:11434/api/tags | grep -o qwen3:14b
systemctl is-active soc-llm-tunnel soc-orchestrator soc-tier3.timer
SHADOW_MODE=true python3 orchestrator.py --minutes 60
python3 tier3.py --once --expunere
```

Portile (lente; nohup ca sa continue dupa iesirea din ssh):

```
nohup bash -c 'source env.sh;
  SCENARIOS=scenarios_fast.yml VERBOSE=1 python3 -u harness.py > results/migrare-fast.txt 2>&1;
  SCENARIOS=scenarios.yml VERBOSE=1 python3 -u harness.py > results/migrare-dev.txt 2>&1;
  SCENARIOS=scenarios_validation.yml VERBOSE=1 python3 -u harness.py > results/migrare-val.txt 2>&1' >/dev/null 2>&1 &
tail -f results/migrare-fast.txt
```

Referinta: fast 4/4, dev 14/14 (recall 100%), validare 8/8. Baseline-ul vechi descrie web-prod
pe Debian; pe Ubuntu apar procese noi (snapd, cloud-init, unattended-upgrades), deci in primele zile
pot aparea findings rare noi. O regresie se raporteaza; nu se ajusteaza scenariile sau pragurile.

## Pasul 12 — dupa ce trec portile

- Opresti VM-urile vechi in VirtualBox (exportate ca OVA); nu le stergi cateva saptamani si nu le
  pornesti in paralel cu cele noi.
- Regulile din es-sg / victim-sg / attacker-sg permit 172.20.99.220: cand dispare elastic-lab vechi,
  le inlocuiesti cu IP-ul tau (comenzile se pregatesc atunci).
- Stergi arhivele (esdata.tgz, lab-local.tgz cu secretele, ~/web) de pe elastic-lab vechi.
- Actualizezi CLAUDE.md (Infrastructura) cu adresele noi.

# Roadmap de intelegere: de la OpenStack la verdict

Scop: sa parcurgi laboratorul in ordinea in care curg datele, de la masinile din OpenStack
pana la verdictul scris in Elasticsearch. Fiecare pas are: ce exista, cum verifici singur
(comenzi read-only), unde e codul/documentul si o intrebare de control. Nu modifici nimic;
toate comenzile de aici sunt citire.

Starea e cea de la 2026-11-05 (verificata cu `openstack server list`, `openstack security
group rule list` si `systemctl list-timers` pe es-node-1). Rezumatul scurt al proiectului
e `docs/pasi/REZUMAT.md`; jurnalul cronologic `docs/pasi/stare.md`; arhitectura tinta
`docs/arhitectura.md`.

Ordinea pasilor:

```
0. de unde lucrezi            (boxa veche, IP-uri flotante)
1. OpenStack: retele          (es-net, attacker-net, public, routere, SNAT)
2. OpenStack: masini          (5 VM, flavor, rol)
3. OpenStack: security groups (cine vorbeste cu cine, strat 1)
4. firewall nft pe hosturi    (strat 2, independent de OpenStack)
5. es-node-1: stiva Elastic   (Docker ES + Kibana, Fleet Server, indici, chei)
6. web-prod: senzorii         (Defend, auditd, Suricata, Apache, momeli -> Fleet -> ES)
7. Kibana: detectia           (reguli native + soc-*; .alerts-security.alerts-*)
8. es-node-1: orchestratorul  (ciclul de 120 s, dedup, coada, mod degradat)
9. Tier 1: triajul            (fast_path.py)
10. Tier 2: investigatia      (hunt_path.py, policy.decide, shadow)
11. Tier 3: programatul       (tier3.py pe timer orar + expunere)
12. celelalte timere          (absence, llm_probe, nday, static, fp_rate, backup, readiness)
13. memoria si omul           (indici proprii, label_ui, dashboard, Discord)
14. atacator + benign-gen + lab-sink (cum generezi semnal si zgomot)
15. harness-ul si portile     (cum stii ca merge)
```

---

## Pasul 0. De unde lucrezi si cum ajungi la masini

- Sesiunea ta (si Claude) ruleaza pe **elastic-lab vechi** (VirtualBox, 172.20.99.220).
  Reteaua privata OpenStack 192.168.10.0/24 **nu e rutabila** de aici; masinile le atingi
  numai prin IP-urile flotante 172.30.6.x.
- Boxa veche e singura sursa permisa pe SSH in es-sg / victim-sg / attacker-sg
  (regula `172.20.99.220/32 tcp 22`). Daca o pierzi, nu mai intri pe nimic in afara de
  benign-gen (care accepta si laptopul 192.168.62.206). E un punct unic de esec documentat.
- Credentialele OpenStack sunt in `~/.config/openstack/clouds.yaml`; CLI-ul `openstack` merge
  de pe boxa veche.

Verifica:
```
openstack server list --long -c Name -c Status -c Networks -c Flavor
ssh tiberiu@172.30.6.106 hostname     # es-node-1
ssh tiberiu@172.30.6.249 hostname     # web-prod
ssh ubuntu@172.30.6.210 hostname      # benign-gen
ssh -J tiberiu@172.30.6.106 ubuntu@192.168.10.160 hostname   # lab-sink (fara flotant)
```
Intrebare de control: de ce lab-sink se atinge doar prin es-node-1 (jump)? Raspuns: nu are
IP flotant si lab-sink-sg permite 22 doar de la es-node-1 si web-prod.

Documente: `docs/migrare.md` (cum s-a construit), `docs/pasi/stare.md` sectiunea
"2026-10-29 acces de pe boxa veche".

---

## Pasul 1. OpenStack: retelele

Trei retele, doua routere:

| Retea | Subnet | Gateway | Cine e in ea | Router |
|---|---|---|---|---|
| es-net | 192.168.10.0/24 | 192.168.10.1 | es-node-1 .121, web-prod .138, benign-gen .150, lab-sink .160 | router1 |
| attacker-net | 10.10.0.0/24 | 10.10.0.1 | atacator .220 | attacker-router |
| public | 172.30.6.0/24 | 172.30.6.254 | IP-urile flotante + GPU-ul 172.30.6.231 + boxa veche vede aici | (extern) |

Consecinte de inteles (astea explica multe "ciudatenii" din loguri):

1. **Atacatorul nu e in es-net.** Ajunge la web-prod doar prin IP-ul flotant 172.30.6.249
   si trece prin SNAT pe attacker-router. Pe web-prod, `source.ip` al atacatorului apare ca
   **172.30.6.133** (flotantul lui), nu 10.10.0.220. De aici: readiness c2 nu poate trece
   (172.30.6.133 e privat, deci "protejat"), never_block e lista de IP-uri, iar c9 (SNAT unic)
   e imposibil in topologia asta.
2. **GPU-ul (172.30.6.231) nu e in OpenStack.** E o masina fizica in reteaua publica a
   flotantelor. es-node-1 si atacatorul ajung la el doar pentru ca au flotante; lab-sink nu are.
   Modelul se consuma prin tunel SSH, nu direct (vezi pasul 5).
3. **MTU 1442 pe es-net** (overlay OVN): explica rafala de "IPv4 truncated packet" din Suricata
   la migrare.
4. Porturile DOWN 192.168.10.2 / 10.10.0.2 sunt porturile distribuite OVN; normale.

Verifica:
```
openstack network list; openstack subnet list; openstack router list; openstack floating ip list
```

---

## Pasul 2. OpenStack: masinile

| VM | Flavor | es-net / flotant | Rol intr-o fraza |
|---|---|---|---|
| es-node-1 | m1.xlarge (16 GB) | 192.168.10.121 / 172.30.6.106 | creierul: ES + Kibana + Fleet Server + orchestrator + 10 timere SOC |
| web-prod | m1.medium | 192.168.10.138 / 172.30.6.249 | victima instrumentata: WordPress + toti senzorii + 6 timere de igiena |
| atacator | m1.xlarge | 10.10.0.220 / 172.30.6.133 | sursa de semnal: OpenClaw/OpenCyber, ajunge DOAR pe web-prod:80 |
| benign-gen | m1.small | 192.168.10.150 / 172.30.6.210 | sursa de zgomot bun: Playwright pe WordPress, scrie benign-ground-truth |
| lab-sink | m1.small | 192.168.10.160 / fara | tinta pasiva pentru testele ART de miscare laterala; nu ruleaza nimic |

Toate: Ubuntu 24.04 (imaginea "Ubuntu Noble"), cota vCPU 20/20 (plina: nu mai poti crea VM-uri
fara sa micsorezi una), RAM 40/50 GB, zero volume (totul e pe discul efemer al VM-ului).
Backup-ul web-prod sta pe es-node-1 (un singur disc, fara copie off-host: abatere cunoscuta).

Utilizatori: `tiberiu` pe es-node-1 (sudo cu parola) si web-prod (sudo fara parola, cerut de
harness), `ubuntu` pe benign-gen si lab-sink. Cheia OpenStack e `lab-key`.

Verifica: `openstack server show es-node-1 -c flavor -c addresses -c status`.

Intrebare de control: de ce atacatorul are m1.xlarge daca foloseste 1.4 GB? Pentru OpenClaw
cu Node; propunerea din audit (2026-11-03) e sa-l cobori la m1.large ca sa eliberezi 4 vCPU.

---

## Pasul 3. OpenStack: security groups (stratul 1 de filtrare)

Security group-urile sunt filtrul de la hipervizor; se aplica inainte ca pachetul sa ajunga
pe VM. Starea reala la 2026-11-05 (dupa B.7 din pasul 13):

```
es-sg (es-node-1)
  22   <- 172.20.99.220 (boxa veche)
  5601 <- 172.20.99.220
  9200 <- 192.168.10.138 (web-prod, output Fleet), 192.168.10.150 (benign-gen)
  8220 <- 192.168.10.138 (web-prod, Fleet Server)

victim-sg (web-prod)
  22   <- 172.20.99.220, 192.168.10.121 (es-node-1: harness, enrich, backup pull)
  80   <- 192.168.10.121, 192.168.10.150, 172.30.6.133 (atacator, prin flotant)
  443  <- 192.168.10.150

attacker-sg (atacator)
  22   <- 172.20.99.220

benign-sg (benign-gen)
  22   <- 172.20.99.220, 192.168.62.206 (laptop)

lab-sink-sg (lab-sink)
  22, 80, 8080, icmp <- 192.168.10.138 (web-prod = sursa testelor ART)
  22                 <- 192.168.10.121 (administrare din es-node-1)
```

Toate au egress liber. Observa:
- lab-sink **nu** vede ES (9200/8220): e tinta, nu client. Asta a fost restrans pe 2026-11-04.
- Portul 80 de la atacator spre web-prod e **deschis acum** (regula 172.30.6.133/32:80).
  Conform CLAUDE.md, se inchide cat timp ruleaza harness-ul (GPU partajat + zgomot).
- Nimic din attacker-net nu ajunge la es-node-1 sau la GPU.

Verifica:
```
for sg in es-sg victim-sg attacker-sg benign-sg lab-sink-sg; do echo "## $sg"; \
  openstack security group rule list $sg -c "IP Protocol" -c "IP Range" -c "Port Range" -c Direction -f value; done
```

Intrebare de control: de ce es-sg permite 9200 doar de la doua IP-uri daca ES e in Docker?
Pentru ca Docker publica 9200 pe host; SG-ul taie la hipervizor, nft-ul (pasul 4) taie la host.

---

## Pasul 4. Firewall nft pe hosturi (stratul 2, independent de OpenStack)

Pe es-node-1 si web-prod exista un tabel nft **propriu**, `inet soc_fw`, incarcat de
`soc-fw.service` din `/etc/soc/soc-fw.nft`. Sursa in repo: `deploy/es-node-1/soc-fw.nft`,
`deploy/web-prod/soc-fw.nft`. Nu foloseste `nftables.service` (care ar face `flush ruleset`
si ar sterge regulile Docker). Rollback = `nft delete table inet soc_fw`.

es-node-1:
- `input` policy drop: lo, established, ICMP, DHCP, interfetele Docker; 22 si 8088 (label_ui)
  doar din `admin_v4` = {172.20.99.220, 192.168.62.206}; 8220 din 192.168.10.0/24.
- `forward_guard`: 9200/5601 sunt publicate de Docker si trec prin FORWARD (DNAT), nu INPUT.
  De aceea lantul asta dropeaza conexiunile noi pe 9200 care nu vin din `es_clients_v4`
  = {web-prod, benign-gen}, pe 5601 care nu vin din admin_v4, si tot IPv6 pe 9200/5601.

web-prod:
- `input` policy drop: 80/443 oricine; 22 doar es-node-1 si admin_v4.
- Suricata (af-packet) vede pachetele **inainte** de netfilter: ce blocheaza nft ramane
  vizibil senzorului.

Important pentru principiul 4 (shadow): setul `blocked_v4` (pasul 9, block_ip_ttl) trebuie sa
fie **gol** cat timp SHADOW_MODE=true. Conditie de oprire daca nu e.

Verifica (read-only, cere sudo):
```
ssh -t tiberiu@172.30.6.106 'sudo nft list table inet soc_fw'
ssh -t tiberiu@172.30.6.249 'sudo nft list table inet soc_fw'
```
Documente: `docs/pasi/pas-00.md` (0.3).

---

## Pasul 5. es-node-1: stiva Elastic

Ce ruleaza (verificat 2026-11-05 07:31 UTC):

```
docker: es01   elasticsearch:9.5.1   healthy     (port 9200, heap 4 GB, single-node, licenta basic)
        kibana kibana:9.5.1                      (port 5601)
host:   elastic-agent 9.5.1 ca Fleet Server      (HTTP pe 0.0.0.0:8220, --fleet-server-insecure-http)
        soc-llm-tunnel (autossh -L 11434:localhost:11434 tiberiu@172.30.6.231)
        soc-orchestrator (shadow fortat)
        + timerele din pasul 12
```

Lucruri de stiut:
- `docker-compose.yml` ridica ES + Kibana; volumele `esdata` (date) si `essnapshots` (depozit
  SLM `soc_local`, snapshot zilnic `soc-daily` la 02:00 UTC, 30 zile). Secretele vin din `.env`
  (HOST_IP, parole). HOST_IP=192.168.10.121 alimenteaza Fleet Server hosts si output-ul Fleet.
- **Stiva nativa 9.5.5** din apt exista pe host dar e dezactivata (`systemctl disable --now
  elasticsearch kibana`); daca cineva o porneste, ocupa 9200/5601.
- Fleet Server pe HTTP (nu TLS) pentru ca compose cere `http://...:8220`; agentii se
  inroleaza cu `--insecure`.
- **Modelul**: Ollama qwen3:14b ruleaza pe GPU (172.30.6.231, 0.0.0.0:11434) si se vede pe
  es-node-1 ca `localhost:11434` prin tunel. Acelasi model il folosesc Tier 1, Tier 2,
  harness-ul si OpenClaw de pe atacator (prin propriul tunel `openclaw-llm-tunnel`).
  GPU-ul e partajat: nu rula OpenClaw in timpul harness-ului. Daca `nvidia-smi` da
  "driver/library mismatch", Ollama cade pe CPU si totul da timeout (cazul B.1 din 2026-11-04).
- Alegerea modelului per rol: `llm.py` citeste `MODEL_<ROL>` / `LLM_BASE_URL_<ROL>`.

Indicii (cine scrie, cu ce cheie):

| Indice | Scrie | Cheie |
|---|---|---|
| logs-* (data streams) | Fleet / Elastic Agent de pe web-prod, benign-gen | token Fleet |
| .alerts-security.alerts-* | Kibana (regulile de detectie) | intern |
| verdicts-history, soc-audit, soc-traces, soc-state | orchestrator | ES_WRITER_API_KEY |
| soc-incidents, soc-hunts | tier3, nday_watch | ES_WRITER / ES_INCIDENTS_WRITER |
| soc-metrics | orchestrator (cycle), llm_probe, absence_check, nday, static, fp_rate | ES_METRICS_WRITER |
| asset-vulns | nday_watch | ES_VULNS_WRITER |
| static-findings | static_triage | ES_STATIC_WRITER |
| soc-wp-inventory, asset-inventory | wp_inventory.py / om | ES_WRITER / elastic |
| benign-ground-truth | benign-gen | ES_BENIGN_WRITER (doar create_doc) |
| soc-cases | orchestrator (upsert) + label_ui | ES_WRITER |
| baseline-entity-parentchild | build_whitelists / baseline | om |

Chei: fiecare scoped, fara delete/manage; ES_API_KEY = citire ingusta (nu vede soc-metrics,
soc-incidents), ES_READER_API_KEY = citire larga, ES_MONITOR = doar cluster:monitor. Valorile
sunt in `soc.env` pe es-node-1 (nu le afisa). Rotatie la 90 zile, prima pe 2027-01-06.
Indicii si cheile noi le creeaza omul cu contul elastic (`deploy/es-node-1/*-setup.sh`);
codul nu foloseste niciodata contul elastic.

Verifica:
```
ssh tiberiu@172.30.6.106 'docker ps; systemctl is-active soc-orchestrator soc-llm-tunnel elastic-agent'
ssh tiberiu@172.30.6.106 'cd ~/lab && source env.sh && curl -s -H "Authorization: ApiKey $ES_API_KEY" "$ES_URL/_cluster/health?pretty" | grep status'
ssh tiberiu@172.30.6.106 'curl -s localhost:11434/api/tags | grep -o qwen3:14b'
```
Kibana: `ssh -J tiberiu@172.20.99.220 -L 5601:localhost:5601 tiberiu@172.30.6.106` apoi
http://localhost:5601.

Intrebare de control: de ce orchestratorul nu poate sterge un indice chiar daca ar vrea?
Pentru ca ES_WRITER_API_KEY nu are privilegiul `delete_index`/`manage`; limitarea e in cheie,
nu in cod (principiul "codul decide" are si un strat de infrastructura sub el).

---

## Pasul 6. web-prod: senzorii si drumul telemetriei spre ES

web-prod e o masina "normala" (Apache 2.4 + PHP 8.3 + MariaDB + WordPress 7.1.3) peste care
s-au pus senzori. Regula R16: web-prod **nu are niciun secret al SOC-ului** (nici chei ES,
nici SSH spre es-node-1). Tot ce produce local merge in `/var/log/soc/*.ndjson` si de acolo il
ridica Elastic Agent.

Senzorii si data stream-ul in care ajung:

| Senzor | Ce vede | Data stream |
|---|---|---|
| Elastic Defend (eBPF) | procese, fisiere, retea, + alerte native (malware, comportament) | logs-endpoint.events.{process,file,network}-* |
| auditd_manager (audit=1 la boot, reguli imuabile) | syscall-uri pe fisiere sensibile (/etc/shadow, momeli) | logs-auditd_manager.auditd-* |
| Suricata 7.0.17 (OISF, JA4, ET Open, af-packet pasiv) | alerte retea, flows, HTTP, TLS; hostul in observer.hostname, nu host.name | logs-suricata.eve-* |
| Apache access/error | fiecare cerere HTTP (inclusiv recon, momeli web) | logs-apache.access-* |
| ModSecurity CRS (DetectionOnly) | anomalii pe cereri, nu blocheaza | prin Apache error log |
| system (auth, syslog) | SSH, sudo, cron | logs-system.auth-*, logs-system.syslog-* |
| soc-sbom.sh (03:00) | inventarul componentelor (apache, php, wp core, plugin-uri) | logs-soc.sbom-* |
| YARA (soc-yara-scan, la 10 min + la creare in webroot) | potriviri noi de reguli webshell/injector | jurnal -> regula soc-yara-webshell |
| AIDE (03:30) | schimbari de integritate pe sistem | jurnal -> soc-aide-change |
| soc-reader gate | cele 11 comenzi permise de pe es-node-1 cu cheia soc-reader; refuzurile sunt alerte | logs -> soc-reader-denied |
| canar (cron la 5 min: /usr/local/bin/soc-canary) | o executie de proces "sigur" ca puls al telemetriei | logs-endpoint.events.process-* |

Momelile (honeytokens, 10): `/var/www/html/.env.bak` (citirea = alerta auditd), caile web
`/.env.bak`, `/admin.old.php`, capcane in robots.txt, backup SQL fals, utilizatorul inexistent
`svc_deploy`, cont MySQL momeala, wp-config read. Orice atingere escaladeaza mereu (motiv
HONEYTOKEN in `should_escalate`). Nu le atinge decat ca test.

Timere de igiena pe web-prod (toate fara chei SOC):

| Ora (UTC) | Timer | Ce face |
|---|---|---|
| 01:30 | soc-backup | baza wp + grants + webroot + /etc/apache2,/etc/php, sha256, 14 zile |
| 02:00 | soc-wp-update | mod raport (APPLY=0): doar spune ce update-uri exista |
| 02:30 | soc-suricata-update | regulile ET Open |
| 03:00 | soc-sbom | inventarul -> /var/log/soc/sbom.ndjson |
| 03:30 | soc-aide-check | integritate |
| la 10 min | soc-yara-scan | webroot |
| */5 min (cron) | soc-canary | pulsul telemetriei |

Drumul unui eveniment: proces pe web-prod -> Defend/auditd/Suricata/Apache -> Elastic Agent
(politica Fleet web-prod) -> output Fleet http://192.168.10.121:9200 -> data stream logs-* ->
(pasul 7) regulile Kibana -> alerta.

Fals pozitive zilnice cunoscute (de decis de om, nu "reparate" din praguri): `lsb_release -i -s`
din unattended-upgrade (regula Reverse shell), `soc-wp-update.py` la 02:00 (binar nevazut ->
malicious/95), sendmail WordPress in regula nativa RCE.

Verifica (de pe es-node-1, fara sa atingi web-prod):
```
ssh tiberiu@172.30.6.106 'cd ~/lab && source env.sh && for i in logs-endpoint.events.* logs-apache.* logs-suricata.eve-* logs-auditd_manager.*; do printf "%-28s " $i; curl -s -H "Authorization: ApiKey $ES_API_KEY" -H "Content-Type: application/json" "$ES_URL/$i/_count" -d "{\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"now-15m\"}}}}"; echo; done'
ssh tiberiu@172.30.6.106 'cd ~/lab && source env.sh && python3 absence_check.py'
```
Documente: `deploy/web-prod/README.md`, `deploy/web-prod/suricata.md`, `auditd-fim.md`,
`docs/pasi/pas-00.md`, `pas-01.md` (SBOM), `pas-03*.md` (senzori 0-day).

Intrebare de control: de ce Suricata ramane util chiar daca nft blocheaza un IP? Pentru ca
af-packet vede pachetul inainte de netfilter.

---

## Pasul 7. Kibana: detectia (de la loguri la alerte)

Regulile de detectie ruleaza in Kibana si scriu in `.alerts-security.alerts-*`. Asta e
singurul loc din care orchestratorul citeste "alerte". Categorii:

1. **Reguli native Elastic** (prebuilt, EQL/KQL) + alertele native Defend (ML malware,
   comportament, memorie), normalizate de `defend_native.py` inainte de Tier 1.
2. **Reguli comportamentale proprii, fara semnatura** (`behavioral_rules.py`, 9): web ->
   shell (`soc-web-spawns-shell`), PHP scris in webroot, www-data executa binar nevazut
   (lista alba din baseline: `data/behavioral-whitelists.json`), outbound nou, scriere in afara
   webroot, apache citeste /etc/shadow, fisiere sensibile, conturi/cron, SUID/capabilities.
3. **Reguli de senzor** (`sensor_rules.py`): `soc-yara-webshell`, `soc-suricata-webattack`,
   `soc-aide-change`, `soc-reader-denied`, `soc-modsec-anomaly`. Escaladeaza mereu
   (SENSOR_DETECTION), dar **fara podea de verdict**: YARA/ET pot fi FP.
4. **Reguli honeytoken** (`honeytokens.py`, 6+): host/http/read/user, wp-login, mysql-user,
   backup-sql, wpconfig, robots-trap. Escaladeaza mereu, cu podea.
5. **Reguli pe trafic** (faza 16-17, 20): XSS, SQLi, traversal, enumerare continut,
   brute-force HTTP si SSH.
6. **Reguli Tier 3** (eticheta `tier3-generated`, spatiul Kibana tier3, shadow 7 zile, apoi
   promovare sau oprire automata). Singurele pe care codul le creeaza/dezactiveaza.

Regulile din 2-5 le creeaza **omul** cu `deploy/kibana/honeytoken_rules.py aplica` (contul
elastic, parola la tastatura); scriptul ia automat tot ce e definit in cod. Regulile noi stau
7 zile in `shadow-review` inainte sa conteze.

A doua sursa de "detectie" nu e in Kibana, ci in cod: **sweep-urile de raritate**
(`elastic_tools.run_full_sweep`, 16): new_parent_child, new_destinations, new_listening_ports,
new_url_paths, new_ja4, response_size_outliers, webroot_writes, web_enumeration, wp_recon_path,
suspicious_exec_path, new_executable, new_user, sbom_drift, beaconing, dns, entity_risk.
Compara ultima ora cu un baseline de 30 de zile si produc `RarityFinding`, care intra direct
in Tier 2 (nu trec prin Tier 1).

Verifica:
```
ssh tiberiu@172.30.6.106 'cd ~/lab && source env.sh && python3 deploy/kibana/honeytoken_rules.py verifica'
ssh tiberiu@172.30.6.106 'cd ~/lab && source env.sh && curl -s -H "Authorization: ApiKey $ES_API_KEY" -H "Content-Type: application/json" "$ES_URL/.alerts-security.alerts-*/_count" -d "{\"query\":{\"range\":{\"@timestamp\":{\"gte\":\"now-24h\"}}}}"'
```
Documente: `detections/*.md` (fise per detectie), `docs/detectii-oprite.md`, `docs/pasi/pas-03.md`.

Intrebare de control: care e diferenta dintre o alerta si un finding? Alerta = Kibana a
potrivit o regula -> Tier 1. Finding = codul a gasit o pereche noua fata de baseline -> Tier 2.

---

## Pasul 8. es-node-1: orchestratorul (bucla principala)

Serviciul `soc-orchestrator` (`deploy/soc-orchestrator.service`):

```
ExecStart=/usr/bin/env SHADOW_MODE=true venv/bin/python orchestrator.py \
          --loop --interval 120 --sweep-every 30 --hunt-limit 5 --limit 50
WatchdogSec=900   MemoryMax=2G   ProtectSystem=strict (scrie doar in data/)
```

SHADOW_MODE e fortat **in comanda**, deliberat: o linie `Environment=` ar fi suprascrisa de
`soc.env`. Iesirea din shadow cere modificarea acestei linii de catre om. Nu o atinge.

Un ciclu (`run_positioned`, la 120 s):

1. **Pozitia**: citeste cursorul din `soc-state` (`load_cursor`) si fereastra pana la
   acum minus lag (`window_end`). Nimic nu se pierde intre restarturi.
2. **Fetch**: ia alertele din `.alerts-security.alerts-*` intre cursor si fereastra
   (`fetch_alerts_between`, pana la FETCH_LIMIT=500).
3. **Dedup + plafon**: `take_until_cap` grupeaza alertele in cazuri (`group_alerts`: aceeasi
   regula + entitate), sare duplicatele vazute deja (`BoundedSeen`, persistat in soc-state cu TTL)
   si opreste la 50 de **cazuri noi** per ciclu; restul raman pentru ciclul urmator.
4. **Sanatatea modelului**: `degraded.llm_healthy("fast")`. Model cazut -> toate alertele
   escaladeaza fara verdict (principiul 8).
5. **Restanta**: daca numarul de cazuri noi depaseste BACKLOG_THRESHOLD, coada se ordoneaza
   dupa severitate si criticitatea activului; alertele critical escaladeaza direct fara model.
6. **process_alerts**: fiecare alerta -> Tier 1 (pasul 9) -> `should_escalate` -> daca
   escaladeaza si mai e buget (`--t2-limit 3`), devine `Case` prin `case_adapter` (fara verdictul
   Tier 1) si intra in Tier 2 (pasul 10); peste buget ramane escaladata la om
   (`tier2=skipped_budget`). Totul se scrie prin `persist`: verdicts-history, soc-audit,
   soc-traces, soc-cases.
7. **Cursor**: daca fereastra s-a golit avanseaza la capat; altfel la ultima alerta consumata.
8. **Metrici si integritate**: la fiecare 30 de cicluri `_metrics_snapshot`; la fiecare ciclu
   `_integrity_watch` (hash-ul canarului si al prompturilor; nepotrivire = conditie de oprire).
9. **Sweep**: la fiecare 30 de cicluri (~1 h) `run_full_sweep(1)` -> findings -> Tier 2
   (`--hunt-limit 5` per ciclu).
10. Un document `type=cycle` in soc-metrics + `WATCHDOG=1` spre systemd. Daca 15 min nu vine
    semnal, systemd il omoara si il reporneste.

Verifica:
```
ssh tiberiu@172.30.6.106 'journalctl -u soc-orchestrator --since "-30min" --no-pager | tail -40'
ssh tiberiu@172.30.6.106 'systemctl show soc-orchestrator -p NRestarts -p ActiveEnterTimestamp'
```
Rulare manuala, fara scriere: `SHADOW_MODE=true python3 orchestrator.py --minutes 60 --limit 5`.

Intrebare de control: de ce plafonul e pe cazuri si nu pe alerte? O rafala de 100 de alerte
de la un IP pe o regula e un singur caz; inainte, duplicatele consumau plafonul si bagau SOC-ul
in mod fara model (constatare 2026-11-03, restanta 2 h 40 min).

---

## Pasul 9. Tier 1: triajul (fast_path.py)

Graf LangGraph liniar, configurabil prin `FastConfig` (configuratiile A-D ale ablatiei):

```
prefetch -> [rag] -> [l1_agent <-> tools, max 3] -> pattern -> verdict -> finalize
```

- **prefetch / enrich** (`enrich.py`): faptele alertei (proces, parinte, user, command_line),
  activul (`lookup_asset`, criticitate, ferestre de mentenanta din `maintenance.py`), threat
  intel local (`kb/threat_intel.yml`), alertele corelate, istoricul pe regula (`lookup_history`).
  Telemetria e marcata ca DATE neincrezatoare in prompt (principiul 10, delimitata).
- **rag** (`rag.py`): cazuri etichetate de **om** (label_source=human) similare; azi sunt 2,
  deci RAG e aproape gol; masurat ca nu schimba acuratetea la 14B.
- **l1_agent** (`l1_agent.py`): modelul poate cere 3 unelte read-only (raritate, istoric,
  context proces). Masurat: dubleaza latenta, nu schimba acuratetea.
- **pattern**: reguli pe fapte (FACT_RULES), deterministe.
- **verdict**: JSON de la model -> `schemas.Verdict` (Pydantic, extra=forbid, enumerari
  inchise). Parsare esuata -> undetermined.
- **finalize**: **podelele** (cod): cont web care executa ceva (`web_exec_floor`), momeala,
  senzor, EDR nativ, actiune sensibila in afara ferestrei -> confidence minima si
  `floor_applied=True`. Modelul nu poate cobori sub podea.
- **should_escalate** (`escalation.py`): escaladeaza daca: nu e benign clar, confidence sub
  LOW_CONF=90, podea aplicata, motiv HONEYTOKEN / SENSOR_DETECTION / BEHAVIORAL / NATIVE,
  model cazut sau parsare esuata. Rezultatul e `EscalationDecision` cu **motive**, fara verdict.

Ce inchide Tier 1: doar benign clar, cu confidence >= 90, fara podea. Restul merge mai departe.

Teste pure: `tests/test_fast_path.py`, `test_escalation.py`, `test_l1_agent.py`, `test_injection.py`.

Intrebare de control: ce primeste Tier 2 de la Tier 1? Fapte, dovezi (`evidence_refs`) si
motivele escaladarii. **Nu** classification, confidence, narrative (principiul 7).

---

## Pasul 10. Tier 2: investigatia (hunt_path.py) si motorul de politici

Intrarea e un `Case` (origin: tier1_alert | rarity_sweep | tier3_hunt), construit de
`case_adapter.py`, cu `chain_id` comun cu Tier 1 (ca sa poti urmari lantul in audit).

```
primary (investigator_a) --[suport = 2]--> secondary (investigator_b) --> corroborate --> finalize --> decide()
                         --[altfel]-------------------------------------> corroborate
```

Fiecare investigator e un sub-graf: `seed` (faptele din entity_id, `execution_facts` cu ES|QL
parametrizat) -> `investigate` (model) <-> `tools` (max 12 apeluri: alerte recente pe host,
Suricata, raritate, istoric, auditd...) -> `conclude`. B ruleaza independent (nu vede
concluzia lui A). `corroborate` compara acord/dezacord; dezacord = confidence mai mica si
escaladare. Criticul e **oprit** (DISABLE_CRITIC=1, masurat daunator la 14B).

`policy.decide(verdict)` (`policy.py`):
- actiunile sunt enumerare inchisa (`ActionType`): none, enrich_only, block_ip_ttl,
  freeze_process, quarantine_file, isolate_host, kill_process, rotate_credentials, escalate_human;
- ireversibilele (kill_process, isolate_host, rotate_credentials) au prag 101: nu se aproba
  niciodata automat; `NEVER_BLOCK_PREFIXES` + lista never_block protejeaza IP-urile interne;
- in SHADOW_MODE, orice decizie se scrie in soc-audit cu `shadow=true` si nu se executa;
- `executor.py` construieste **planul** (pasi, rollback, expirare, criticitate, absolvire pe
  clase din etichete umane: >= 50, precizie >= 95%, 0 FN in 30 zile) si il pune in audit
  (`execution_plan`). Nu exista cod de executie reala.

Verifica un lant in audit:
```
ssh tiberiu@172.30.6.106 'cd ~/lab && source env.sh && curl -s -H "Authorization: ApiKey $ES_READER_API_KEY" "$ES_URL/soc-audit/_search?size=3&sort=@timestamp:desc&_source=chain_id,tier,action,shadow,escalation_reasons" | python3 -m json.tool'
```
Documente: `docs/standard-investigatie.md`, `docs/pasi/pas-06.md` (injectie), `pas-07.md`.

Intrebare de control: ce se intampla daca modelul raspunde cu un camp in plus in JSON?
Pydantic cu extra="forbid" refuza -> undetermined + escalate_human (principiile 2 si 8).

---

## Pasul 11. Tier 3: programatul (tier3.py)

`soc-tier3.timer` (orar) ruleaza patru comenzi in ordine, toate cu SHADOW_MODE=true:

1. `--ciclu-reguli --scrie-kibana`: regulile proprii in shadow -> promovare (prag atins) sau
   oprire (zgomotoase). Singura scriere in Kibana pe care o face codul, cu `KIBANA_TIER3_API_KEY`
   limitata la spatiul tier3 si eticheta tier3-generated.
2. `--ore 24 --scrie`: **incidente** (`incidents.py`): grupeaza verdictele din 24 h pe host +
   stramosi + timp, modelul scrie naratiunea kill chain, se deschide (nu se inchide niciodata)
   in soc-incidents.
3. `--reguli --ore 24 --doar-noi --scrie-kibana`: **propuneri de reguli EQL** (`rules.py`) pentru
   lanturile de atac fara regula (sursa: etichete umane de atac + Tier 2 malicious cu acord A/B);
   validate (sintaxa, prinde, zgomot; max 2 reincercari), apoi shadow 7 zile.
4. `--vanatoare --scrie`: **vanatoare ATT&CK** (`hunt.py`): 14 tehnici cu sabloane ES|QL scrise
   de om; codul alege 2 tehnici/ora (cele vanate cel mai demult), modelul scrie ipoteza si alege
   sablonul + fereastra (`HuntPlan` validat); potrivirile noi -> Case origin=tier3_hunt -> Tier 2
   (max 3/rulare); acoperirea (inclusiv negativa) in soc-hunts.

Separat, `soc-exposure.timer` (la 15 min): `tier3.py --expunere` coreleaza inventarul WordPress
(soc-wp-inventory) cu `kb/wp_vulns.yml` si cu atingerile Apache pe componentele vulnerabile
(faza 18): componenta vulnerabila instalata + recon pe ea = caz de incredere mare, devreme.

Iesirile JSON ale fiecarei rulari: `data/tier3/` pe es-node-1.

Verifica:
```
ssh tiberiu@172.30.6.106 'journalctl -u soc-tier3 --since "-2h" --no-pager | tail -30; ls -t ~/lab/data/tier3 | head'
```
Dry-run local: `python3 tier3.py --once --vanatoare --fara-model` (nu scrie nimic).

Intrebare de control: ce NU are voie Tier 3? Sa scrie exceptii, sa modifice reguli existente,
sa inchida incidente (principiul 6).

---

## Pasul 12. Celelalte timere de pe es-node-1 (ce ruleaza "in jurul" orchestratorului)

| Cand (UTC) | Timer | Script | Ce face / unde scrie |
|---|---|---|---|
| la 1 min | soc-absence | absence_check.py | absenta = alerta: backup > 26 h, servicii cazute, canar lipsa, fluxuri web-prod oprite, Fleet Server, snapshot, rotatie chei, restore test -> soc-metrics + Discord |
| la 1 min (:30) | soc-llm-probe | llm_probe.py | tunel + model raspund? -> soc-metrics type=llm_probe (1438/1440 ieri) |
| la 15 min | soc-exposure | tier3.py --expunere | corelatia de expunere (pasul 11) |
| orar | soc-tier3 | tier3.py | pasul 11 |
| 00,06,12,18:10 | soc-fp-rate | fp_rate.py | rata FP per regula pe traficul benign (benign-ground-truth vs alerte) |
| 02:15 | soc-backup-pull | soc-backup-pull.sh | trage backup-ul de pe web-prod cu cheia soc-backup (rrsync -ro), sha256, 30 zile |
| 04:00 | soc-nday | nday_watch.py | SBOM x NVD/OSV/WPScan -> asset-vulns; CVSS >= 9 -> hunt/patch_request in soc-incidents (plafonat 10) |
| 06:15 | soc-readiness | readiness.py | criteriile c1-c9 pentru block_ip_ttl; doar evaluare; c2/c9 nu pot trece aici |
| dum 05:00 | soc-static | static_triage.py | Semgrep pe copia webroot + triaj -> static-findings |
| ziua 1, 03:00 | soc-backup-restore-test | restore in MariaDB temporar fara retea |

Plus snapshotul SLM `soc-daily` la 02:00 (in ES, nu systemd).

Ordinea noptii, ca sa intelegi dependentele: 01:30 backup (web-prod) -> 02:00 snapshot ES si
wp-update raport -> 02:15 pull backup -> 02:30 reguli Suricata -> 03:00 SBOM -> 03:30 AIDE ->
04:00 N-day pe SBOM-ul proaspat -> 06:10 fp_rate -> 06:15 readiness.

Verifica: `ssh tiberiu@172.30.6.106 'systemctl list-timers --all --no-pager | grep soc-'`.

---

## Pasul 13. Memoria si omul

Indicii proprii, cititi la ce:

- **verdicts-history**: fiecare verdict Tier 1/2; sursa pentru RAG (doar label_source=human),
  incidente si gap_detect. Campurile `ground_truth` si `label_source=human` se scriu **numai**
  din interfata de etichetare, la actiunea unui om (principiul 5).
- **soc-audit**: fiecare decizie (`decide()`), planul executorului, motivele de escaladare,
  `chain_id`. Raspunde la "de ce a facut asta".
- **soc-traces**: per caz si per apel de unealta: argumente, ID-uri de documente (nu text),
  durata, tokeni. Raspunde la "de ce a gresit agentul la cazul X".
- **soc-cases**: unitatea de lucru a omului (agregare pe entitate, upsert din orchestrator).
- **soc-incidents**, **soc-hunts**, **soc-metrics**, **asset-vulns**, **static-findings**,
  **benign-ground-truth**: iesirile din pasii 11-12.

Interfatele:
- `label_ui.py` pe es-node-1:8088 (doar admin_v4 prin nft; parola LABEL_UI_PASSWORD):
  etichetezi TP/FP/FN/TN si lucrezi cazurile. **Drumul critic al proiectului**: >= 100 etichete
  (sunt 2) deblocheaza setul de aur, regresia (`regression.py`), readiness c1/c7 si absolvirea
  executorului.
- Dashboard-urile Kibana `SOC Health` / `SOC Status` / `metrici` (`deploy/kibana/*.ndjson`,
  construite de `build_*dashboard.py`), din soc-metrics si soc-audit.
- Discord (`notify.py`, webhook doar in soc.env pe es-node-1): escaladari critice
  (honeytoken/senzor/nativ) si alertele de absenta.

Prompturile sunt versionate (`prompts/MANIFEST.json`, sha256; `prompts.py`); orchestratorul
scrie `prompt_set` in fiecare document de ciclu, iar nepotrivirea hash-ului e conditie de oprire.

---

## Pasul 14. Cum intra semnal si zgomot: atacator, benign-gen, lab-sink

- **atacator** (OpenClaw "RedAgent" pe qwen3:14b prin `openclaw-llm-tunnel`, plus OpenCyber):
  lanseaza recon/exploit **doar** spre web-prod, prin flotantul 172.30.6.249:80. Pe 2026-11-03
  auto-atacul (nmap, whatweb, feroxbuster, nuclei, nikto, sqlmap, hydra, dalfox, wpscan) a
  produs 1713 alerte in 15 min, a aprins toate straturile, a tinut `isolate_host` in shadow si a
  gasit goluri (XSS la IDS, traversal, enumerare REST) care au fost inchise. Nu a existat RCE.
  Nu-l rula in timpul harness-ului: acelasi GPU.
- **benign-gen** (`benign-gen.service`, user soc-benign, Playwright, cont WP editor
  soc-benign-admin): navigheaza, scrie articole, uploadeaza; fiecare actiune e scrisa in
  `benign-ground-truth` cu ES_BENIGN_WRITER (doar create_doc). Din el se calculeaza FP-urile
  per regula (soc-fp-rate). **Se opreste inainte de harness** (`sudo systemctl stop benign-gen`)
  ca sa nu polueze scenariile; ramas: Fleet Custom Logs `soc.benign_actions`.
- **lab-sink**: tinta pentru `deploy/web-prod/art_runner.py` (Atomic Red Team, 20 tehnici planificate,
  1 rulata). Nimic nu ruleaza pe el; doar web-prod il poate atinge (22/80/8080/icmp), ca sa
  existe "miscare laterala" de observat. Fiecare test cere aprobarea omului per comanda, iar
  un cleanup esuat e conditie de oprire.

---

## Pasul 15. Cum stii ca merge: harness-ul si portile

`harness.py` genereaza atacuri **reale** pe web-prod (prin SSH cu sudo, de aceea victim-sg
permite 22 de la es-node-1), asteapta alertele si compara verdictul cu scenariul:

| Fisier | Scenarii | Referinta |
|---|---|---|
| scenarios_fast.yml | 4 | 4/4 |
| scenarios.yml (dev) | 14 | 14/14, recall 100% (2 FP cunoscute: `php --version`, "Deploy legitim") |
| scenarios_validation.yml | 8 | 8/8 |
| scenarios_0day.yml | 1 | 1/1 |
| scenarios_injection.yml + suita prompt_injection.py | 4 + 48 | 4/4, 48/48 (prag >= 98% identic) |
| scenarios_ablation.yml (A-D, `ablation.py`) | 36 | 36/36 pe fiecare configuratie |

Rulare (lenta, in fundal, cu benign-gen oprit, portul 80 de la atacator inchis, GPU liber):
```
SCENARIOS=scenarios_fast.yml VERBOSE=1 python3 -u harness.py | tee results/<nume>-$(date +%F-%H%M).txt
```
Teste unitare (fara model, fara ES): `python3 -m pytest tests -q` (1099 verzi).
`make determinism` masoara stabilitatea verdictelor (prag 98%, B.9 ramas).

Regula de aur: orice regresie fata de referinta = te opresti si raportezi; nu se ajusteaza
scenariile sau pragurile ca sa treaca. Poarta B.1 (pasul 13) e oprita acum pentru ca GPU-ul
172.30.6.231 are driver mismatch si Ollama a cazut pe CPU; se reia de la zero dupa reboot.

---

## Harta pe scurt (de tinut in cap)

```
atacator 10.10.0.220 --SNAT 172.30.6.133--> web-prod:80 (flotant 172.30.6.249)
benign-gen .150 --------------------------> web-prod:80/443
web-prod .138 --ART--> lab-sink .160 (22/80/8080)

web-prod: Defend + auditd + Suricata + Apache + momeli + SBOM/YARA/AIDE
   |  Elastic Agent -> http://192.168.10.121:9200 (Fleet Server :8220)
   v
es-node-1: ES/Kibana (Docker) -> reguli Kibana -> .alerts-security.alerts-*
   |                                   + sweep-uri de raritate (cod)
   v
soc-orchestrator (120 s, shadow):  alerta -> Tier 1 -> should_escalate -> Case -> Tier 2 -> decide() -> audit
                                   finding -----------------------------> Case -> Tier 2 -> decide() -> audit
soc-tier3 (orar): incidente | reguli EQL proprii (shadow 7 zile) | vanatoare ATT&CK | expunere (15 min)
model: qwen3:14b pe GPU 172.30.6.231, prin tunel autossh localhost:11434 (partajat cu OpenClaw)
om: label_ui :8088 (ground_truth) | dashboard Kibana | Discord
```

## Ce sa citesti dupa roadmap, in ordine

1. `docs/pasi/REZUMAT.md` (starea), apoi `docs/plan-0day.md` (regulile R1-R16).
2. `orchestrator.py` (`run_positioned`, `process_alerts`), apoi `escalation.py`, `policy.py`.
3. `fast_path.py` (`build_fast_path`, `node_finalize`), `hunt_path.py` (`_build_investigator`, `build_hunt_path`,
   `node_corroborate`), `schemas.py` (granita Pydantic).
4. `tier3.py` + `hunt.py` + `rules.py` + `incidents.py`.
5. `deploy/` fisier cu fisier, in ordinea pasilor 4-6 si 12 de mai sus.
6. `harness.py` + `scenarios_fast.yml`, apoi un rezultat din `results/`.

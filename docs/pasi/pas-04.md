# Pasul 4 — Trafic benign cu adevar cunoscut (benign-gen) + rata FP per regula

Scop: un utilizator WordPress normal, din alt IP decat SOC-ul si atacatorul, ca sa masuram
cat zgomot face fiecare regula pe trafic legitim. fp_rate.py LISTEAZA regulile peste 5%;
nimic nu se dezactiveaza automat.

## De ce VM separat (A9, discutat 2026-11-02)
- Masurarea FP e pe IP: pe es-node-1, testele mele / honeytoken-urile / curl-urile SOC-ului
  ar fi numarate ca "benign".
- Honeytoken atins din BENIGN_GEN_IPS = config_error (3.C). Cu es-node-1 in lista, un es-node-1
  compromis ar atinge momelile ca "eroare de configurare".
- Creierul SOC-ului nu tine parola de editor WordPress si nu ruleaza Chromium (ca A11).

## A. Fisiere
| Fisier | Unde | Ce face |
|---|---|---|
| benign_gen.py | benign-gen /opt/soc-benign | sesiuni zi (08-20: 2-6 min) / noapte (15-40 min), max 30 cereri; navigare publica, login/logout real (Playwright), articol nou / editat / imagine PNG generata local (REST cu cookie + nonce, ca Gutenberg), wp-cron. Adevar in benign-ground-truth INAINTE de cerere (phase=start) si dupa (phase=end). Fara start inregistrat -> fara cerere. safe_path refuza orice cale cu caractere speciale. |
| deploy/benign-gen/{setup.sh, benign-gen.service, benign.env.example} | benign-gen | user soc-benign (nologin), venv (playwright 1.47.0, requests, pillow), ProtectSystem=strict, MemoryMax 1.5G, TZ Europe/Bucharest |
| fp_rate.py | es-node-1 | atribuire benign_ip / benign_ua / benign_time (alerte de host in fereastra unei actiuni) / benign_update (benign-actions de pe web-prod); soc-metrics type=fp_rate + data/fp_report.txt |
| deploy/soc-fp-rate.{service,timer} | es-node-1 | la 00/06/12/18:10 |
| deploy/es-node-1/benign-setup.sh | es-node-1 (OM, elastic) | index benign-ground-truth (strict) + chei soc-benign-writer (doar create_doc) si soc-fp-reader (doar citire) |
| tests/test_benign_gen.py | — | 32 teste pure |

## B. Comenzi

Facute de Claude (aprobat 2026-11-02):
```
openstack security group create benign-sg       # 22 doar de la 172.20.99.220 si 192.168.62.206
openstack port create --network es-net --fixed-ip subnet=b08b2a0e-...,ip-address=192.168.10.150 --security-group benign-sg benign-gen-port
openstack server create --flavor m1.small --image "Ubuntu Noble" --key-name lab-key --port benign-gen-port --wait benign-gen
openstack server add floating ip benign-gen 172.30.6.210     # flotantul nefolosit din proiect (pool-ul public era plin)
openstack security group rule create --protocol tcp --dst-port 80 --remote-ip 192.168.10.150/32 victim-sg
# cheia de host verificata din consola OpenStack: SHA256:f+7FepqW7hIcczq476CoXJn6euun8fJ/soMKm4/2n8o
sudo bash /tmp/soc-benign/setup.sh               # pe benign-gen; Chromium testat ca soc-benign: 200
# /etc/soc-benign/benign.env (root:soc-benign 640) scris pe VM, parola WP generata acolo, neafisata
```

De facut de OM, in ordine:
```
# 1. index + chei (contul elastic) -> asteptat: creat, 2 chei adaugate, 403 / 200 / 403
ssh tiberiu@172.30.6.106 'cd ~/lab && bash deploy/es-node-1/benign-setup.sh'

# 2. cheia de scriere pe VM (prin pipe, neafisata)
ssh tiberiu@172.30.6.106 'grep "^ES_BENIGN_WRITER_API_KEY=" ~/lab/soc.env' | ssh ubuntu@172.30.6.210 'sudo tee -a /etc/soc-benign/benign.env >/dev/null && sudo grep -c "^ES_BENIGN_WRITER_API_KEY=" /etc/soc-benign/benign.env'

# 3. contul WordPress (editor, nu administrator), parola din VM prin stdin (nu apare in command_line)
ssh ubuntu@172.30.6.210 'sudo grep -oP "^BENIGN_WP_PASSWORD=\K.*" /etc/soc-benign/benign.env' | ssh tiberiu@172.30.6.249 'sudo -u www-data /usr/local/bin/wp --path=/var/www/html user create soc-benign-admin benign@localhost.invalid --role=editor --prompt=user_pass --porcelain'

# 4. Kibana -> Fleet -> policy web-prod -> Add integration "Custom Logs" (ca la soc.sbom):
#    path /var/log/soc/benign-actions.ndjson, dataset soc.benign_actions,
#    procesor decode_json_fields pe message, target "", add_error_key.

# 5. timer-ul fp_rate
ssh -t tiberiu@172.30.6.106 'sudo install -m 644 ~/lab/deploy/soc-fp-rate.service ~/lab/deploy/soc-fp-rate.timer /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl enable --now soc-fp-rate.timer'
```
Dupa 1-3, Claude ruleaza o sesiune de proba (BENIGN_ONCE=1) si porneste benign-gen.service.

IMPORTANT: benign-gen se OPRESTE in timpul harness-ului (conditii de referinta, GPU partajat):
`ssh ubuntu@172.30.6.210 'sudo systemctl stop benign-gen'` inainte, `start` dupa.

## C. Verificare
- logs-apache.access-*: user_agent.original : *soc-benign* in ultimele 10 min;
- benign-ground-truth/_count creste; perechi start/end;
- `journalctl -u benign-gen` fara traceback; data/fp_report.txt are >= 1 linie.

## D. Metrica
soc-metrics type=fp_rate (rule_name, fp_count, total, fp_rate, by_reason, recalibrate);
sessions_24h si errors_24h din benign-ground-truth (run_id distinct, phase=end cu error).
Acceptare: 24 h fara restart; 4 rapoarte FP; regulile > 0.05 listate pentru lista alba.

## E. Rollback (doar la cerere)
```
ssh ubuntu@172.30.6.210 'sudo systemctl disable --now benign-gen'
openstack server delete benign-gen; openstack port delete benign-gen-port; openstack security group delete benign-sg
openstack security group rule delete <id regula 80 din victim-sg>   # 72d6d61b-d2bc-4779-a233-3a5a96110976
ssh tiberiu@172.30.6.249 'sudo -u www-data wp --path=/var/www/html user delete soc-benign-admin --reassign=1'
sudo systemctl disable --now soc-fp-rate.timer
# elastic: DELETE benign-ground-truth; _invalidate soc-benign-writer, soc-fp-reader; scoate cheile din soc.env
```

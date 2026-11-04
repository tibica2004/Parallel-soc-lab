# REZUMAT — starea proiectului la 2026-11-04

Rezumat de sine statator: ce exista, ce merge, ce ramane. Jurnalul cronologic (cu toate
constatarile, in ordinea in care au aparut) e `docs/pasi/stare.md`; detaliile A-E pe fiecare
pas sunt in `docs/pasi/pas-NN.md`; planul original e `docs/plan-0day.md`.
Ramura: `faza-21-protectie` (nepublicata, fara push; omul face merge in main).

EXCLUSIV DEFENSIV. Shadow mode permanent: nicio actiune pe hosturi, executorul doar dry-run.

## 1. Ce este

Un SOC agentic Blue Team pe Elastic Stack 9.5.1 + modele locale (qwen3:14b prin Ollama), cu
trei niveluri si cod determinist in jurul modelului:

- **Senzori** (web-prod): Elastic Defend eBPF, auditd (kernel imuabil), Suricata 7 cu
  reguli ET actualizate zilnic, ModSecurity CRS in DetectionOnly, Apache/MariaDB/syslog,
  AIDE, YARA, SBOM zilnic, 10 honeytokens (fisiere, cai robots.txt, conturi inexistente).
- **Detectie** (Kibana): reguli EQL/KQL native + 9 reguli comportamentale fara semnatura
  (shell din apache2, PHP in webroot, binar nevazut, outbound nou, scriere in afara webroot,
  /etc/shadow, fisiere sensibile, conturi/cron, SUID), 6 reguli honeytoken, XSS/SQLi/
  traversal/enumerare/brute-force pe trafic, sweep-uri de raritate (new_executable, new_user,
  new_url_path, sbom_drift).
- **Tier 1** (triaj, `fast_path.py`): enrich -> RAG -> agent cu max 3 unelte -> verdict ->
  podele de cod -> `should_escalate()`. Inchide doar benign clar.
- **Tier 2** (investigatie, `hunt_path.py`): doua investigatii independente cand suportul
  e 2, coroborare, `policy.decide()`. Nu primeste verdictul Tier 1. Criticul e oprit
  (masurat daunator la 14B).
- **Tier 3** (programat, `tier3.py`, orar): vanatoare pe ipoteze ATT&CK, grupare in
  incidente, reguli EQL proprii cu shadow 7 zile, cereri N-day din SBOM x NVD/WPScan.
- **Memorie**: verdicts-history, soc-audit, soc-traces, soc-incidents, soc-cases (unitatea de
  lucru a omului), soc-metrics (ciclu, sonda LLM, integritate, porti), benign-ground-truth.
- **Om**: interfata de etichetare + cazuri (`label_ui.py`), dashboard SOC Health / SOC Status,
  notificari Discord (escaladari critice + absente).

## 2. Infrastructura (OpenStack, din 2026-10-26)

| VM | IP intern / flotant | Rol |
|---|---|---|
| es-node-1 | 192.168.10.121 / 172.30.6.106 | ES + Kibana (Docker), Fleet Server, orchestrator + 10 timere SOC |
| web-prod | 192.168.10.138 / 172.30.6.249 | WordPress tinta, toti senzorii, 6 timere (backup, update raport, SBOM, AIDE, YARA, suricata-update) |
| atacator | 10.10.0.220 / 172.30.6.133 | OpenClaw / OpenCyber; ajunge doar pe web-prod:80/443; SNAT -> apare ca 172.30.6.133 |
| benign-gen | 192.168.10.150 / 172.30.6.210 | trafic WordPress benign (Playwright), scrie benign-ground-truth |
| lab-sink | 192.168.10.160 | tinta ART miscare laterala / exfiltrare; nimic nu ruleaza pe el |
| GPU | 172.30.6.231 | Ollama qwen3:14b, prin tunel autossh |

Sesiunea Claude ruleaza pe boxa veche (172.20.99.220); hosturile se ating prin IP-urile
flotante. Firewall nft propriu (`inet soc_fw`) pe es-node-1 si web-prod; security groups
restranse (2026-11-04: 9200 doar web-prod + benign-gen, 8220 doar web-prod, fara SSH de la atacator).

## 3. Ce s-a facut (pasii 0-12b, plan-0day)

| Pas | Continut | Stare |
|---|---|---|
| 0 | backup zilnic + copie trasa + restore lunar; unattended-upgrades; WP fara auto-update; firewall nft; Discord; hardening Apache | FACUT |
| 1, 1b, 1c | SBOM -> N-day watch (asset-vulns, 224 vulns, hunt/patch_request plafonat); cont soc-reader cu gate de 11 comenzi; soc-metrics | FACUT |
| 2 | Semgrep saptamanal pe copia webroot + triaj fara model implicit; core-ul oficial WP sarit dupa checksum | FACUT |
| 3 | reguli comportamentale, honeytokens WP/MySQL, monitor de integritate (absence_check la 1 min), AIDE, sweep-uri de raritate | FACUT |
| 4 | VM benign-gen + benign-ground-truth + raport FP la 6 h | FACUT (ramas: Fleet Custom Logs soc.benign_actions) |
| 5 | art_runner + coverage ATT&CK + lab-sink | COD GATA; 1/20 tehnici rulate |
| 6 | suita de injectie (48/48), telemetrie delimitata in Tier 1 si Tier 2, snapshot SLM zilnic + restore testat | FACUT |
| 7 | metrici per ciclu, sonda LLM, watchdog 900 s, MemoryMax, dashboard SOC Health | FACUT |
| 8 | prompturi versionate (MANIFEST sha256), regression.py, determinism | COD GATA; cere >= 100 etichete umane (sunt 2) |
| 9 | readiness c1-c9, executor cu garzi, doar dry-run | FACUT ca evaluare; c9 imposibil (SNAT unic), c2 nu trece in topologia asta |
| 10 | CLAUDE.md, agregare pe cazuri, ServerName | FACUT |
| 11, 12, 12b | ILM 30/45/180 zile, cheia soc-monitor; suricata-update zilnic; ModSecurity CRS DetectionOnly | FACUT |
| 13 | completari: plafon pe cazuri noi in coada, reguli 3.1 e/f/g, G8 rotatie chei, restore lunar, SBOM fix | B.3, B.4, B.7 aplicate; B.1 poarta in curs; B.2, B.5, B.8, B.9 ramase |

Porti de regresie (referinta): dev 14 scenarii recall 8/8 atacuri (2 FP cunoscute: `php --version`,
"Deploy legitim"), validare 8/8, fast 4/4, 0-day 1/1, injectie 4/4 Tier 2 + 48/48 suita.
Teste unitare: 1099 verzi (`python3 -m pytest tests -q`).

## 4. Ce a aratat auto-atacul (2026-11-03, OpenCyber din atacator)

- recon/enumerare: Suricata rateaza flood-ul de 404; sweep-ul propriu (web_enumeration,
  entity_risk pe IP) il prinde -> suspicious, caz pe source_ip.
- exploit (nuclei, nikto, sqlmap, hydra, dalfox, wpscan): 1713 alerte intr-un sfert de ora;
  toate straturile s-au aprins; isolate_host malicious/95 tinut in shadow; coada s-a plafonat
  corect (R9: criticul escaladeaza fara model sub flood).
- goluri inchise: XSS la IDS (regula noua, 0 -> 753 alerte), traversal, directory listing,
  enumerare utilizatori REST, sendmail WordPress ca FP in soc-web-spawns-shell.
- NU a existat RCE: executiile www-data erau scenariile harness-ului (corelat pe telemetrie).

## 5. Ce ramane (in ordine)

1. **Pas 13**: B.1 poarta (ruleaza), B.2 deploy + restart orchestrator, B.5 cele 3 reguli noi
   in Kibana (shadow-review 7 zile), B.8 Fleet soc.benign_actions, B.9 `make determinism`.
2. **Etichetare**: >= 100 alerte in interfata (>= 25 malicious / suspicious / benign). Drumul
   critic: fara ea nu exista setul de aur, regresia, c1/c7, graduation. ~3-4 h, in bucati.
3. **ART pe lab-sink**: >= 20 tehnici, fiecare cu cleanup OK si ipoteza Tier 3 pentru cele
   nevazute. 2-3 sesiuni, omul aproba fiecare comanda.
4. **Fals pozitive zilnice de calibrat** (decizie om, apoi harness): `lsb_release -i -s` din
   unattended-upgrade (regula Reverse shell), `soc-wp-update.py` la 02:00 (binar nevazut ->
   malicious/95), sendmail in regula nativa RCE.
5. **Ferestre**: 7 zile shadow-review pentru regulile e/f/g; 24 h benign fara restart.
6. **Igiena**: chei API duplicate active (3x soc-reader, 4x writer-ele din 29.10) de invalidat
   cu contul elastic; copiile `.pre-*` de pe es-node-1 dupa B.2; rotatia cheilor pe 2027-01-06.

Abateri documentate (nu lipsuri): timesyncd in loc de chrony; backup fara copie off-host
(un singur disc); pasul 9 doar readiness (principiul 4 neatins); fara disable_functions
(ar pica portile); WP update in mod raport; conturile honeytoken nu exista; Discord ca notificare.

## 6. Reguli de lucru care au contat

- Codul decide, modelul judeca; esecul escaladeaza, nu inchide; ground_truth doar de la om.
- Orice schimbare care atinge verdictul: harness fast + dev inainte de deploy; nicio regresie
  "reparata" din praguri.
- Comenzile pe hosturi le ruleaza omul (sau Claude cu aprobare explicita); copii `.pre-<pas>`
  inainte de fiecare deploy; rollback doar la cerere.
- Gotcha-uri de tinut minte: kernelul auditd e imuabil (regula noua = reboot web-prod);
  source.ip pe web-prod e IP-ul flotant al atacatorului (SNAT); never_block e lista de IP-uri,
  nu CIDR; benign-gen se opreste la harness; GPU-ul e partajat (nu rula OpenClaw in poarta).

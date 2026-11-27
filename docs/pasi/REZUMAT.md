# REZUMAT — starea proiectului la 2026-11-17

Rezumat de sine statator: ce exista, ce merge, ce ramane. Jurnalul cronologic (cu toate
constatarile, in ordinea in care au aparut) e `docs/pasi/stare.md`; detaliile A-E pe fiecare
pas sunt in `docs/pasi/pas-NN.md`; planul original e `docs/plan-0day.md`.
Ramuri (2026-11-17): `main` = `faza-22-igiena-si-corectii` = 80a867c, pe GitHub, trecuta prin poarta pe
2026-11-17 (fast 4/4, dev recall 8/8 cu 1 FP, validare 8/8, injectie 4/4, suita 48/48) si in productie pe
es-node-1 din 2026-11-16. Lucrul continua pe `faza-23-inchidere-conceptuala` (pe GitHub, neunita): contine
si regula asimetrica Tier 2 (etapa 5), care ATINGE VERDICTUL si nu e in productie pana nu trece poarta.
Sectiunile de mai jos descriu starea de la 2026-11-04 acolo unde nu spun altfel; ce s-a schimbat de atunci
e in `stare.md` (intrarile 2026-11-16 si 2026-11-17) si in `DE_FACUT.md`.

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
| benign-gen | 192.168.10.150 (fara flotant; prin es-node-1) | trafic WordPress benign (Playwright), scrie benign-ground-truth |
| lab-sink | 192.168.10.160 / 172.30.6.210 | tinta ART miscare laterala / exfiltrare; nimic nu ruleaza pe el |
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

## 7. Limitari (si ce le compenseaza azi)

Scrise si in lucrare (DE_FACUT.md F1). Domeniul (ce acopera / ce nu) e in `README.md`, sectiunea "Domeniu".

| Limitare | Ce o compenseaza azi |
|---|---|
| **Notele umane ajung la model.** `lookup_history` pune ultimele 5 etichete ale regulii, cu notele trunchiate la 120 de caractere, in contextul Tier 1, IN AFARA blocului de telemetrie neincrezatoare. O nota gresita sau manipulata poate inclina verdictul. | Notele le scrie doar omul, prin `label_ui` (LabelInput: max 500 de caractere, fara caractere de control; portul 8088 deschis in nft doar pentru `admin_v4`). Modelul doar propune: podelele, `should_escalate()` si `policy.decide()` nu citesc notele (principiul 1). Suita de injectie (48/48) nu acopera canalul notelor: e un gol cunoscut. |
| **Un singur model si un GPU al altcuiva.** Tier 1, Tier 2 si OpenClaw folosesc acelasi qwen3:14b pe GPU-ul 172.30.6.231, administrat de altcineva (vezi caderea din 04.11: driver nepotrivit, Ollama pe CPU). | Esecul escaladeaza, nu inchide (principiul 8): timeout / model cazut -> undetermined + escalate_human; mod degradat (R9) sub flood; `soc-llm-probe` la 1 min si `absence_check` alerteaza pe Discord; modelul si adresa se schimba per rol fara cod (`MODEL_<ROL>`, `LLM_BASE_URL_<ROL>`); shadow mode face ca un verdict gresit sa nu atinga hosturile. |
| **Fara copie off-host.** Backup-ul (soc-backup-pull) si snapshot-ul SLM zilnic stau pe discul lui es-node-1; un singur disc, un singur proiect OpenStack. | Backup zilnic al lui web-prod tras pe es-node-1 (deci separat de tinta), snapshot SLM zilnic cu retentie 30 de zile, restore de test lunar (`soc-backup-restore-test`, verificat de `absence_check`); codul e pe GitHub. Datele (indici, etichete) nu au a doua copie: abatere documentata. |
| **Un singur host si un set mic.** Un web-prod, 14 + 8 + 4 scenarii de poarta, setul de aur tinta de ~100 de etichete, ART de la 1 spre 20 de tehnici. | Intervale Wilson 95% in regresie si in linia de baza (`regression.py`, `experiments/direct_baseline.py`): cifrele se raporteaza cu incertitudinea lor; set de validare separat de dev; trafic benign real si etichetat automat ca adevar separat (benign-gen -> benign-ground-truth); suita de injectie; determinism >= 98%. Generalizarea la alte hosturi / medii nu e demonstrata. |

# Standardul de investigatie: ce inchide o alerta, ce o escaladeaza, ce ramane la om

Scris 2026-11-03, derivat din cod (nu din intentii). Raspunde la criteriul 3 din lista de
pregatire pentru agenti AI in SOC (The Hacker News, 2026-11-02): "exista un standard scris
pentru ce inseamna o investigatie completa, pentru clasele de alerte cu volum mare?".
Serveste si ca ghid de etichetare in interfata (ground_truth attack/benign) si ca raspuns la
intrebarea "pe ce criterii ati etichetat" din lucrarea de licenta.

Regula documentului: codul e sursa adevarului. Fiecare afirmatie citeaza functia din care vine.
Daca documentul si codul difera, codul castiga si documentul se corecteaza. Daca o regula din
cod pare gresita, se schimba codul printr-o faza cu poarta de harness, nu documentul.

## 0. Elementele comune tuturor claselor

### 0.1 Faptele deterministe (calculate de cod inainte de orice model)

| Fapt | Sursa | Unde se calculeaza |
|---|---|---|
| `ran_by_web_service_account` | user-ul procesului e contul serverului web (WEB_SVC_USERS) | fast_path.node_enrich, hunt_path.prefetch_context |
| `ran_by_known_admin` | user-ul e in `normal_admins` din asset-inventory pentru host | fast_path.py:261, hunt_path.py:348 |
| `sensitive_action` | proces din SENSITIVE_CHILD, comanda din SENSITIVE_CMD, executie din TEMP_DIRS, fisier executabil scris in webroot | fast_path.py:276, hunt_path.py:356 |
| `in_maintenance_window` | fereastra valida din asset-inventory la ora EVENIMENTULUI | maintenance.py |
| `pair_in_baseline` | perechea parinte-copil vazuta pe host in baseline-entity-parentchild (90 zile) | elastic_tools |
| `honeytoken` / `honeytoken_config_error` | rule_id din honeytokens.RULES; config_error daca sursa e IP propriu sau benign-gen | honeytokens.is_config_error |
| `native_detection` | alerta nativa Elastic Defend (malware, comportament, memorie) | defend_native.py |
| `sensor_detection` | YARA / Suricata / ModSecurity / AIDE, dupa rule_id | sensor_rules.sensor_facts |
| `behavioral` | una din cele 6 reguli soc-behavioral | behavioral_rules.is_behavioral |
| `correlated_alerts`, `threat_intel_matches` | alte alerte pe host in fereastra; indicatori gasiti exact in kb/threat_intel.yml | enrich.enrich |
| `similar_cases` | cazuri etichetate de OM, asemanatoare pe trasaturi | rag.py |
| `investigation_guide` | detections/<ghid>.md dupa numele regulii (RULE_TO_GUIDE) | fast_path.lookup_guide |

Textul din telemetrie (command_line, user, nume de procese, URL) e DATE, delimitat in prompt
ca neincrezator; nu poate schimba clasa (FACT_RULES, pasul 6.1).

### 0.2 Bugetele

| Nivel | Unelte | Alt plafon |
|---|---|---|
| Tier 1 (calea rapida) | max 3 apeluri | timeout per caz; agent cazut/timeout -> benign devine undetermined (fast_path.node_finalize) |
| Tier 2 (investigatie) | max 12 apeluri per investigator (hunt_path.MAX_TOOL_CALLS) | MAX_TOKENS_PER_HUNT; buget epuizat -> corroboration_status=budget_exhausted |
| Sweep orar | --hunt-limit 5 investigatii Tier 2 | restul: verdict de cod undetermined + escalate_human (BACKLOG_SEVERE), nimic pierdut |
| Restanta | > BACKLOG_THRESHOLD (20) alerte intr-un ciclu | coada ordonata pe severitate si criticitate; severitatea critical escaladeaza fara model (degraded.py) |

### 0.3 Podelele (codul rastoarna modelul; fast_path.node_finalize si hunt_path.node_finalize)

| Podea | Conditie | Efect |
|---|---|---|
| 0 | benign + honeytoken | suspicious, escalate_human, incredere <= 60 |
| 1 | benign + ran_by_web_service_account | suspicious, escalate_human, incredere <= 60 |
| 2 | benign + sensitive_action, fara (fereastra de mentenanta SI admin cunoscut) | suspicious, escalate_human, incredere <= 60 |
| 3 (actiune) | suspicious/malicious pe fapte riscante, dar actiune none/enrich_only | escalate_human |
| 4 | contul web a pornit un proces cu parinte in WEB_EXEC_PARENTS (apache2, php, sh, dash, bash...), fara sudo | malicious, escalate_human (escalation.web_exec_floor) |
| Tier 2 | caz din Tier 1 cu suspicious/malicious/undetermined si actiune none/enrich_only | escalate_human (hunt_path.tier1_case_action_floor) |

### 0.4 Cand se inchide o alerta pe Tier 1 (escalation.should_escalate)

O alerta se inchide DOAR daca TOATE sunt adevarate:
1. clasificarea e `benign`;
2. increderea >= 90 (ESC_LOW_CONF);
3. `pair_in_baseline` e exact true (None = nevazut = escaladeaza);
4. nicio podea nu s-a aplicat;
5. niciun steag: native_detection, honeytoken, sensor_detection, behavioral.

Orice altceva escaladeaza, cu lista de motive (EscalationReason) scrisa in soc-audit. Esecul
(model cazut, timeout, parsare esuata, buget) nu inchide niciodata: undetermined + escalate_human.

### 0.5 Cand Tier 2 spune "malicious" (hunt_path.merge_corroboration)

Increderea finala nu e media a doua pareri. `support_score` numara semnalele independente
confirmate prin unelte: process_chain, new_egress, file_write, http_precursor (0-4).
- Acord A/B pe aceeasi clasa: incredere = min(97, 40 + 15 x suport).
- Dezacord: incredere <= 40, indiferent cat de siguri par investigatorii.
- Investigator B indisponibil: not_required / secondary_unavailable, increderea lui A.
Tier 2 nu primeste verdictul Tier 1 (principiul 7): doar fapte, dovezi si motivele escaladarii.

### 0.6 Ce inseamna "investigatie terminata"

Un caz e terminat cand exista, in soc-audit si soc-traces: verdictul (clasa, incredere, actiune
propusa), motivele escaladarii, `evidence_refs` (ID-uri de documente, nu text), fiecare apel de
unealta cu argumente si durata, decizia motorului de politici (policy.decide: actiune aleasa,
motiv, shadow) si naratiunea in romana. Omul vede cazul in /cases (label_ui) si, pentru
honeytoken / senzor / detectie nativa, primeste notificare Discord (notify.maybe_notify_escalation).
Nimic nu se executa pe hosturi (shadow); kill_process are prag 101 (niciodata automat).

## 1. Fisele pe clase (dupa volumul din ultimele 24 h, 2026-11-03)

Pentru fiecare clasa: ce aduna Tier 1, ce poate inchide, ce escaladeaza obligatoriu, ce
verifica omul, cum se eticheteaza.

### 1.1 Serverul web a executat ceva: "RCE: Web server spawns shell", "Comportament: serverul web a nascut un shell", "Payload download: curl/wget", "Reverse shell"

- Fapt decisiv: `ran_by_web_service_account` + parinte apache2/php/sh. Podeaua 4 -> malicious.
- Tier 1 nu poate inchide: podeaua 1 blocheaza orice benign.
- Singurele explicatii legitime cunoscute pe web-prod (mod_php, fara php-fpm): soc-wp-update
  (parinte python3 din systemd, nu apache2) si wp-cli prin sudo (sudo_invoked_by = admin).
  Ambele NU se potrivesc cu podeaua 4 (parintele nu e in WEB_EXEC_PARENTS).
- Omul verifica: arborele de procese (tool_process_tree), conexiunile noi (tool_egress_for_host),
  cererea HTTP precursoare in Apache (tool_apache_requests), destinatia curl/wget.
- Eticheta: attack daca parintele e serverul web si user-ul www-data, indiferent de comanda
  (`id` si `hostname` sunt recunoastere). benign doar pentru soc-wp-update sau un admin din
  normal_admins cu curl spre localhost/intern. Ghiduri: detections/rce-web-shell.md,
  payload-download.md, reverse-shell.md.

### 1.2 Fisier scris in webroot: "Webshell: Executable written to webroot", "Comportament: fisier PHP scris in webroot"

- Fapt: `sensitive_action` (webroot_executable_write). Podeaua 2: benign doar in fereastra de
  mentenanta SI de un admin cunoscut. Regula comportamentala escaladeaza mereu (BEHAVIORAL).
- Explicatii legitime: update de plugin/tema in fereastra de mentenanta (maintenance_windows din asset-inventory, scrise de om; vezi maintenance.py),
  rularea soc-wp-update (fereastra de update din fp_rate.update_windows), plantarea momelilor.
- Omul verifica: cine a scris (proces, user), hash-ul fisierului fata de checksum-urile WP
  oficiale (static_triage foloseste aceeasi logica: upstream_core), YARA, AIDE, cererea HTTP
  precursoare (upload prin plugin?).
- Eticheta: attack daca scriitorul e www-data in afara unei ferestre si fisierul nu e in
  checksum-urile oficiale. benign pentru update-uri in fereastra si plantari documentate.
- Ghid: detections/webshell-webroot.md (scris 2026-11-03).

### 1.3 "Comportament: www-data a executat un binar nevazut"

- Fapt: lista alba data/behavioral-whitelists.json (wwwdata_exec = dash, php8.3), generata din
  baseline cu NEVER_WHITELIST (id, env, uptime excluse ca recon). BEHAVIORAL -> escaladeaza mereu.
- Explicatii legitime: niciuna in afara listei albe; soc-wp-update ruleaza ca www-data prin
  python3/wp (parinte python3) si e in fereastra de update.
- Eticheta: attack pentru orice binar in afara listei albe, in afara ferestrei soc-wp-update.

### 1.4 Detectii de retea pe source.ip: "Suricata: tentativa de atac web (IDS)", "ModSecurity: cerere web anormala", "Tentativa de SQL injection (web)", "Enumerare continut web", "Brute-force autentificare web", "Brute-force SSH"

- Fapt: `sensor_detection` (Suricata, ModSecurity) sau regula proprie pe loguri Apache/auth.
  Escaladeaza mereu, FARA podea de verdict (semnaturile pot fi fals pozitive).
- Context de laborator: tot traficul extern vine prin SNAT-ul 172.30.6.133 (atacatorul); benign-gen
  e 192.168.10.150 (BENIGN_GEN_IPS); omul admin nu ajunge pe 80 la web-prod.
- Omul verifica: IP-ul sursa, codurile de raspuns (200 pe cai noi = expunere; 404 in masa =
  scanare), alertele de pe host care urmeaza (1.1-1.3) in aceeasi fereastra (correlated_alerts),
  semnatura Suricata si categoria.
- Eticheta: attack daca vine de la atacator in timpul unui exercitiu (harness, ART, OpenCyber) sau
  e urmata de alerte pe host. benign daca e atribuita benign-gen (fp_rate.attribute) sau e un
  scan al adminului. Recon fara consecinta e tot attack la etichetare (a fost un atac), chiar
  daca Tier 1 spune enrich_only: eticheta descrie ce s-a intamplat, nu ce a zis modelul.
- Gol IDS cunoscut: Suricata nu prinde flood-ul de 404 (feroxbuster 9634 cereri -> 1 alerta);
  controlul compensator e sweep-ul web_enumeration.

### 1.5 Momeli: cele 10 reguli soc-honeytoken-* / soc-honey-*

- Fapt: `honeytoken`. Podeaua 0 si motivul HONEYTOKEN: escaladeaza mereu, Tier 2 nu poate inchide.
- Nimic legitim nu atinge o momeala. Exceptie tehnica: lovita de pe IP propriu sau benign-gen ->
  HONEYTOKEN_CONFIG_ERROR (tot la om, fara paginare): e o eroare de configurare, nu un atac.
- Excluderi deja in reguli: apache2 (serveste fisierele), /usr/bin/yara, /usr/bin/aide, backup-ul.
- Omul verifica: sursa (IP / proces / user), ce momeala, daca a fost un test documentat.
- Eticheta: attack pentru orice atingere din exterior sau de pe host de un proces neasteptat;
  benign pentru config_error si pentru testele de plantare/validare notate in stare.md.
- /db-backup si /wp-admin-old sunt ROBOTS_TRAPS (momeli), nu expuneri. Ghid: detections/honeytoken.md.

### 1.6 Outbound nou: "Comportament: web-prod a deschis o conexiune outbound noua", findings new_destination / beaconing

- Fapt: lista alba egress (8 destinatii externe din baseline) + sweep-ul de raritate; beaconing
  = CV al intervalelor <= 0.25 si >= 6 conexiuni in 6 h (anomalies.py).
- Explicatii legitime: unattended-upgrades (oglinzi Ubuntu), api.wordpress.org, feed-ul ET Open
  (soc-suricata-update 02:30), NTP.
- Omul verifica: procesul care a deschis conexiunea, destinatia (threat_intel), ritmul.
- Eticheta: attack daca procesul e www-data / un binar nevazut sau destinatia e necunoscuta si
  regulata; benign pentru procesele de sistem spre destinatiile de mai sus.

### 1.7 Integritate si senzori pe host: "AIDE: fisier schimbat in afara unui update", "YARA: webshell gasit in webroot", "soc-reader: comanda refuzata de gate"

- AIDE: codul marcheaza `explicat` cand un pachet dpkg s-a instalat de la rularea anterioara;
  altfel senzor -> escaladeaza. Eticheta: benign daca explicat de dpkg sau de o schimbare
  documentata in stare.md (hardening, momeli); altfel attack.
- YARA: FARA podea (poate fi FP). FP cunoscut pe fisiere WordPress core; eticheta benign daca
  hash-ul fisierului e in checksum-urile WP oficiale; attack altfel. Ghid: detections/yara-webshell.md.
- soc-reader denied: gate-ul de pe web-prod a refuzat o comanda (bash -i, sh -c id...). Doar
  es-node-1 poate deschide sesiunea, deci orice refuz inseamna fie testul de gate al portii
  (scenarios_injection, notat in results/), fie cheia soc-reader compromisa. Eticheta: attack,
  inclusiv pentru teste (sunt atacuri reale contra gate-ului, detectate corect).

### 1.8 Findings din sweep (raritate, web_enumeration, wp_recon_path, new_url_path, entity_risk, sbom_drift, new_user, new_executable)

- Nu trec prin Tier 1: intra direct in Tier 2 (max 5 per rulare), restul la om fara model.
- Omul verifica dupa tipul finding-ului: pentru new_url_path cu 200, daca e o cale legitima
  nou publicata sau o expunere (sau o momeala: ROBOTS_TRAPS); pentru entity_risk, ce alerte au
  compus scorul; pentru sbom_drift, daca modificarea e un update documentat.
- Eticheta: ca la clasa care a produs semnalul; entity_risk pe user-ul care ruleaza harness-ul
  (tiberiu) e attack (atacurile sunt reale), dar se noteaza in stare.md ca exercitiu.

## 2. Cum se eticheteaza (interfata label_ui, labeling.outcome)

- `ground_truth` e binar: attack / benign. Descrie ce s-a intamplat in realitate, nu ce a zis
  modelul si nu cat de "grav" a fost. Recon de la atacator = attack. Test de plantare = benign.
- Rezultatul (TP/FP/FN/TN) il calculeaza codul: `flagged` = suspicious/malicious/undetermined
  sau actiune != none (labeling.is_flagged, identic cu harness.score_verdict).
- Tinta: >= 50 attack si >= 50 benign (regression.py), ideal amestecate pe clasele 1.1-1.8.
  Deblocheaza: readiness c1 si c7, setul de aur pentru regresie, graduation in executor
  (>= 50 etichete, precizie >= 0.95, 0 FN in 30 zile), RAG pe cazuri umane, fp_rate per regula.
- Ce NU se eticheteaza automat, niciodata: ground_truth si label_source=human (principiul 5).

## 3. Linia de baza (de inregistrat INAINTE de etichetarea masiva, cum cere articolul)

Valori din soc-metrics type=cycle, ultimele 24 h la 2026-11-03 08:45 UTC (contaminate de harness
si de auto-atacul OpenCyber, deci NU sunt "operare normala"):

| Metrica | Valoare |
|---|---|
| alerte procesate | 470 |
| escaladate (Tier 2 sau om) | 379 |
| inchise pe Tier 1 | 91 |
| verdicte fara model (buget / cadere) | 16 |
| honeytoken_hits | 1 |
| timp pana la prima procesare | <= 120 s (ciclul orchestratorului) |
| verdicte etichetate de om | 2 din 2668 |

Lipsesc fata de articol: timpul pana la prima privire a OMULUI (de calculat din labeled_at -
@timestamp dupa ce exista etichete) si cazurile redeschise (soc-cases nu are inca "reopened").

## 4. Goluri gasite la scrierea documentului

1. REZOLVAT 2026-11-03: detections/webshell-webroot.md si detections/temp-exec.md scrise (lipseau,
   desi RULE_TO_GUIDE le astepta; "Webshell: Executable written to webroot" avea 63 alerte/24 h cu
   ghid "indisponibil"). tests/test_guides.py verifica ca toate ghidurile din harta exista si incap
   in 1500 de caractere. Poarta fast + dev de rulat dupa deploy (schimba promptul Tier 1).
2. Regulile comportamentale, Suricata/ModSecurity, enumerarea si brute-force nu au ghid; au in
   schimb contextul de senzor (sensor_facts) si FACT_RULES. De decis daca merita ghid.
3. new_url_path raporteaza si momelile ROBOTS_TRAPS (dublura cu regula honeytoken).
4. Metricile "prima privire a omului" si "redeschis" nu exista inca.

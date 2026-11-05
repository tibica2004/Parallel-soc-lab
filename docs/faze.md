# Fazele proiectului

Sursa: promptul de lucru din conversatia claude.ai (2026-10-09) si lista de sarcini din aceeasi conversatie (2026-10-08/09). Promptul original s-a oprit la inceputul fazei 3; restul fazelor vin din descrierile sarcinilor si trebuie detaliate cu Tiberiu inainte de implementare.

Starea la 2026-10-09: faza 0 (CLAUDE.md) facuta; faza 1 implementata pe ramura faza-01-securitate, cu rezultatele in results/*-faza1-2026-10-09-0534.txt (harness dev 14/14; harness fast de verificat ca s-a terminat 4/4).

Starea la 2026-10-15: fazele 1-10 facute (vezi git log si results/). Faza 11 pe ramura faza-11-tier3:
- 11a incidente: gata (incidents.py, tier3.py --once; attack_run.sh -> un singur incident).
- 11b reguli: gata in dry-run (rules.py, tier3.py --once --reguli). Sursele golului: etichete umane de atac si Tier 2 malicious cu acord A/B. Nimic nu se creeaza in Kibana pana la: cheia Kibana separata (tier3-generated), filtrul tier3-shadow in orchestrator (cu harness dev + fast) si aprobarea lui Tiberiu.
- 11c vanatoare ATT&CK (ramura faza-11c-vanatoare, 2026-10-16): hunt.py, 13 sabloane ES|QL scrise de om pe 12 tehnici; codul alege 2 tehnici/ora (cele vanate cel mai demult), modelul scrie ipoteza si alege sablonul + fereastra (HuntPlan validat, implicite la esec); potrivirile noi -> Case origin=tier3_hunt -> Tier 2 (max 3/rulare), restul la om; acoperirea, inclusiv negativa, in soc-hunts. Porti: dev 14/14 (recall 100%, FP 0/6); 566 teste. Timer: prima vanatoare automata 2026-10-16 07:06 (systemd: 2 potriviri la Tier 2; chei SSH: negasit).
Ramase din diagrama: executorul dry-run (politici), scheduler-ul Tier 3 (timer systemd, de aprobat).

## Promptul original (fidel)

FAZA 1 — Securitate si reparatii mici
Aceste reparatii le-as fi scris eu: pentru fiecare, ARATA-MI diff-ul propus si asteapta aprobarea inainte sa-l aplici.
a) hunt_path.py: parametrizeaza cele 4 interogari ES|QL (execution_facts: principala, fallback-ul cu LIKE -> STARTS_WITH, lookup-ul sudo; recent_host_alerts). Foloseste _esql din elastic_tools. int(minutes).
b) fast_path.py: node_finalize intoarce floor_applied (camp nou in FastState); lookup_history foloseste {"term": {"rule_name.keyword": rule_name}} in loc de match.
c) Deduplicarea (BoundedSeen) persista intre restarturi (fisier de stare langa cursor sau index), ca sa nu se reproceseze findings.
d) escalation.py: LOW_CONF implicit 90.
Poarta: test unitar de injectie (nume de proces cu ghilimele si operatori ES|QL -> interogarea nu se rescrie, execution_facts intoarce curat); harness dev 14/14.

FAZA 2 — Lantul in audit si escaladarea inregistrata
- In schemas.py: chain_id in Verdict si AuditRecord; escalation_reasons (lista de EscalationReason) in AuditRecord; modelul Case (chain_id, origin: tier1_alert | rarity_sweep | tier3_hunt, host, entity_id, parent, child, rule_name, escalation_reasons, evidence_refs) — FARA classification/confidence/narrative de la Tier 1.
- Orchestratorul apeleaza should_escalate dupa Tier 1 si scrie decizia in audit. NU apeleaza inca Tier 2.
- Unifica logica duplicata dintre main() si process_alerts(); ramura manuala de sweep trece si ea prin decide() si persist().
Poarta: teste unitare pentru should_escalate si Case; orchestrator --once pe ultimele 60 min ruleaza fara erori; raport cu rata de escaladare observata.

FAZA 3 — Interfata de etichetare
- O interfata web minimala servita local pe elastic-lab (Flask sau FastAPI, un singur fisier + template), accesibila din browser pe reteaua de laborator, protejata cu parola din mediu.
- Lista
[... promptul original se opreste aici ...]

## Fazele urmatoare (din lista de sarcini, in ordine)

3. **Interfata de etichetare.** Omul marcheaza verdictele (TP/FP/FN/TN) cu ground_truth si label_source=human. Deblocheaza RAG, drift, absolvirea pe clase si metricile. Web minimal local pe elastic-lab (Flask/FastAPI, un fisier + template), parola din mediu.
4. **Siguranta la caderea modelului si modul degradat.** Model/tunel cazut -> tot ce e in curs escaladeaza, nimic nu se inchide. Restanta peste prag -> coada prioritizata (severitate, criticitate); alertele grave escaladeaza direct fara model. Plafon de timp per caz.
5. **Trasarea uneltelor si evidence_refs.** Per caz si per apel de unealta: argumentele, ID-urile documentelor returnate (nu textul), durata si tokenii. Populeaza evidence_refs in Verdict. Raspunde la "de ce a gresit agentul la cazul X".
6. **Legarea Tier 1 -> Tier 2.** Modelul Case, case_adapter (alerta/finding -> Case, fara verdictul Tier 1), seed pornit din entity_id, apel real la Tier 2 din orchestrator, harness pe lantul complet.
7. **Investigatorul B pe RedSage, cu rata de acord.** B pe alt model decat A, pentru erori mai putin corelate. Masurat: rata de acord A/B cu un model vs doua.
8. **Dashboard de metrici din audit.** Rata de escaladare, latenta, tokeni, acord A/B, precizie/recall pe etichete umane per nivel, plus drift global. Calculat din soc-audit si soc-traces, in afara grafului.
9. **Tier 1 extins si studiul de ablatie.** enrich cu threat intel si alerte corelate, RAG pe cazuri etichetate de om, 3 unelte read-only; configuratiile A-D masurate cu harness, inclusiv rezistenta la injectie. Miezul lucrarii de licenta.
10. **Alertele native Elastic Defend tratate corect.** Normalizarea campurilor alertelor native (ML malware, comportament, memorie) inainte de Tier 1, ca sa nu mai fie clasate gresit ca benigne. Verificat ca protectiile din politica Defend sunt in modul detect. Dupa legarea Tier 1 -> Tier 2.
11. **Tier 3: incidente, reguli, vanatoare.** In ordine: gruparea in incidente (test cu attack_run.sh), propuneri de reguli EQL cu shadow si promovare, vanatoare pe ipoteze ATT&CK dupa senzorii noi.
12. **Senzori pentru 0-day.** In ordine: honeytokens (atingere = escaladare mereu, criteriu nou in should_escalate); sweep extins (new_destination_asn, new_webroot_write, new_listening_port, response_size_outlier, cai URL noi) plus reguli New Terms; auditd + FIM; Suricata (beaconing, DNS, JA4); YARA pe webroot; anomalii ML simple in Python (beaconing, entropie DNS) ca findings. Atentie: joburile ML Elastic cer licenta platita, trial-ul expira la mijlocul lui octombrie.

Faza 12, pasul 1 — honeytokens (ramura faza-12-senzori, 2026-10-16): honeytokens.py (momeli + 3 reguli cu rule_id fix), motivul de escaladare honeytoken (mereu), podele pe Tier 1 si Tier 2, grav in restanta. Plantarea pe web-prod si regulile din Kibana le face omul (deploy/web-prod/honeytokens.sh, deploy/kibana/honeytoken_rules.py).
Faza 12, pasul 2 — sweep extins: run_full_sweep legat in orchestrator (pana acum rula doar parinte-copil); destinatii noi, porturi noi care accepta conexiuni, cai URL noi servite cu succes, raspunsuri anormal de mari, scrieri in webroot grupate pe fisier. Baseline live pe 30 de zile, fara transform.
Faza 12, pasul 3 — auditd (Fleet; FIM renuntat: blocat in Fleet, acoperit de Defend + auditd + YARA) si audit=1 la boot pe web-prod; honeytoken de citire soc-honeytoken-read (vede si citirea din apache2, deci din webshell PHP).
Faza 12, pasul 4 — anomalii in Python (anomalies.py): beaconing (CV intervale <= 0.25, 6+ conexiuni in 6 h) si DNS (eticheta >= 20 caractere cu entropie >= 3.5, sau >= 30 subdomenii unice); verificate pe trafic real generat.
Faza 12, pasul 5 — Suricata 7.0.10 pe web-prod (IDS pasiv af-packet, community-id, JA4, ET Open 53k semnaturi, integrare Fleet); sweep new_ja4; sweep-ul parinte-copil exclude thread-urile kernelului (parinte PID 2, fara executabil).
Faza 12, pasul 6 — YARA pe webroot: 5 reguli proprii (deploy/web-prod/yara), scanare la 10 min + la creare in /var/www/html, doar potrivirile noi in jurnal (soc-yara) -> regula Kibana soc-yara-webshell -> calea rapida cu motivul sensor_detection (fara podea: YARA poate fi FP).
Porti faza 12 (2026-10-16): dev 14/14 (recall 100%, FP 0/6), fast 4/4; 538 teste unitare.

Executorul dry-run (ramura faza-13-executor, 2026-10-15): executor.py construieste planul (pasi argv / API, rollback, expirare, criticitate, absolvire din etichete umane: >= 50, precizie >= 95%, 0 FN in 30 zile); planul intra in soc-audit (execution_plan). Nu exista cod de executie reala.

Faza 14 — ferestre de mentenanta (ramura faza-14-mentenanta, 2026-10-19): maintenance.py valideaza ferestrele din asset-inventory (recurente <= 8 h, inclusiv peste miezul noptii; unice <= 72 h; motiv obligatoriu; invalidele ignorate) si le evalueaza la ora EVENIMENTULUI (Tier 1: kibana.alert.original_time; Tier 2: @timestamp-ul procesului sau inceputul si sfarsitul potrivirii de vanatoare). Tier 2 calculeaza acum in_maintenance_window (inainte lipsea, deci podeaua trata orice actiune sensibila ca fiind in afara ferestrei). Fereastra + admin cunoscut ridica doar podeaua "actiune sensibila"; contul web, momelile, YARA si detectiile EDR raman la om. Ferestrele le scrie omul cu contul elastic, direct in asset-inventory (comanda in docstring-ul maintenance.py; deploy/inventory_windows.py a fost sters la curatenia 9b391a1).
Porti faza 14 (2026-10-19): dev 14/14 (recall 100%, FP 0/6), fast 4/4; 624 teste unitare.
Ablatia A-D reluata pe codul fazei 14 (2026-10-19, alertele salvate pe 13.10, qwen3:14b pe Tier 1): 28 TP, 8 TN, 0 FP, 0 FN pe toate configuratiile, injectie 10/10; RAG si uneltele nu schimba acuratetea, uneltele dubleaza latenta (p50 ~27 s vs ~15 s) si adauga ~60% tokeni. check_scenarios.py terminat (validatorul setului de ablatie, cu teste).

## Starea finala (2026-10-19)

Toate fazele din lista sunt facute in cod: Tier 1, Tier 2, Tier 3 (incidente, reguli, vanatoare), senzorii pentru 0-day, executorul dry-run, ferestrele de mentenanta. Porti: dev 14/14, fast 4/4, ablatie 36/36 pe fiecare configuratie; 631 teste unitare.

Raman la om (nu le face agentul, prin principiile de mai sus):
- revizuirea si merge-ul in main, push-ul, restartul soc-orchestrator;
- ferestrele de mentenanta (asset-inventory, contul elastic; comanda in maintenance.py);
- etichetarea in interfata (ground_truth, label_source=human) — deblocheaza absolvirea executorului si metricile pe etichete;
- schimbarile pe web-prod (ex. actualizarea zilnica a regulilor Suricata) si in regulile Kibana;
- alegerea si rularea testelor Atomic Red Team.

## Program 0-day web: acoperirea lantului de atac WordPress (faze 15-18)

Scopul: sa detectam exploatarea unui WordPress/plugin vulnerabil pe tot lantul —
inainte (expunere + recon), in timp (tentativa de exploit) si dupa (consecinta).
Nu e acoperire totala (0-day fara semnatura, payload criptat, persistenta doar in
DB raman gauri reale), ci aparare in adancime, mai multe straturi imperfecte care
prind consecinta, nu exploitul anume. Fiecare faza pe ramura ei, nemergeuita.

Faza 15 — consecinta fileless (ramura faza-15-0day-fileless, nemergeuita): sweep
suspicious_exec_path in timp real (/tmp, /var/tmp, /dev/shm, memfd, binare sterse),
promovat din vanatoarea Tier 3. Porti: dev 14/14, fast 4/4; teste unitare verzi.
(Plus 4 reguli YARA generice pentru injectoare JS / plugin-uri care se ascund,
validate pe wp-warden: prins pe response_size_outlier + new_webroot_write + YARA.)

Faza 16 — detectie de recon/enumerare (ramura faza-16-recon-wp): doua sweep-uri noi
pe logurile Apache, faza "inainte". web_enumeration: un IP care aduna multe raspunsuri
de eroare (>= ENUM_MIN_ERRORS) pe multe cai distincte (>= ENUM_MIN_PATHS) in fereastra
— scanare cu wpscan/nuclei, fara baseline (largimea si ritmul tradeaza, nu noutatea);
prag aplicat in Python (enumeration_hits, pur). wp_recon_path: acces la puncte de
dezvaluire a versiunii si enumerare (readme.html/txt, license.txt, /wp-json/wp/v2/users,
xmlrpc.php) — cai constante proprii, nu interpolate din telemetrie. Ambele: source.ip,
url.path si user_agent sunt DATE (UNTRUSTED_DETAIL_KINDS), dedup pe IP respectiv pe cale.

Faza 17 — detectie de tentativa de exploit (facuta, detaliu mai jos): alertele Suricata web-attack
(ET-WEB) ridicate ca detectie proprie cu podea, nu doar unealta de Tier (Suricata
ruleaza semnaturile la senzor, noi doar citim alertele: principiul 3 respectat).
Optional, un clasificator in Python pe formele generice (LFI ../, php://, markeri SQLi),
pe randuri aduse cu interogare statica — tratate ca DATE, nu ca text de interogare.

Faza 18 — constiinta de expunere / CVE pe versiuni vechi (facuta, detaliu mai jos):
colector pe web-prod care citeste "wp core version" + "wp plugin list" -> asset-inventory,
incrucisat cu un feed local kb/wp_vulns.yml; hunt Tier 3 care marcheaza componentele
vulnerabile instalate. Platforma reala: cand expunerea stie ca plugin X e vulnerabil SI
recon/exploit-ul loveste endpoint-ul lui X, corelatia (cod determinist) = alerta de
incredere mare, devreme. Colectorul = schimbare pe web-prod: comenzi propuse, aprobare.
## Faza 17 — detectie de tentativa de exploit (Suricata web-attack)

Ramura faza-17-exploit-suricata (din main). Etapa "in timp" a lantului: alertele
Suricata de atac web, ridicate ca detectie proprie de senzor, nu doar unealta de Tier.
Pana acum alertele Suricata se vedeau doar reactiv (tool_suricata_alerts, in
investigatia Tier 2); acum o regula Kibana proprie le transforma in alerte care intra
pe calea rapida (Tier 1), exact ca YARA (faza 12).

Mecanism (oglindeste YARA, principiile intacte):
- sensor_rules.RULES primeste soc-suricata-webattack: regula Kibana (query kuery pe
  logs-suricata.eve-*, event.kind="alert" si rule.category in setul de atac web ET),
  T1190. Categoriile sunt constante ale setului de reguli, nu telemetrie (principiul 3).
- suricata_facts(alert): {sensor, signature, category, source_ip, destination_ip}
  validate — categoria din multimea inchisa WEB_ATTACK_CATEGORIES, source.ip validat
  ca IP, semnatura scurtata la 200; altfel None. sensor_facts() dispeceza YARA vs Suricata
  dupa rule_id. Semnatura/categoria sunt DATE in prompt.
- Escaladare: is_sensor_alert acopera deja SENSOR_DETECTION in orchestrator -> alerta
  escaladeaza mereu, FARA podea de verdict (Suricata/ET poate fi FP, ca YARA).
- fast_path: contextul senzorului generalizat (YARA aduce nota despre scanner; Suricata
  e senzor de retea, fara proces); regula pe fapte (FACT_RULES) acopera ambii senzori.
- honeytokens.TACTIC primeste T1190 (Initial Access).

Regula Kibana o creeaza OMUL cu scriptul existent (ia automat tot sensor_rules.RULES):
  python3 deploy/kibana/honeytoken_rules.py aplica   (contul elastic, parola la tastatura)
Nimic nu se creeaza/modifica in Kibana din agent.

Porti: teste unitare verzi (641); harness dev + fast de rulat la final (atinge Tier 1).

## Faza 18 — constiinta de expunere / CVE pe versiuni vechi (WordPress)

Ramura faza-18-expunere-cve (din main). Etapa "inainte" a lantului: sa stim ce
componente vulnerabile sunt instalate, inainte sa le exploateze cineva. Platforma
reala vine din corelatie: expunerea stie ca pluginul X e vulnerabil + recon/exploit
(fazele 16-17) loveste fix X -> alerta de incredere mare, devreme (cod determinist).

Bucata 1 — motorul offline determinist (FACUT, nu atinge nimic):
- kb/wp_vulns.yml: lista de versiuni vulnerabile (component core sau slug plugin,
  interval introduced..fixed, severitate, CVE). In git, revizuita de om. Exemple de
  laborator; feed real (WPScan/wpvulndb, acelasi format) prin WP_VULNS_FEED.
- exposure.py: comparator de versiuni pur (parse_version, in_range introduced<=v<fixed),
  validarea feed-ului (parse_entries: slug/versiune/severitate/CVE in multimi/forme
  inchise), normalize_installed (accepta forma `wp plugin list`), vulnerable_components
  (potrivire pura, sortata dupa severitate). Fara model, fara retea, fara ES.
- tests/test_exposure.py: comparator, limite introduced/fixed, validare, potrivire (20).

Bucata 2 — colectorul + legarea in Tier 3 (FACUT in cod; deploy-ul de APROBAT):
- wp_inventory.py: colector care ruleaza pe elastic-lab (cheia de writer NU se copiaza
  pe web-prod), intreaba web-prod prin ssh cu WP-CLI fara sudo (`wp core version`,
  `wp plugin list --fields=name,version,status --format=json`) si scrie un document
  curent in soc-wp-inventory (indice dedicat, ales de om). `arata` = dry-run, `scrie`
  = scrie; `--fisier` citeste dintr-un JSON local (test). build_doc/parse_plugin_json pure.
- exposure.py: corelatie pura adaugata. component_from_path (slug din
  /wp-content/plugins|themes/<slug>), correlate (componenta vulnerabila INSTALATA +
  lovita de recon = corelatie per source_ip/componenta; 'core' prinde orice atingere
  de atac pe host), installed_from_doc, correlation_key, make_exposure_case
  (Case origin=tier3_hunt, HUNT_MATCH, T1190/wp_exposure — fara schema noua).
- tier3.py: `--expunere` (run_exposure). Citeste inventarul (soc-wp-inventory), afla
  vulnerabilele (vulnerable_components), aduce atingerile Apache pe suprafata WordPress
  (ES|QL cu prefixe constante, host prin params — nicio valoare din telemetrie in text),
  coreleaza, trimite primele TIER2_BUDGET corelatii noi la Tier 2 (shadow) cu --scrie,
  restul in soc-hunts pentru om. Esecul oricarui pas -> status error, nu opreste.
- Teste: tests/test_exposure.py (+15: potrivire cale, corelatie, caz), test_wp_inventory.py
  (4: parsare, build_doc), test_tier3_exposure.py (4: dry-run, fara vulnerabilitati,
  inventar lipsa, buget Tier 2) — fara ES, fara model, fara ssh.

Deploy FACUT si validat live (2026-10-22): indicele soc-wp-inventory creat; ES_WRITER_API_KEY
primeste write+create_index, ES_API_KEY (read-only) primeste read pe soc-wp-inventory; colectorul
a scris inventarul real (core 7.1.3, akismet 5.7.2, hello 1.7.2) si --expunere a corelat cap-coada
un recon extern (172.20.99.220) cu core + hello vulnerabile (akismet nevulnerabil: zero FP),
self-IP exclus, Tier 2 shadow -> suspicious/escalate_human, acoperire in soc-hunts.
Optional ramas: timer systemd pentru wp_inventory.py pe elastic-lab.

Bucata 1 — porti: teste unitare verzi (652). Nu atinge verdictul: harness neimplicat.
Bucata 2 — porti: teste unitare verzi (677, +25). Corelatie determinista (cod decide),
granita Pydantic reutilizata (HUNT_MATCH), interogari parametrizate. Nu atinge calea de
verdict Tier 1/2, deci harness-ul nu e implicat; dry-run live posibil dupa deploy (`--expunere`).

# Plan de finalizare: ce se scoate si ce se adauga (2026-11-02)

Scop: un SOC agentic pe 3 niveluri FUNCTIONAL si CORECT, demonstrabil cu cifre, nu doar proiectat.
Pornim de la starea reala (docs/pasi/stare.md): pasii 0-4, 6, 7, 9-12b facuti; 5 si 8 raman la om.
Principiile din CLAUDE.md raman neatinse: codul decide, modelul judeca; esecul escaladeaza;
shadow permanent; ireversibilul la om.

## 0. Ce ramane neschimbat (punctele tari, nu se ating)

- Granita Pydantic (extra=forbid), interogari parametrizate, podelele de cod (inclusiv podeaua 4:
  serverul web a pornit un proces -> malicious + om).
- Tier 2 fara verdictul Tier 1; A/B cu coroborare; Tier 3 cu sabloane inchise si shadow 7 zile.
- Detectia pe CONSECINTE (comportament, momeli, raritate, AIDE, tacere) ca raspuns la 0-day.
- Auto-monitorizarea (absence_check, watchdog, sonda LLM, puls, sanatate ES).
- Telemetria delimitata ca neincrezatoare in ambele tier-uri; suita de injectie ca poarta.

## 1. De SCOS sau de redus

| # | Ce | De ce | Cum |
|---|---|---|---|
| S1 | Triajul cu modelul din analiza statica (static_triage.py, rolul `static_triage`) | masurat: 3/3 "adevarat pozitive" verificate manual erau false; produce zgomot, consuma GPU saptamanal | ramane DOAR partea determinista: fisiere de core modificate fata de checksum-urile oficiale (semnal real de backdoor) + Semgrep pe plugin-uri/teme raportat brut omului, fara model, fara draft_rule. Promptul v2 ramane in repo (istoric). |
| S2 | Investigatorul B pe acelasi model (qwen3:14b, temperatura 0.7) | doua rulari ale aceluiasi model nu sunt doua opinii: sunt una + zgomot; zgomotul e exact variatia de FP (1-3 din 6 benigne) | decizie prin masuratoare cu harness-ul de ablatie: (a) B pe RedSage 8B (model diferit) sau (b) fara B, bugetul de unelte dat lui A. Se pastreaza varianta cu recall 100% si FP minim. |
| S3 | Criticul din hunt_path (DISABLE_CRITIC=1) | masurat daunator la 14B; cod mort cu ramura oprita | se sterge ramura si promptul `hunt.critic` din registru (bump in MANIFEST). |
| S4 | Investitii in blocare (executor real, soc-block-gate, nft blocked_v4) | in aceasta topologie (un singur IP SNAT) blocarea e auto-vatamare; c9 nu poate trece niciodata | ramane exact ce exista: readiness zilnic + garzi dry-run. Nu se mai scrie nimic aici. |
| S5 | Jurnalul de audit ModSecurity cu corpul cererilor | parole in clar fara HTTPS; fara valoare de detectie in plus | ramane oprit (SecAuditEngine Off). Dupa HTTPS se poate reconsidera, doar cu partile fara corp. |
| S6 | Regulile YARA pe WordPress core | fals pozitive dupa fiecare update de core (60 potriviri pe 26.10) | scannerul sare fisierele identice cu checksum-urile oficiale WP (aceeasi logica ca S1). |

## 2. De ADAUGAT (goluri de design)

| # | Ce | De ce | Cum (determinist, mic) |
|---|---|---|---|
| A1 | **Ciclul de viata al cazului** (Case cu stare) | azi unitatea e alerta; un SOC lucreaza pe cazuri: open -> investigating -> escalated -> closed(motiv) cu proprietar si eticheta | un model Pydantic `CaseRecord` (chain_id, stare, tier curent, motive, dovezi, verdicte, etichete), index `soc-cases`, tranzitii in cod, inchidere DOAR de om (din interfata de etichetare, care devine coada de cazuri). |
| A2 | **Playbook de raspuns ca livrabil** | executia ramane la om; iesirea utila a unui caz critic e planul pregatit, nu "escalate_human" sec | executorul deja construieste planuri dry-run (pasi argv, rollback, expirare): se ataseaza cazului si se afiseaza omului ca "ce ai de rulat, in ce ordine, cum anulezi, ce colectezi intai". Shadow devine raspuns asistat. |
| A3 | **Scor de risc pe entitate, in timp** (host, IP sursa, user) | tiparele lente (recon low-and-slow, actiuni legitime repetate dupa intrare, beaconing sub prag) nu se vad pe un singur eveniment | scor acumulat cu decadere (cod pur), alimentat de alerte, raritate, honeytoken, ModSecurity; peste prag -> caz de tip `entity_risk` spre Tier 2. Intra in context (fapt calculat de cod). |
| A4 | **Pagina de stare a SOC-ului** (una singura) | demo-ul si examenul au nevoie de O vedere: readiness, sanatate, cazuri deschise, ultimele porti | dashboard Kibana "SOC Status" din panourile existente (SOC Health + readiness + soc-cases + soc-metrics tip gate). |
| A5 | **Rezultatele portilor in soc-metrics** (`type=gate`) | azi portile sunt fisiere text in results/; teza are nevoie de curbe, nu de capturi | harness.py scrie la final un document (set, TP/FN/TN/FP, recall, FP rate, prompt_set, model_tag, commit). |
| A6 | **Propuneri de lista alba din benign-ground-truth** | recalibrarea FP e manuala si nu se va face | fp_rate.py propune (nu aplica) excluderi per regula din traficul benign dovedit; omul aproba in interfata; promovarea scrie in build_whitelists. |
| A7 | **Determinism pe Tier 1** | cifrele tezei trebuie reproductibile | temperatura 0 + seed (deja) pe `fast`; explorare doar in Tier 3 (ipoteze). `make determinism` ca poarta la orice schimbare de prompt/model. |

## 2b. Stare (2026-11-02, seara)

| # | Stare |
|---|---|
| S1 | FACUT (90c3a72): STATIC_USE_MODEL=0 implicit; core_drift (modificat / necunoscut) -> open |
| S2 | DE MASURAT (harness de ablatie: B pe RedSage vs fara B) — dupa pasul 8 |
| S3 | FACUT: criticul sters; prompt_set nou |
| S4 | FACUT prin decizie (doar readiness + garzi dry-run) |
| S5 | FACUT (SecAuditEngine Off) |
| S6 | FACUT (90c3a72): YARA sare fisierele identice cu sumele oficiale |
| A1 | FACUT (74d7a70): cases.py + soc-cases + /cases in interfata; cere pas-a1-cases.sh (om) |
| A2 | FACUT (74d7a70): playbook-ul executorului atasat cazului, afisat in /cases |
| A3 | FACUT (8432e61): risk.py, sweep orar entity_risk -> Tier 2 |
| A4 | FACUT (6de4b71): soc-status.ndjson (import de om, ca SOC Health) |
| A5 | FACUT (90c3a72): harness scrie type=gate |
| A6 | FACUT (6de4b71): propuneri de lista alba in soc-metrics + data/whitelist-proposals.json |
| A7 | FACUT (pas 8): seed + top_p fix pe toate rolurile; `make determinism` |

Toate sunt COD + teste, NEAPLICATE pe es-node-1 pana la o poarta (dev + val + injectie) dupa
poarta podelei 4. Pe hosturi: pas-a1-cases.sh si importul soc-status.ndjson rulate de om pe 2026-11-03 (FACUT).

## 3. Ordinea de executie

1. (azi) poarta podelei 4 -> restart orchestrator -> HTTPS/SSH pe web-prod -> benign-gen pornit.
2. Pasul 5 (ART, ~20 tehnici, omul da "ok" per test) -> coverage.py -> gap_list in Tier 3.
3. Pasul 8: etichete (>= 50 atac + >= 50 benign; alertele ART sunt sursa rapida) -> `make golden`,
   `make regression`, `make determinism`.
4. S1 + S6 (static fara model, YARA fara core) - o zi.
5. A1 + A2 (cazuri + playbook) - 2-3 zile; apoi A4 (pagina de stare).
6. S2 (masuratoare A/B vs fara B vs RedSage) - o zi de harness; decizie pe cifre.
7. A3 (scor de risc) + A6 (liste albe propuse) - 2 zile.
8. A5 + A7 - jumatate de zi; S3 - o ora.
9. 30 de zile de rulare cu benign-gen, etichetare saptamanala, readiness zilnic. Abia apoi:
   fuzzing (faza separata), iesirea din shadow (daca se schimba vreodata topologia).

## 4. Criterii de "functional si corect" (poarta finala)

- Recall 100% pe toate seturile (fast, dev, val, injectie, ART >= 20 tehnici: fiecare tehnica
  detectata sau cel putin logata, niciuna nevazuta fara ipoteza Tier 3).
- Injectie: >= 98% identic, 100% pe atac, in ambele tier-uri, pe suita in memorie SI pe
  scenariile cu telemetrie reala.
- Determinism >= 98% pe 2 rulari; nicio schimbare malicious <-> benign.
- FP pe benign-gen < 5% per regula de retea (sau regula listata pentru recalibrare, nu oprita).
- 24 h de cicluri fara gol > 4 min; zero alerte honeytoken fara test in 48 h; backup < 26 h;
  snapshot < 26 h; readiness evaluat zilnic (ready=false e raspunsul corect in laborator).
- Fiecare caz critic are playbook atasat; fiecare caz inchis are eticheta umana si motiv.
- Teste unitare verzi local si pe es-node-1; prompturile versionate; CLAUDE.md la zi.

## 5. Ce face omul (si nimeni altcineva)

- "ok" per test ART (pasul 5); etichetele (pasul 8); inchiderea cazurilor (A1).
- Deciziile cu masuratori: S2 (B sau nu), aprobarea listelor albe (A6).
- Orice schimbare pe hosturi, chei, reguli Kibana; restartul orchestratorului.
- Rotatia cheilor la 90 de zile (prima: 2027-01-06; corectat 2026-11-04); licenta ES (trial -> basic) inainte de expirare.

## 6. Ce NU se face in acest proiect

Blocare/izolare/kill automat; fuzzing; mai multe reguli "de dragul numarului"; model schimbat
fara ablatie; etichete scrise de cod; copie off-host a snapshot-urilor (decizie luata; gol notat).

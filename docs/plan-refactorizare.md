# Plan de refactorizare: de la orchestratorul serial la monolitul modular pe cozi

Scris fara diacritice, ca restul documentatiei din depozit. Fiecare faza e o sarcina de sine
statatoare, pe ramura ei, cu oprire si raport la final (regulile din CLAUDE.md raman valabile).

Tinta: structura `elasticlab/` cu procesele `adaptor`, `worker_t1`, `worker_t2`, `scriitor`,
legate prin RabbitMQ. Logica de verdict (fast_path, hunt_path, escalation, policy, podele)
NU se rescrie; se muta si se cheama din alt loc.

Lucrul se face in worktree-ul `~/lab-refactor` (nu in `~/lab`, din care ruleaza `soc-orchestrator`).

## 0. Inainte de orice (decizii ale omului)

Decise de om pe 2026-11-23, puse in cod pe ramura `faza-23-decizii` (din `faza-23-inchidere-conceptuala`):

- [x] Ramura de baza: tot din `faza-23-inchidere-conceptuala`, FARA `cada43f` (regula asimetrica).
      `faza-23-decizii` = faza-23 + revert `cada43f` + cele doua reparatii de mai jos. Faza 24 porneste din ea.
- [x] Regula asimetrica din etapa 5: SCOASA (varianta c). Ramane masuratoarea din etapa 2 ca limita
      cunoscuta. Consecinta pentru faza 26: `result_has_rows` nu mai exista (a venit cu `cada43f`);
      plicul de rezultat se face fara el, iar regula pentru benign fara dovezi vine dupa refactorizare.
- [x] Defectul `action_target`: REPARAT separat (`7cf3216`). Tinta invalida -> `None` + `escalate_human`
      in `fast_path` si `hunt_path`, clasa ramane. Harness-ul puncteaza exceptia din graf ca escaladare
      (undetermined + escalate_human, ca orchestratorul) si listeaza separat scenariile nepunctate
      (alerta negasita, fara rule_name).
- [x] Pragul pentru `isolate_host` / `rotate_credentials`: 101 (`992a742`), ca in CLAUDE.md.

Revertul si pragul 101 schimba decizia fata de productie (80a867c), deci referinta portilor se reface:
omul ruleaza poarta (fast, dev, validare, injectie; dev/validare/injectie de 3 ori pentru intervalul FP
al Tier 2) pe `faza-23-decizii` inainte ca o faza care atinge verdictul (25+) sa fie comparata cu ea.

## Reguli valabile in toate fazele

- O ramura pe faza (`faza-NN-nume`), commit-uri mici, fara push si fara merge.
- Nicio comanda pe hosturi fara confirmarea omului. Instalarile (RabbitMQ, Postgres, poarta de
  inferenta, unitati systemd noi) se PROPUN ca lista de comenzi si le aplica omul.
- Nu se modifica `ExecStart` din `deploy/soc-orchestrator.service`. Shadow ramane fortat.
- Secretele nu se afiseaza, nu se comit, nu se copiaza.
- Nu se sterg fisiere pana la faza 33; la vechea cale ramane un fisier subtire.
- Teste unitare noi pentru orice functie noua (pytest, fara model si fara Elasticsearch).
- Referinta portilor: fast 4/4, dev recall 8/8, validare 8/8, injectie 4/4, suita 48/48,
  determinism >= 98% identic. Tier 2 variaza la fals-pozitive intre rulari: se compara
  recall-ul si suita de injectie, iar FP se raporteaza ca interval pe 3 rulari.
- Orice regresie = oprire si raport. Nu se ajusteaza scenarii sau praguri ca sa treaca.
- Pana la faza 33 exista un comutator `SOC_PIPELINE=legacy|queue`. `legacy` e calea de azi si
  ramane implicita pana cand `queue` trece toate portile.

## Sarcina pentru firma (2026-11-24): ordinea care se aplica de acum

Omul a dat pe 2026-11-24 "Sarcina pentru firma: SOC care rezista la trafic mare" (test de incarcare
cu sase conditii: nicio alerta pierduta, clasele critice la om in tinta, restul cu verdict sau
escaladate pana la termen, coada se goleste singura, caderile nu pierd nimic, verdictele de
referinta). Ea inlocuieste ordinea fazelor 26-33 de mai jos; fazele 24 si 25 sunt deja facute pe
ramuri, iar numerotarea din depozit continua de la ele:

| Faza (depozit) | Faza (sarcina) | Ce | Stare |
|---|---|---|---|
| 24 `faza-24-structura-pachet` | — (sarcina spune "fisierele nu se muta"; mutarea era deja facuta, cu cai vechi aliate) | structura de pachet | pe ramura, porti nerulate |
| 25 `faza-25-timpul-alertei` | 24 | timpul alertei | pe ramura, porti nerulate |
| 26 `faza-26-intrare-grupare` | 25 | intrare fara pierderi, grupare, potop, critice la intrare | pe ramura (docs/faza-26-intrare-grupare.md) |
| 27 `faza-27-cozi-workeri` | 26 | RabbitMQ (PROPUS), patru procese, reincercari, esuate, termen de varsta | urmeaza |
| 28 `faza-28-inferenta-paralela` | 27 | poarta de inferenta (PROPUSA), debit la 1/2/4/8 | |
| 29 `faza-29-test-incarcare` | 28 | `eval/replay.py`, trei profiluri, trei defecte, comparatie cu legacy | |
| 30 `faza-30-pregatire-firma` | 29 | profil de host si harta de campuri din configurare, citire/scriere separate | |

Raman pentru dupa (nu tin la rafala): plicul de rezultat al uneltelor, lantul de audit, starea pe
pas la Tier 2, pachetul de dovezi, agregatele pe entitate. In afara sarcinii: data lake-ul,
capcanele, scorul ieftin, inchiderea fara model, Arcanna.

Deschise, de stabilit de om cu firma inainte de faza 29: in cat timp ajunge o alerta critica la om;
termenul pentru restul alertelor; marimea rafalei de dimensionat (alerte pe minut la varf).
Structura modulelor si regulile de import: docs/arhitectura-monolit-modular.md.

## Ordinea si dependentele (planul initial, 2026-11-23; inlocuit de tabelul de mai sus)

| Faza | Ce face | Atinge verdictul | Cere instalari |
|---|---|---|---|
| 24 | structura de pachet | nu | nu |
| 25 | timpul alertei | da | nu |
| 26 | contracte de mesaje si plicul de rezultat al uneltelor | nu (regula neschimbata) | nu |
| 27 | adaptor de intrare si grupare, in acelasi proces | nu | nu |
| 28 | Scriitor si lant de audit | nu | nu |
| 29 | cozi si workeri | nu (aceeasi logica) | RabbitMQ |
| 30 | Tier 2: stare pe pas si pachet de dovezi | da | Postgres |
| 31 | poarta de inferenta | nu (acelasi model) | poarta de inferenta |
| 32 | agregate pe entitate pentru sweep | da | nu |
| 33 | curatenie si inchidere | nu | nu |

---

## Faza 24 — structura de pachet (`faza-24-structura-pachet`)

Scop: modulele din radacina ajung in `elasticlab/`, fara nicio schimbare de logica.

1. Noteaza starea de plecare: numarul de teste verzi si setul de prompturi (`prompts.py --check`).
2. Gaseste toate caile construite din `Path(__file__)` (kb/, prompts/, detections/, scenarii).
   Fa `elasticlab/paths.py` cu radacina depozitului si foloseste-l in ele. Commit separat.
3. Creeaza subpachetele: contracts, core, intake, tier1, tier2, tier3, store, bus, ops, extras,
   eval, apps.
4. Muta fisierele INTREGI cu `git mv`, de jos in sus: contracts -> core -> store -> tier1 ->
   tier2 -> tier3 -> ops -> extras -> eval -> apps. Fara despartiri si fara redenumiri.
5. Dupa fiecare grup: la vechea cale ramane un fisier care aliaza modulul nou (acelasi obiect de
   modul, nu `import *`); scripturile rulate direct cheama in continuare `main()`; `pytest`; commit.
6. Adauga regula de importuri (import-linter): `contracts` si `core` nu importa din rest;
   `tier1` si `tier2` nu se importa intre ele. Incalcarile se LISTEAZA, nu se repara acum.

Gata cand: acelasi numar de teste verzi, acelasi set de prompturi, importurile vechi merg,
toate caile din `ExecStart` exista. Portile le ruleaza omul; trebuie sa iasa ca referinta.

Oprire: un test pica din alt motiv decat o cale sau un import; setul de prompturi se schimba.

## Faza 25 — timpul alertei (`faza-25-timpul-alertei`)

Scop: tot ce tine de timp in logica de verdict se raporteaza la momentul alertei, nu la
momentul prelucrarii. Conditie pentru cozi: o alerta poate fi prelucrata cu intarziere.

1. Inventar: toate folosirile de `now()`, `utcnow()` si ale ferestrelor relative din
   fast_path, hunt_path, elastic_tools, maintenance, incidents, rules, degraded. Tabel in raport:
   loc, ce calculeaza, daca trebuie sa treaca pe timpul alertei.
2. `elasticlab/core/eventtime.py`: functii pure care primesc explicit timpul alertei.
3. Inlocuieste folosirile marcate in inventar. Timeout-urile pe caz si ceasul de garda raman
   pe timpul real.
4. Test nou: aceeasi alerta trecuta prin calea rapida imediat si cu intarziere simulata de
   60 de minute da acelasi verdict. La fel pentru fereastra de mentenanta si pentru contextul
   preadus al Tier 2.

Gata cand: testul de intarziere trece; determinismul pe calea rapida ramane >= 98%.
Poarta: fast, dev, validare, injectie, suita. Oprire: orice verdict schimbat fata de referinta.

Stare 2026-11-23: cod si teste pe `faza-25-timpul-alertei` (inventar si decizii in
docs/faza-25-timpul-alertei.md). Testul de intarziere trece. Omul a cerut faza 25 inainte de
portile pe `faza-23-decizii` si `faza-24-structura-pachet`: portile si determinismul raman de rulat
(`TO_DATETIME(?)` verificat pe ES-ul real: 12 = 12).

## Faza 26 — contracte de mesaje si plicul de rezultat (`faza-26-contracte-unelte`)

Scop: forme fixe pentru ce va circula prin cozi si pentru ce intorc uneltele.

1. `contracts/messages.py`: mesajele `AlertaNormalizata`, `CazDeInvestigat`, `VerdictDeScris`,
   fiecare cu `schema_version`, `prompt_set`, `chain_id` si momentul alertei. `extra="forbid"`.
2. `contracts/errors.py`: codurile de eroare ale uneltelor, multime inchisa.
3. `contracts/tool_result.py`: plicul de rezultat cu `ok`, `coverage.status`
   (complete, partial, unknown, empty), `examined`, `limitations`, `provenance.untrusted_content`,
   `sha256` pe JSON canonic care include si argumentele apelului.
4. `tier2/tools.py`: catalogul inchis de unelte, despartit din `elastic_tools.py`, cu efecte
   declarate pe fiecare unealta. Test: nicio unealta din calea de verdict nu are alt efect
   decat citirea.
5. Uneltele intorc plicul. `result_has_rows` citeste din plic, cu ACELASI rezultat ca azi.
   Regula pentru benign fara dovezi NU se schimba in faza asta.
   (Nota faza 0: `result_has_rows` a plecat cu `cada43f`; pasul se reduce la a pastra ce citesc azi
   din rezultatul uneltelor `hunt_path` si `harness`.)
6. Amprenta catalogului de unelte intra in hash-ul setului de prompturi. Asta schimba
   `prompt_set`: se face doar cu aprobarea omului si se noteaza noul identificator.

Gata cand: teste pe plic (gol, partial, eroare, trunchiat) trec; verdictele pe porti sunt cele
de referinta. Poarta: dev, validare, injectie, suita. Oprire: un verdict Tier 2 schimbat.

## Faza 27 — adaptor de intrare si grupare (`faza-27-adaptor-grupare`)

Scop: citirea, normalizarea si gruparea stau intr-un singur loc, chemate inca din acelasi proces.

1. `intake/adapter.py`: cursorul si marja de indexare din `state.py`, citirea alertelor,
   normalizarea la `AlertaNormalizata`. Aduna aici `alert_facts`, `case_adapter.from_alert` si
   extractoarele din `sensor_rules.py`.
2. `intake/grouping.py`: `dedup_key_alert`, `group_alerts`, `BoundedSeen`, cu aceeasi cheie ca azi.
   Gruparea mai larga pe entitati vine separat, dupa refactorizare.
3. `intake/notify.py`: notificarea claselor critice, chemata din adaptor.
4. `orchestrator.py` cheama adaptorul si gruparea in loc de functiile proprii.
5. Contabilitate pe ciclu, scrisa in metrici: alerte citite = alerte normalizate + alerte grupate.

Gata cand: pe aceeasi fereastra de alerte, calea veche si cea noua produc aceleasi cazuri
(test de comparatie pe date inregistrate). Poarta: fast, dev. Oprire: diferenta la numarul de cazuri.

## Faza 28 — Scriitor si lant de audit (`faza-28-scriitor-audit`)

Scop: o singura bucata de cod scrie in indici, iar auditul devine verificabil.

1. `store/writer.py`: `_record`, `persist`, `_upsert_case` scoase din orchestrator. Fiecare verdict
   are identificator determinist din cheia de deduplicare, deci o a doua scriere il inlocuieste.
2. `store/audit_chain.py`: `seq`, `prev_hash`, `hash` pe fiecare inregistrare de audit; functie
   de verificare care intoarce prima inregistrare invalida si ultimul hash.
3. Ultimul hash al zilei se scrie si in `soc-metrics`.
4. Daca auditul nu se poate scrie, verdictul nu se considera livrat (eroare, nu avertisment).

Gata cand: test de modificare, stergere si reordonare pe lant; test de scriere dubla fara dubluri.
Poarta: fast, dev (se verifica doar ca scrierea nu s-a schimbat). Oprire: un verdict scris altfel.

## Faza 29 — cozi si workeri (`faza-29-cozi-workeri`)

Scop: bucla seriala devine patru procese legate prin RabbitMQ. Logica ramane cea importata.

1. Propune omului comenzile de instalare pentru RabbitMQ pe es-node-1 si asteapta aprobarea.
2. `bus/broker.py`: cozi durabile `alerte`, `cazuri`, `verdicte`, `esuate`; publicare cu
   confirmare; prioritati pentru honeytoken, detectie nativa si senzor.
3. `apps/adaptor.py`: publica, apoi muta cursorul. Niciodata invers.
4. `apps/worker_t1.py` si `apps/worker_t2.py`: valideaza mesajul la primire, cheama `fast_path`
   respectiv `hunt_path` si politica, publica verdictul, confirma mesajul abia dupa publicare.
5. `apps/scriitor.py`: consuma `verdicte` si scrie prin `store/writer.py`.
6. Reincercari: 3 pe loc, pana la 5 treceri prin coada secundara, apoi `esuate`. Din `esuate`
   iese verdict din cod: `undetermined` + `escalate_human`.
7. `core/degraded.py`: pragul fix de 20 devine lungimea cozii si varsta celui mai vechi mesaj;
   termen de varsta pe mesaj; intrerupator de circuit pe apelurile de model si de Elasticsearch.
8. Fiecare proces verifica la pornire setul de prompturi si modul shadow.
9. Unitati systemd noi, cate una pe proces, PROPUSE in `deploy/`; le instaleaza omul.
10. `SOC_PIPELINE=queue` porneste calea noua; `legacy` ramane implicit.

Gata cand:
- o rafala inregistrata trece fara pierderi (alerte citite = verdicte + cozi);
- un worker oprit la mijloc nu pierde cazul;
- un mesaj otravit ajunge in `esuate` si iese escaladat;
- portile dau referinta cu `SOC_PIPELINE=queue`.

Poarta: toate. Oprire: orice alerta pierduta sau verdict diferit.

## Faza 30 — Tier 2: stare pe pas si pachet de dovezi (`faza-30-tier2-stare-dovezi`)

Scop: investigatia se reia de la ultimul pas, iar uneltele citesc dintr-o felie fixa de loguri.

1. Propune instalarea Postgres pentru starea pe pas; asteapta aprobarea.
2. Adauga mecanismul de salvare din LangGraph in `hunt_path.py` (verifica intai pe versiunea
   instalata ca exista si cum se configureaza).
3. `tier2/evidence.py`: la inceputul cazului se trage o singura data felia de loguri
   (host, entitate, fereastra in jurul momentului alertei) si se salveaza cu hash.
4. Uneltele Tier 2 interogheaza pachetul. Daca o cautare iese din fereastra pachetului,
   rezultatul e `partial`, nu `empty`.
5. Masoara, pe scenariile portii, cate apeluri de unealta ar fi cerut date din afara pachetului.

Gata cand: un caz oprit la pasul N se reia de la pasul N; verdictele pe porti raman cele de
referinta. Poarta: dev, validare, injectie, suita, de 3 ori. Oprire: recall sub referinta sau
un atac retrogradat. Daca fereastra pachetului schimba verdicte, se raporteaza, nu se largeste
pe ghicite.

## Faza 31 — poarta de inferenta (`faza-31-poarta-inferenta`)

Scop: toate apelurile de model trec printr-un singur punct, cu limita de concurenta.

1. Propune instalarea portii de inferenta in fata serverului de modele; asteapta aprobarea.
2. `core/llm.py` devine clientul ei. Rolurile, samanta si temperatura raman cele de azi.
3. Workerii pot rula mai multe sarcini deodata, in limita data de poarta.
4. Masoara debitul: cazuri pe minut la 1, 2, 4 si 8 cereri simultane.

Gata cand: acelasi model, aceleasi verdicte; debit masurat. Poarta: fast, dev, determinism.
Oprire: determinismul scade sub 98%.

## Faza 32 — agregate pe entitate (`faza-32-agregate`)

Scop: sweep-urile nu mai interogheaza loguri brute pe 168 de ore.

1. `store/aggregates.py`: pe host, utilizator si pereche parinte-copil se tin prima aparitie,
   ultima aparitie si numarul de aparitii, actualizate incremental.
2. Sweep-urile citesc agregatele. Un finding iese cand apare o pereche noua.
3. Comparatie pe aceeasi fereastra de 7 zile: findings din sweep-ul vechi fata de cel nou.
   Diferentele se listeaza una cate una.

Gata cand: aceleasi findings pe fereastra de comparatie, sau diferente explicate si acceptate
de om. Poarta: dev, validare, scenariul 0-day. Oprire: un finding de atac disparut.

## Faza 33 — curatenie si inchidere (`faza-33-curatenie`)

1. `apps/doctor.py`: autoverificare la pornire (set de prompturi, shadow, acces la coada si
   la indici), folosita si ca verificare de sanatate.
2. Regula de importuri devine obligatorie; se repara incalcarile listate in faza 24.
3. Cu aprobarea omului: se scot fisierele subtiri de la vechile cai si calea `legacy`.
4. Se actualizeaza README, `docs/arhitectura.md`, `docs/faze.md` si CLAUDE.md.

Gata cand: toate portile trec pe structura finala, fara cai vechi.

---

## Ce NU e in acest plan (vine dupa, ca functii noi)

- gruparea mai larga pe entitati comune si scorul ieftin inaintea modelului;
- inchiderea fara model;
- folosirea starii de acoperire in regula pentru benign fara dovezi;
- legatura cu Arcanna si calibrarea pe datele firmei;
- data lake-ul.

Toate acestea schimba verdictul sau depind de firma. Se fac abia dupa ce structura e stabila.

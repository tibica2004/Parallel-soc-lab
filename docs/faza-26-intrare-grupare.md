# Faza 26 — intrare fara pierderi si grupare

Ramura `faza-26-intrare-grupare`, din `faza-25-timpul-alertei` (fef20dd). Corespunde fazei
"25 — intrare fara pierderi si grupare" din sarcina pentru firma (2026-11-24); numerotarea din
depozit merge mai departe de la faza 25 (timpul alertei), vezi docs/plan-refactorizare.md.

Scop: volumul se taie inaintea modelului (grupare + potop), nicio alerta citita nu se pierde
(contabilitate pe ciclu), clasele critice ajung la om la citire, nu dupa verdict.
Logica de verdict (fast_path, hunt_path, escalation, policy, podele) nu se atinge.

## Ce s-a schimbat

| Fisier | Ce | De ce |
|---|---|---|
| `elasticlab/contracts/messages.py` (nou) | `AlertaNormalizata` (extra="forbid", frozen, `schema_version`), `CriticalClass`, `Contabilitate` cu `ok()` | forma fixa pentru ce trece de la intrare la judecata; aceeasi forma va trece prin coada |
| `elasticlab/intake/grouping.py` (nou) | `dedup_key_alert`, `group_alerts`, `take_until_cap`, `case_extra`, `BoundedSeen` MUTATE din orchestrator, neschimbate; nou: `FloodTracker`, `plan_cycle`, `PlanCiclu` | un singur loc pentru grupare; plan pur, testabil fara ES |
| `elasticlab/intake/adapter.py` (nou) | `read_window` (search_after, pagini, plasa `INTAKE_MAX`), `normalize`, `critical_class`, `next_cursor` | citirea fara plafonul de 500 al caii vechi; cursorul nu sare niciodata peste ce nu s-a consumat |
| `elasticlab/intake/critical.py` (nou) | `notify_critical` (pointer, dedup 15 min, sumar peste 10 pe ciclu; trimiterea injectata) | notificarea claselor critice la intrare |
| `elasticlab/apps/orchestrator.py` | importa gruparea din intake (aceleasi nume); `SOC_PIPELINE`; `_run_legacy` (codul de azi, mutat intr-o functie) si `_run_intake`; `process_floods`; `persist` sare paginarea daca s-a notificat la intrare; `--intake-page`, `--intake-max`; metrici `pipeline`, `intake`, `flood_cases` | cablajul; calea veche ramane implicita si neschimbata |
| `elasticlab/contracts/schemas.py` | `EscalationReason.FLOOD = "flood"` | motivul incidentului de potop, in enumerarea inchisa |
| `elasticlab/eval/synthetic.py` (nou) | alerte sintetice (rafala, critice presarate), `FakeAlertsES` cu search_after | teste fara date din afara laboratorului; refolosit la replay |
| `elasticlab/eval/intake_compare.py` (nou) | simuleaza ciclurile pe ambele cai si compara cazurile; CLI doar-citire pe ES-ul laboratorului | criteriul "aceleasi cazuri" |
| `tests/test_intrare_grupare.py` (nou) | 121 de teste | |
| `.importlinter` | 3 contracte noi (intake, bus, calea de verdict nu importa intake) | monolitul modular, docs/arhitectura-monolit-modular.md |
| `deploy/es-node-1/faza26-setup.sh` (nou, PROPUS) | mapping pentru campurile noi din soc-metrics | il ruleaza omul, cu contul elastic |
| `soc.env.example` | `SOC_PIPELINE`, `FLOOD_THRESHOLD`, `FLOOD_WINDOW_MIN`, `INTAKE_PAGE`, `INTAKE_MAX` | |

`deploy/soc-orchestrator.service` (ExecStart) NU s-a schimbat. `SOC_PIPELINE` vine din mediu
(soc.env); fara el, serviciul ruleaza `legacy`, adica exact codul de azi.

## Contabilitatea (pe ciclu, in soc-metrics `intake.*`)

```
citite    = consumate + amanate
consumate = cazuri + grupate + in_potop
```

- `cazuri`: alerte care deschid un caz nou (judecat de Tier 1 sau escaladat din cod);
- `grupate`: alerte care intra intr-un caz deja deschis (in lot sau intr-un ciclu anterior);
- `in_potop`: alerte absorbite intr-un incident de potop;
- `amanate`: citite, dar lasate pentru ciclul urmator de plafonul `--limit`; cursorul ramane la
  ultima alerta consumata, deci se recitesc;
- `respinse`: plicul n-a putut fi validat; alerta merge totusi mai departe, cu cheia din documentul
  brut (numarata, nu pierduta); `critice`, `critice_notificate`, `pagini`, `trunchiat`.

Daca invariantul nu se inchide, ciclul scrie `[contabilitate] NEECHILIBRATA` in jurnal (testat pe
toate loturile din teste, inclusiv rafalele de 10.000).

## Potopul

- Cheia: (regula, sursa, fereastra). Sursa = `source.ip`, altfel `host.name`. Fereastra = intervale
  fixe de `FLOOD_WINDOW_MIN` (10) minute dupa MOMENTUL ALERTEI (faza 25), nu al prelucrarii.
- Primele `FLOOD_THRESHOLD` (20) cazuri noi din fereastra sunt cazuri obisnuite; restul se strang
  intr-un incident: UN verdict scris de cod (`undetermined` + `escalate_human`, motiv `flood`,
  `model_id=none`), cu `case_alert_count`, primul/ultimul moment si referinte la primele 50 de alerte.
- Incidentul e marcat vazut doar dupa scriere; un esec de scriere il reemite la ciclul urmator.
- Alertele potopului nu consuma plafonul de cazuri si nu sunt amanate.
- Clasele critice (honeytoken, detectie nativa, senzor) nu intra niciodata in potop (testat).

## Clasele critice la intrare

- Clasa se decide din cod, la normalizare: momeala (`honeytokens.escalation_reason` =
  `honeytoken`; cea atinsa de pe un IP propriu ramane la om fara paginare, ca azi), senzor
  (`sensor_rules.is_sensor_alert`), detectie nativa (`defend_native.is_native`).
- Se notifica din TOT lotul citit, inainte de plafon si de model: o alerta critica amanata la ciclul
  urmator e notificata acum. Mesajul e un pointer (clasa, regula, host, id-ul scurt al alertei).
- Dupa verdict, `persist` nu mai pagineaza cazurile notificate la intrare. Daca notificarea de la
  intrare a esuat (webhook nesetat sau cazut), paginarea de dupa verdict ramane plasa de siguranta.

## Rezultate

- pytest: **1539 verzi** (inainte: 1418; +121 noi). `prompts.py --check`: `prompt_set=23664c93b9cd; la zi`
  (neschimbat).
- import-linter: 5 contracte respectate, 1 incalcat (tier1 <-> tier2, cel vechi, listat in faza 24).
- Aceleasi cazuri, cale veche vs noua: identice pe 5 ferestre sintetice de 1500 de alerte (plafon 50,
  pagina veche 500, pagina noua 97) si pe 20 x 4 loturi (plafoane 0, 1, 5, 50) la nivel de ciclu:
  `plan_cycle` fara potop == `take_until_cap`.
- Rafala de 10.000 de alerte cu 90% duplicate (sintetica, `eval/synthetic.burst`), un ciclu, fara plafon:

| Rafala | Potop | Cazuri | Grupate | In potop | Incidente | Critice noi | Timp plan |
|---|---|---|---|---|---|---|---|
| 1000 cazuri distincte pe 50 de surse | nu | 1000 | 9000 | 0 | 0 | 0 | 253 ms |
| idem | da (20/10 min) | 1000 | 9000 | 0 | 0 | 0 | 156 ms |
| 1000 cazuri distincte de la 1 sursa | nu | 1000 | 9000 | 0 | 0 | 0 | 293 ms |
| idem | da (20/10 min) | 167 | 1454 | 8379 | 5 | 0 | 235 ms |
| 50 de surse + 20 de momeli | da | 1020 | 9000 | 0 | 0 | 20 | 149 ms |

  (masurat pe es-node-1, fara ES si fara model; citirea a 10.000 de alerte din ES-ul fals: 21 de pagini.)

## Ce ramane de verificat pe laborator (de omul care aproba)

1. Pe ES-ul real, doar citire (nu scrie nimic, nu porneste nimic):
   `source env.sh && python3 -m elasticlab.eval.intake_compare --hours 24 | tee results/faza26-intrare-$(date +%F-%H%M).json`
   Asteptat: `"identical": true`. Verifica si ca sortarea pe `kibana.alert.uuid` e acceptata de indicii
   de alerte (altfel interogarea da eroare si comanda se opreste, fara efect).
2. Portile fast si dev (cerute de sarcina). Faza nu atinge calea portilor (harness-ul cheama fast_path /
   hunt_path direct, nu gruparea orchestratorului), deci trebuie sa iasa exact referinta.
3. `deploy/es-node-1/faza26-setup.sh` (mapping soc-metrics), inainte de primul ciclu cu `SOC_PIPELINE=intake`.
4. O rulare scurta cu `SOC_PIPELINE=intake --once` intr-un worktree, nu in ~/lab, cand omul decide.

## Decizii si alternative respinse

1. **Gruparea mutata, nu rescrisa.** Functiile de azi sunt mutate in `intake/grouping.py` si importate
   in orchestrator sub aceleasi nume; testele vechi trec neatinse. Respins: o cheie noua de grupare
   (pe entitati comune) — schimba cazurile, deci verdictele; ramane pentru dupa refactorizare.
2. **Comutator cu trei valori** (`legacy|intake|queue`): sarcina cere `legacy|queue`, dar intre ele
   exista acum o cale intermediara, in acelasi proces. `queue` e rezervat si refuza pornirea.
   Respins: noua intrare direct sub `queue` (ar fi insemnat ca `queue` nu are cozi).
3. **Potopul doar peste prag, nu tot grupul.** Primele 20 de cazuri din fereastra se judeca normal
   (pot fi atacuri diferite), doar restul se strang. Respins: tot grupul in potop (ar ascunde de model
   primele cazuri ale unui atac care face zgomot).
4. **Ferestre fixe de potop, dupa momentul alertei.** Respins: fereastra glisanta pe timpul real
   (rezultat dependent de intarzierea prelucrarii, exact ce a scos faza 25).
5. **Paginare cu search_after pe (@timestamp, kibana.alert.uuid), fara PIT.** Fereastra are deja
   marja de indexare (LAG_SECONDS); PIT ar cere o cheie cu alt drept si un pas in plus. Respins si
   `from/size` (limitat la 10.000 si instabil la inserari).
6. **Notificarea critica inainte de plafon.** O alerta critica amanata e notificata in ciclul in care
   e citita; dedup 15 min pe cheie, plus sumar peste 10 pe ciclu. Respins: plafonul sa nu se aplice
   claselor critice (ar schimba ce cazuri se judeca intr-un ciclu fata de calea veche).
7. **Plicul nu respinge alerta.** Un plic invalid se numara (`respinse`), dar alerta merge pe calea
   de verdict cu documentul brut. Respins: aruncarea alertei (pierdere).

## Riscuri ramase

- **Pierderea la scriere ramane ca pe calea veche.** Daca auditul unei alerte nu se poate scrie
  (ES cazut la mijloc), cursorul trece mai departe (comportamentul de azi din `process_alerts`).
  Se rezolva in faza cozilor: mesajul se confirma abia dupa scriere.
- **Alertele potopului dupa emiterea incidentului** (cicluri urmatoare, aceeasi fereastra) se numara
  `in_potop`, dar contorul incidentului deja scris nu creste. Omul vede incidentul; contorul exact e in
  `soc-metrics`.
- **`FLOOD_THRESHOLD` = 20 si `FLOOD_WINDOW_MIN` = 10 sunt alese, nu stabilite cu firma.** Se
  dimensioneaza dupa rafala tinta (alerte pe minut la varf), cand firma o da.
- **`FloodTracker` e in memorie.** La repornire un potop reincepe cu pana la 20 de cazuri obisnuite:
  mai multa munca, nu alerte pierdute.
- **Sortarea pe `kibana.alert.uuid`** n-a fost verificata pe ES-ul real (pasul 1 de mai sus).
- **Dependenta intake -> tier1** (doua predicate pure), documentata in docs/arhitectura-monolit-modular.md.

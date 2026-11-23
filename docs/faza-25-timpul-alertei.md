# Faza 25 — timpul alertei: inventar si decizii

Ramura `faza-25-timpul-alertei`, din `faza-24-structura-pachet`. Plan: docs/plan-refactorizare.md.

Scop: logica de verdict isi socoteste ferestrele fata de momentul alertei, nu fata de momentul
prelucrarii, ca o alerta prelucrata cu intarziere (cozi, faza 29) sa primeasca acelasi verdict.

## Regula (elasticlab/core/eventtime.py)

- **Ancora** = momentul cazului:
  - alerta Tier 1: `kibana.alert.original_time`, altfel `@timestamp` (acelasi camp ca fereastra de
    mentenanta din calea rapida);
  - finding de sweep: momentul sweep-ului (`run_full_sweep`);
  - fara moment: `None`.
- **Fereastra** pentru un pas inapoi `b`: `[ancora - b, ancora + DUPA_EVENIMENT]`, cu `DUPA_EVENIMENT`
  = 10 minute. La prelucrare imediata limita de sus e in viitor, deci se vede tot ce exista, ca azi.
  La prelucrare intarziata nu mai intra ce s-a intamplat dupa.
- **Fara ancora** functiile intorc textul vechi, caracter cu caracter (`@timestamp >= NOW() - 15 minutes`,
  `{"gte": "now-15m"}`). Sweep-urile, Tier 3 si apelurile din afara unei investigatii raman neschimbate.
- **Timpii** merg ca parametri ES|QL (`TO_DATETIME(?)`), nu in textul interogarii. Formatul e
  `yyyy-MM-ddTHH:mm:ss.SSSZ`.
- **Uneltele Tier 2** le cheama modelul, cu argumentele lui. Ancora nu poate deveni argument fara sa
  schimbe schema uneltelor si setul de prompturi. De aceea `hunt_path` pune ancora intr-o variabila
  de context (`eventtime.anchored`) in jurul investigatorilor A si B. LangGraph o copiaza in firele
  in care ruleaza uneltele; testul cap la cap o verifica prin `ToolNode`-ul real.

## Inventar

| Loc | Ce calculeaza | Pe timpul alertei? | Ce s-a facut |
|---|---|---|---|
| `tier1/fast_path.py:284` `build_context` | fereastra de mentenanta | da | era deja la ora evenimentului (`event_time`) |
| `tier1/fast_path.py:193` `lookup_history` | ultimele 10 verdicte etichetate de om pe regula, fp_rate | da | doar verdictele scrise pana la momentul alertei (`eventtime.until`) |
| `tier1/fast_path.py:240` `in_maintenance_window(at=None)` | fereastra, implicit acum | nu se foloseste pe calea verdictului (doar un test) | neschimbat; de scos in faza 33 |
| `tier1/fast_path.py:133` `alert_facts` | parintele / sudo dupa entity_id exact | nu are fereastra | neschimbat |
| `tier1/fast_path.py:226` `pair_in_baseline` | perechea in baseline (transform) | baseline-ul nu are istoric | neschimbat; risc mai jos |
| `tier1/fast_path.py:488` `_ask` | durata apelului la model | timp real (masuratoare) | neschimbat |
| `tier1/enrich.py:61` (configuratiile A-D) | alerte corelate +-30 min | da | era deja fata de `@timestamp`-ul alertei |
| `tier1/l1_agent.py:134` (C, D) | ferestrele uneltelor L1 | da | era deja fata de momentul alertei |
| `tier2/hunt_path.py:203` `execution_facts` | procesul dupa entity_id, 168 h | da | ancorat |
| `tier2/hunt_path.py:224` `execution_facts` | perechea / copilul, 90 min | da | ancorat (finding-uri si cazuri fara entity_id) |
| `tier2/hunt_path.py:319` `recent_host_alerts` | alerte deschise pe host, 60 min | da | ancorat |
| `tier2/hunt_path.py:361` `prefetch_context` | ultimele 5 verdicte pe host | da | doar verdictele scrise pana la momentul cazului |
| `tier2/hunt_path.py:400` `prefetch_context` | fereastra de mentenanta | da | era deja la ora evenimentului (`maintenance.covers`) |
| `tier2/hunt_path.py:705, 733` investigatorii A si B | ancora uneltelor | da | `eventtime.anchored` |
| `tier2/elastic_tools.py:813-936` cele 6 unelte | `NOW() - N minutes` / `now-Nm` / 90 de zile | da | `eventtime.current()` |
| `tier2/elastic_tools.py:595` `pair_event_refs` | referintele perechii din sweep (doar in verdict, nu la model) | da | ancorat pe momentul finding-ului |
| `tier2/elastic_tools.py:792` `run_full_sweep` | momentul finding-urilor | e chiar ancora | pune `observed_at` = momentul sweep-ului |
| `tier2/elastic_tools.py:250-770` `sweep_*`, `_windows` | ce e nou in ultima ora fata de 30 de zile | nu: sweep-ul programat defineste finding-ul | neschimbat |
| `tier2/elastic_tools.py:202` `lookup_past_verdicts` | verdicte pe 30 de zile | nu se cheama (`build_context_pack` nu are apelanti) | neschimbat; cod mort pentru faza 33 |
| `core/maintenance.py:169, 180` | fereastra la un moment dat | functii pure, primesc momentul | neschimbat |
| `core/maintenance.py:128` `expired(now)` | raport de ferestre expirate | timp real (operare) | neschimbat |
| `core/degraded.py:35-36, 124` | timeout pe caz (90 s / 600 s) | timp real (plan, pasul 3) | neschimbat |
| `apps/orchestrator.py` | cursorul, ciclul, ceasul de garda, durata cazului | timp real (plan, pasul 3) | neschimbat |
| `tier3/incidents.py:217, 420` | gruparea alertelor in incidente | deja dupa timpii alertelor; intervalul `collect` il da apelantul | neschimbat |
| `tier3/rules.py:344, 452` | programul regulilor propuse (`now-6m`, e al Kibana), zgomotul la validare | nu e logica de verdict | neschimbat |
| `tier3/hunt.py:384`, `extras/exposure.py:226` | cazuri Tier 3 (`origin=tier3_hunt`) | vezi decizia 3 | `observed_at` ramane None, deci ferestrele vechi |

## Decizii si alternative respinse

1. **`DUPA_EVENIMENT` = 10 minute.**
   - Respins 0: taie conexiunea shell-ului invers si copilul procesului, care urmeaza imediat evenimentul.
   - Respins mai mult de 10: la prelucrarea intarziata ar intra activitate fara legatura (in harness,
     scenariile urmatoare).
   - 10 minute acopera intarzierea de azi: regulile ruleaza la 5 minute, orchestratorul la un ciclu dupa.
     Prelucrarea imediata vede deci acelasi lucru ca inainte.
2. **Ancora pentru alerte = ora evenimentului** (`original_time`), nu ora alertei (`@timestamp`).
   Asa e consecventa cu fereastra de mentenanta, care o folosea deja.
3. **Tier 3 ramane pe timpul real.** Vanatoarea isi investigheaza cazurile imediat, in acelasi proces.
   Daca ar fi ancorate la `last_seen`, uneltele s-ar uita ore in urma: verdictele s-ar schimba pe o
   cale pe care poarta nu o masoara. Se reia cand vanatoarea trece pe cozi.
4. **Finding-ul ia momentul sweep-ului** (sfarsitul ferestrei cercetate), nu al evenimentelor din el.
   La prelucrare imediata ferestrele raman deci cele vechi.
5. **Harness-ul pune momentul pe finding** (`run_hunt`, ca `run_full_sweep`). Altfel seturile dev,
   validare si injectie ar rula tot pe forma veche, iar poarta nu ar masura codul nou.
6. **Istoricul de verdicte merge pana la momentul cazului.** In productie, verdictul Tier 1 al
   aceluiasi caz e scris inainte de Tier 2 (`_record` inainte de `hunt.run`). Pana acum intra deci in
   `past_verdicts` ale Tier 2, ceea ce contrazice principiul 7. Cu ancora nu mai intra. Harness-ul nu
   scrie verdicte, asa ca poarta nu vede schimbarea.
7. **Variabila de context**, nu un argument nou al uneltelor. Argumentul ar fi schimbat schema
   uneltelor trimisa modelului, deci setul de prompturi.

## Teste

`tests/test_timpul_alertei.py` foloseste o lume falsa cu ceas: un Elasticsearch fals in care ce s-a
intamplat dupa ceas nu exista, iar `NOW()` e ceasul. Pe host activitatea continua dupa alerta: o alerta
la +20, un copil al procesului la +40, egress la +45, un verdict scris si etichetat la +15. Aceeasi
alerta e prelucrata la +5 si la +65 si da:

- acelasi context si acelasi verdict pe calea rapida (fereastra de mentenanta se termina la +30;
  istoricul vazut e cel de la momentul alertei);
- acelasi context preadus Tier 2;
- aceleasi rezultate pentru toate cele 6 unelte;
- acelasi verdict Tier 2 cap la cap. Graful e cel real (`ToolNode`), cu un model fals al carui verdict
  depinde de amprenta tuturor mesajelor.

Fiecare test are un control: fara ancora, aceeasi lume da alt context si alte rezultate. Asta arata ca
testul chiar pune ancora la incercare.

## Riscuri ramase

- **`TO_DATETIME(?)` cu parametru** nu a rulat pe Elasticsearch-ul real; testele sunt fara ES.
  `l1_agent` foloseste aceeasi forma. Verificarea (doar citire) e in raport.
- **Starea care nu are timp:**
  - `workflow_status != closed` la alertele recente: omul inchide alerte intre timp;
  - baseline-ul perechilor (transform);
  - inventarul de active.

  O prelucrare intarziata le vede asa cum sunt la prelucrare.
- **Etichetarea:** un verdict scris inainte de alerta, dar etichetat de om dupa, intra in istoric.
  Eticheta nu are timp propriu.

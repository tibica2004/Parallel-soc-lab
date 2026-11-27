# Pasul 24 — decizia invatata din etichete, in stil Arcanna

Ramura `faza-24-decizie-invatata`, pornita din `faza-26-intrare-grupare` (2026-11-27). Lucrata cap-coada
dupa exceptiile E1-E5 din sarcina: alegerile de proiectare de mai jos sunt ale agentului, cu
alternativa respinsa langa fiecare. Nimic nu a rulat pe hosturi; tot ce cere drepturi e in
`deploy/faza-24-apply.sh` (revenire: `deploy/faza-24-rollback.sh`).

## Pe scurt

```
alerta -> pasul 0: faptele (build_context, o singura data)
       -> pasul 1: clasa critica sau podea? -> pasul 4                          (L4)
       -> pasul 2: grupul (punctele de decizie) are consens uman?
                   benign -> inchidere | attack -> motiv + pasul 4
       -> pasul 3: modelul pipeline-ului (sau campul extern) e activ si sigur?
                   benign >= prag, nu outlier -> inchidere | atac probabil -> motiv + pasul 4
                   | nesigur / outlier -> pasul 4
       -> pasul 4: fast_path + should_escalate, ca azi -> Tier 2 (cu bucket_id) -> om
omul   -> eticheteaza GRUPURI in label_ui (coada ordonata de cod), vot majoritar
Tier 3 -> orar: candidat pe etichete umane -> controlorul: candidat -> umbra -> activ -> umbra
```

Comutatorul: `T1_CASCADE=off|shadow|on` (implicit **off** in cod; scriptul de aplicare pune **shadow**).
Inchiderile au efect DOAR cu `on` si doar pe pipeline-urile pe care controlorul le-a activat.

## Numerotarea

Sarcina se numeste "faza 24". In depozit, numarul 24 era deja folosit (`faza-24-structura-pachet`),
iar ramurile 25 si 26 exista. Decizie: pastrez numele cerute de sarcina pentru livrabile
(`docs/pasi/pas-24.md`, `deploy/faza-24-apply.sh`, `deploy/faza-24-rollback.sh`) si numesc ramura
`faza-24-decizie-invatata`, pornita din 26 (are deja pachetul, contractele, intrarea). In
docs/faze.md apare ca "Faza 24 (sarcina Arcanna)". Respins: renumerotarea ca faza 27 (omul cauta
fisierele dupa numele din sarcina) si pornirea din `main` (ar fi refacut fazele 24-26).

## Unde e fiecare punct din sarcina

| Punct | Cod | Teste |
|---|---|---|
| 1 pipeline-uri | `config/pipelines.yml`, `core/pipelines.py` | `test_invatare_nucleu.py` |
| 2 puncte de decizie | `core/decision_points.py` (catalog de categorii inchise) | idem |
| 3 grupuri | `core/buckets.py` (cheia), `store/writer.py` (`observe_bucket`), `store/buckets.py`, index `soc-buckets` | `test_scriitor.py` |
| 4 feedback | `apps/label_ui.py` (`/buckets`, `/b/{id}`, `/api/*`), `eval/labeling.py` (`build_bucket_vote`) | `test_label_ui_grupuri.py` |
| 5 model | `core/classifier.py`, `store/models.py` (manifest cu hash) | `test_invatare_nucleu.py`, `test_controlor.py` |
| 6 cascada | `core/cascade.py` (pura), `tier1/cascade.py`, `apps/orchestrator.py` (`process_alerts`) | `test_cascada.py`, `test_cascada_orchestrator.py` |
| 7 antrenare si activare | `tier3/learning.py`, `core/controller.py`, `tier3.py --invatare*`, unitatile `soc-learn*` | `test_controlor.py` |
| 8 post-decizie | `ops/kibana_tags.py` (API Kibana, doar etichete) | `test_post_decizie.py` |
| 9 Tier 2 | `CazDeInvestigat` pe magistrala, `Case.bucket_id`, `RezumatTier2` -> `tier2_summary` | `test_cascada_orchestrator.py` |
| 10 Tier 3 | `tier3/learning.py`: metrici per pipeline/clasa, pasii cascadei, drift | `test_controlor.py` |
| 11 sursa externa | `tier1/decision_source.py` (`ExternalFieldSource`) | `test_cascada.py` |
| forma codului | `bus/` (in proces + RabbitMQ optional), `store/writer.py` (scriitorul unic), regula de importuri | `test_magistrala.py`, `test_importuri_faza24.py` |

## Liniile rosii, in cod

| | Cum e tinuta | Test |
|---|---|---|
| L1 | nicio actiune noua pe hosturi; ExecStart neatins (scriptul verifica inainte si dupa); setarile noi in soc.env; unitatile noi sunt fisiere noi | `test_shadow_mode.py` (vechi), scriptul |
| L2 | votul pe grup il construieste doar `labeling.build_bucket_vote`, chemat doar din label_ui cu utilizatorul din sesiune/token; verdictul inchis de cascada are `ground_truth=None`; `observe_bucket` nu atinge voturile | `test_scriitor.py`, `test_cascada_orchestrator.py::test_L2_*`, `test_labeling.py` (garda veche) |
| L3 | `store/buckets.labeled` intoarce doar consens attack/benign; antrenarea nu citeste verdicte | `test_controlor.py::test_L3_*` |
| L4 | `tier1/cascade.critical_classes` + `core/cascade.floor_would_apply` -> pasul 4 inainte de grup si model | `test_cascada.py::test_L4_*`, `test_cascada_orchestrator.py::test_on_clasa_critica_*` |
| L5 | cu off, `_cascade_runtime()` intoarce None si nimic nou nu ruleaza (graful, intrarea, apelurile Tier 2 identice) | `test_cascada_orchestrator.py::test_L5_*` |
| L6 | `tier1/cascade.evaluate` prinde orice exceptie -> pasul ERROR = pasul 4 | `test_cascada.py::test_L6_*`, `test_cascada_orchestrator.py::test_L6_*` |
| L7 | cheile noi se scriu direct in soc.env de script (variabila nu se afiseaza); codul nu foloseste contul elastic | — |
| L8 | interogari term/terms; punctele de decizie doar cauta telemetria in multimi fixe; campul extern doar intr-un dictionar fix | `test_invatare_nucleu.py` |
| L9 | promptul nu s-a schimbat: `prompt_set=23664c93b9cd` inainte si dupa | `test_prompts_manifest.py`, `prompts.py --check` |

## Decizii (si alternativa respinsa)

1. **Algoritmul: Bayes naiv categorial + vecini (Hamming).** Determinist (numaratori intregi),
   explicabil exact pe punct de decizie (log-raport aditiv), salvat ca JSON, fara dependente noi.
   Respins: arbore/regresie logistica din scikit-learn (dependenta mare in venv-ul de productie,
   artefact pickle = cod executabil), kNN pur (fara contributii pe punct).
2. **Un exemplu de antrenare = un grup**, nu o alerta. Volumul nu cumpara greutate; zgomotul
   frecvent nu ingroapa clasa rara. Respins: ponderarea cu numarul de alerte.
3. **Outlier** = cel mai apropiat grup etichetat la distanta > `outlier_distance` (implicit 2) sau
   >= 2 valori nevazute la antrenare. Un outlier nu se inchide niciodata. Respins: prag pe
   probabilitate (Bayes naiv e increzator si pe ce n-a vazut).
4. **Pasii 2 si 3 au efect doar pe pipeline activ** (si mod on). Pasul 2 (consens uman benign) e
   cel mai puternic: un singur vot ar inchide tot grupul. L-am legat tot de controlor (50+50 de
   etichete, 7 zile de umbra, regresie) ca sa nu existe o cale de inchidere fara masuratoare.
   Respins: pasul 2 activ imediat ce exista o eticheta.
5. **"Inchidere contrazisa" in umbra** = cascada ar fi inchis, iar calea completa (pasul 4) a scris
   suspicious/malicious. Separat se numara inchiderile pe grupuri cu consens attack (trebuie 0).
   Respins: doar eticheta umana (rara in 7 zile, n-ar fi masurat nimic).
6. **Candidat -> umbra cere >= 5 etichete schimbate** fata de modelul din umbra (pe langa "nu scad
   metricile", masurate pe ACEEASI validare). Altfel reantrenarea orara ar reporni la fiecare ora
   ceasul de 7 zile si nimic nu s-ar activa. Respins: inlocuire la orice hash nou.
7. **Retrogradarea imediata**: la vot (label_ui cheama `learning.on_human_label`), plus garda la 5
   minute (`soc-learn-guard`) pentru control, drift si hash; orchestratorul refuza oricum un artefact
   cu hash nepotrivit la incarcare. Respins: doar controlorul orar.
8. **Esantionul de control**: `sha256(cheia cazului) % 100 < 10`, determinist; cazul merge prin
   pasul 4 si primeste motivul `control_sample` (forteaza escaladarea). Dezacordul = etichete
   umane attack (ground_truth pe caz sau consensul grupului) / cazuri de control etichetate.
9. **Regresia pe setul de aur** = Tier 1 (setul de prompturi curent) pe `data/golden` fara niciun
   atac ratat + modelul nu inchide niciun atac din set; inregistrata pe (model, prompt_set); ruleaza
   zilnic doar cu sonda LLM sanatoasa. Respins: refolosirea `regression.py run` (compara cu baseline,
   nu raspunde "trecut/picat").
10. **Registrul modelelor pe disc** (`data/models`, JSON + MANIFEST cu hash), nu in Elasticsearch:
    orchestratorul are deja `data/` ca singur loc scriibil; modelele sunt reproductibile din etichete.
    Tranzitiile merg si in `soc-metrics` (type=cascade_transition) si `soc-learning-audit`.
    Respins: `soc-audit` (forma lui e AuditRecord per verdict; metrics.py numara escaladarile din el).
11. **Magistrala**: interfata `Bus`, `InProcessBus` sincrona (aceeasi ordine ca apelurile directe),
    `RabbitBus` optional (pika importat lenes, NU in requirements; `SOC_BUS=rabbitmq` = livrare locala +
    copie in RabbitMQ). Tier 1 -> Tier 2 trece acum prin `tier2.caz` (si pe off; verdicte identice,
    test). Respins: RabbitMQ ca transport principal (cere instalare si schimba semantica la erori).
12. **Scriitorul unic**: `store/writer.py` scrie verdicte, audit, urme, cazuri, grupuri; orchestratorul,
    `cases.save` si label_ui trec prin el. Testul `test_un_singur_modul_scrie_*` cauta scrieri directe.
13. **Regula de importuri**: am reparat cele 3 incalcari tier1<->tier2 listate in faza 24 (constante ->
    `core/facts.py`, delimitarea telemetriei -> `core/untrusted.py`, clientul ES de citire ->
    `store/esread.py`), fara schimbare de logica (prompt_set identic, 1538 teste vechi trec).
    Ramane LISTATA o singura exceptie: `tier3.tier3 -> apps.orchestrator` (HuntRunner/WRITER), cu
    test care interzice orice exceptie noua. Respins: mutarea caii de inregistrare a verdictului in
    faza asta (atinge persist/policy/notify; e treaba workerilor).
14. **Mai multi oameni**: `LABEL_UI_USERS` (pbkdf2-sha256), numele din sesiune intra in vot; fara
    variabila ramane parola unica (utilizator "operator"), deci testele si folosirea de azi raman.
    API-ul cere token (`LABEL_UI_API_TOKENS`, doar hash-ul in soc.env), fara cookie (deci fara CSRF).
15. **Post-decizia**: `POST /api/detection_engine/signals/tags` (Kibana 9.5), etichete dintr-o multime
    inchisa `soc-decizie:*`; starea alertei nu se atinge. Cheia proprie are write pe indexul de
    alerte (Kibana actualizeaza cu drepturile apelantului) — vezi riscuri.
16. **Faptele o singura data**: `tier1/cascade.build_prefetched` construieste graful caii rapide din
    ACELEASI noduri (`fast_path.make_pattern`, `make_verdict`, `node_finalize`...), doar prefetch-ul
    foloseste contextul deja calculat. `fast_path.py`, `hunt_path.py`, `policy.py`: logica neatinsa.
17. **Dependente noi: niciuna** in requirements.txt (E4 nefolosit). pika e optional, documentat.

## Teste

- inainte (ramura de baza, local, Python 3.13): **1538 trec, 1 sarit**;
- dupa: **1689 trec, 1 sarit** (151 noi), cele vechi nemodificate;
- import-linter: 8/8 contracte (6 vechi + 2 noi); `prompts.py --check`: la zi, `23664c93b9cd`.

## Porti (harness dev / validation / fast / injection; regresie; determinism)

**In asteptare** (E5): web-prod (192.168.10.138), benign-gen si lab-sink nu raspund de pe es-node-1
la 2026-11-27 (stersi de om pe 2026-11-26), iar harness-ul genereaza atacurile pe web-prod. Tunelul
LLM raspunde (Ollama 200), dar regresia cere setul de aur `data/golden` (inca neexportat: `python
regression.py export` cu >= 50 attack / 50 benign etichetate). Cifrele de referinta raman cele din
CLAUDE.md; cu T1_CASCADE=off verdictele sunt identice prin constructie si prin testul L5. Consecinta:
controlorul nu poate activa nimic (nicio regresie trecuta) — comportament intentionat.

## Riscuri

- **Mapping-urile ES.** verdicts-history si soc-metrics primesc campuri noi prin PUT _mapping. Daca
  un camp `cascade.*` a fost deja mapat dinamic altfel (nu ar trebui: nu s-a scris inca), scriptul
  se opreste la acel pas.
- **Cheia de etichete Kibana**: are write pe `.alerts-security.alerts-default` (cerut de API-ul
  Kibana). Codul o foloseste doar prin `ops/kibana_tags.py`; privilegiul de functie se ia din
  `/api/features` (id-ul exact al versiunii 9.5 nu l-am putut verifica fara Kibana).
- **Pasul 2 cu etichete gresite**: un grup etichetat benign gresit ar inchide cazuri similare dupa
  activare. Plase: L4, esantionul de control, retrogradarea la primul attack pe un grup inchis.
- **Puncte de decizie prea grosiere/fine**: grupuri prea mari amesteca atacuri cu benigne (contrazise
  in umbra -> nu se activeaza); prea fine -> drift mare -> retrogradare. Se ajusteaza in
  config/pipelines.yml cu `decision_points_version` marit (etichetele vechi nu se transfera).
- **Productia de azi**: la verificarea din 2026-11-27, `soc-orchestrator` din ~/lab cadea in bucla cu
  `TabError` (orchestrator.py:801, modificari locale necomise). Nu e cauzat de faza; scriptul cere
  `git stash` inainte de checkout.

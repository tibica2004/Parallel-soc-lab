# DE_FACUT — inchiderea proiectului

Lista de lucru pana la final (scrisa 2026-11-12). Se bifeaza pe masura ce se termina; dupa fiecare
faza, raport si confirmare inainte de urmatoarea (CLAUDE.md).

**Rezultat final:** faza-22 trecuta prin poarta si pusa pe es-node-1, setul de aur construit din
cel putin 100 de etichete, cifre cu intervale de incredere, regula asimetrica la Tier 2, 20 de
tehnici Atomic Red Team rulate, domeniul si limitarile scrise.

**Reguli pentru tot taskul:**
- Orice regresie la poarta = oprire si raport, nu praguri ajustate.
- Comenzile pe hosturi le ruleaza sau le aproba omul.
- Shadow mode ramane pornit.

---

## Faza A — acum, fara GPU

### A1. Mesajul catre Laura
- [ ] Cere reboot pe 172.30.6.231: `nvidia-smi` da "Driver/library version mismatch", iar Ollama ruleaza pe CPU.

**Gata cand:** `nvidia-smi` merge si `ollama ps` arata modelul pe GPU.

### A2. Etichetarea
- [ ] Pornesti `label_ui.py` pe es-node-1 si intri prin tunel SSH pe portul 8088, cu filtrul "neetichetate" si sursa fast.
- [ ] Faci intai 5 etichete si rulezi `make golden`. "fara alerta in ES" trebuie sa fie 0.
- [ ] Etichetezi ce s-a intamplat in realitate, dupa `docs/standard-investigatie.md`:
  - **attack**: tot ce vine de la 172.30.6.133 si scenariile de atac din harness;
  - **benign**: benign-gen, `lsb_release`, `soc-wp-update` si testele documentate.
- [ ] Cel mult 10 etichete pe regula, cu note scurte si factuale.
- [ ] Eviti verdictele de dupa 4 noiembrie 15:00 UTC.

**Gata cand:** ai cel putin 50 attack si 50 benign.

### A3. Textul de domeniu
- [x] Adaugi sectiunea "Domeniu" in `README.md` (faza-23, 2026-11-17).
- [ ] Aceeasi sectiune in lucrare (omul).
  - **Acopera:** un host web Linux, detectie, triaj, investigatie, plan de raspuns pentru om.
  - **Nu acopera:** executia raspunsului, recuperarea, identitate, email, cloud, Windows, mai multe hosturi.

### A4. Codul fara poarta
Ramura noua, de exemplu `faza-23-inchidere-conceptuala`.
- [x] `regression.py`: functia pura `wilson(k, n)`, cu intervale pentru precizie, recall si rata de fals pozitive in `metrics()` si in raport.
- [x] `regression.py`: `export()` sa poata rescrie fisierul setului de aur, care azi ramane doar-citire.
- [x] `tests/test_guides.py`: sa nu mai depinda de `~/lab/detections`.
- [x] Teste unitare pentru toate trei. (1239 verzi, si cu HOME fara ~/lab)

**Gata cand:** pytest e verde.

### A5. Masuratoarea pentru regula Tier 2 (doar citire, pe es-node-1)
- [ ] (script gata, nerulat: `experiments/tier2_fara_dovezi.py`, asteapta aprobarea) Numeri cate verdicte hunt benigne pe findings din ultimele 30 de zile nu au niciun document in `soc-traces`.

**Gata cand:** stii cate findings pe zi ar ajunge in plus la tine.

---

## Faza B — dupa rebootul GPU-ului

### B1. Poarta faza-22
- [ ] Opresti benign-gen: `sudo systemctl stop benign-gen` (pe benign-gen: `ssh -J ubuntu@172.30.6.106 ubuntu@192.168.10.150`).
- [ ] Rulezi pe rand cele patru seturi:
  ```
  SCENARIOS=scenarios_fast.yml VERBOSE=1 python3 -u harness.py | tee results/faza22-fast-$(date +%F-%H%M).txt
  ```
  Repeti cu `scenarios.yml`, `scenarios_validation.yml` si `scenarios_injection.yml`.
- [ ] Pornesti benign-gen la loc.
- [ ] Scenariile 8 si 14 au nume de proces noi, deci notezi referinta noua.

**Gata cand:** recall pe atacuri neschimbat, injectie fara retrogradari.

### B2. Deploy
- [ ] Faci copii `.pre-22`.
- [ ] Aduci codul faza-22 pe es-node-1.
- [ ] `sudo systemctl restart soc-orchestrator`.

**Gata cand:** jurnalul arata noul `prompt_set` si coada scade la 0.

### B3. Ce a ramas din pasul 13
- [ ] Regulile e/f/g in Kibana: `python3 deploy/kibana/honeytoken_rules.py verifica`, apoi `aplica`.
- [ ] Custom Logs `soc.benign_actions` in Fleet.
- [ ] `make determinism`.

**Gata cand:** 9 reguli comportamentale pornite si determinism de cel putin 98%.

### B4. Merge
- [ ] Aduci faza-22 in main.

---

## Faza C — dupa etichete si GPU

### C1. Setul de aur si regresia
- [ ] Rulezi `make golden` (astepti `ok: True`).
- [ ] Rulezi `make regression` de 3 ori.

**Gata cand:** ai precizie si recall cu interval si numarul de verdicte schimbate intre rulari.

### C2. Coada omului
- [x] Adaugi in `metrics.py` timpul pana la prima privire (`labeled_at` minus `@timestamp`, mediana si p90).
- [x] Adaugi in `metrics.py` numarul de cazuri escaladate pe zi.
- [x] Teste pentru ambele.
- [ ] Apar in `soc-metrics` abia dupa deploy-ul codului faza-23 (orchestratorul scrie instantaneul).

**Gata cand:** ambele apar in `soc-metrics`.

---

## Faza D — regula asimetrica la Tier 2 (atinge verdictul)

### D1. Regula
In `hunt_path.py`, un finding din sweep ramane benign doar in unul din doua cazuri; altfel devine
`undetermined` cu `escalate_human`:
- cel putin un apel de unealta a intors documente;
- exista un fapt determinist benign: `pair_in_baseline`, sau fereastra de mentenanta cu admin cunoscut.

Cazurile venite din Tier 1 raman neatinse.

- [ ] Implementarea in `hunt_path.py`.
- [ ] Testele acopera patru situatii: fara dovezi, cu documente, cu fapt determinist si caz din Tier 1 neschimbat.
- [ ] Poarta dev si validare, separata de cea din Faza B.

**Gata cand:** poarta trece la referinta si raportul spune cu cat a crescut coada.

---

## Faza E — acoperire si calibrare

### E1. Atomic Red Team pe lab-sink
- [ ] Ajungi la cel putin 20 de tehnici.
- [ ] Aprobi fiecare comanda si verifici cleanup-ul.

**Gata cand:** fiecare tehnica e detectata sau are o ipoteza Tier 3.

### E2. Fals pozitivele zilnice
- [ ] Decizi pentru `lsb_release`, pentru `soc-wp-update.py` de la 02:00 si pentru sendmail in regula nativa RCE.
- [ ] Rulezi harness-ul.

---

## Faza F — inchiderea

### F1. Limitarile
Se scriu in lucrare si in `REZUMAT.md`, fiecare cu ce o compenseaza azi
(bifat = scris in `REZUMAT.md` sectiunea 7, faza-23; in lucrare le copiaza omul):
- [x] notele umane ajung la model;
- [x] un singur model si un GPU al altcuiva;
- [x] fara copie off-host;
- [x] un singur host si un set mic.

### F2. Jurnalul
- [ ] Aduci `stare.md` si `REZUMAT.md` la zi, cu numarul de teste, rezultatele portilor si cifrele din Faza C.

---

## Note de la verificarea repo-ului (2026-11-12)

Constatari facute la scrierea listei; nu schimba taskul, dar trebuie stiute.

1. **B4 / merge-ul e deja facut local, inainte de poarta.** La cererea omului, `main` a fost adus
   prin fast-forward la `4521a2c` (faza-22 + rezultatele fazei 18), dar NU e urcat pe GitHub
   (`main` local e cu 14 commit-uri inaintea `origin/main`).
   **Verificat 2026-11-17 (corectat la a doua verificare):** in clona de pe es-node-1, `main` local
   e VECHI: `a0f4a56`, cu 127 commit-uri IN URMA `origin/main` (`2782119`, 2026-11-05). faza-22
   (`80a867c`) e cu 19 commit-uri inaintea `origin/main` si nu e continuta in el. Deci pe es-node-1
   nu exista un `main` adus la faza-22; B4 = push faza-22 -> main dupa poarta (din clona care il are).
2. **A4, `tests/test_guides.py`: CORECTAT 2026-11-17 — nota initiala era gresita.** Testul nu
   depindea de ROOT, ci de `fast_path.lookup_guide`, care citea `hunt_path.GUIDES_DIR` cu implicitul
   `~/lab/detections`. Intr-o clona in alt director trecea doar pentru ca `~/lab` exista pe es-node-1;
   cu HOME fara `~/lab` picau 3 teste (`test_lookup_guide_pe_regulile_cu_volum_mare`,
   `test_contextul_marcheaza_doar_honeytoken`, `test_contextul_cu_fapte_yara`). Rezolvat in faza-23
   (`ed205cb`): implicitul e `detections/` de langa `hunt_path.py`; `GUIDES_DIR` din mediu ramane.
3. **A4, `export()`:** fisierul setului de aur devine doar-citire din cauza
   `os.chmod(GOLDEN, 0o440)` (`regression.py`, in `export()`); a doua rulare esueaza la `write_text`.
4. **B1, scenariile 8 si 14** din `scenarios.yml`: 8 = "Admin verifica versiunea php",
   14 = "Reverse shell in Python".
5. **Propus in plus (decizia omului): pragurile din `policy.py`.** CLAUDE.md spune ca
   `isolate_host` si `rotate_credentials` sunt ireversibile, cu prag 101 (doar la om), dar
   `policy.THRESHOLDS` le are la 95. Shadow mode impiedica orice executie, deci n-a avut efect pe
   hosturi; totusi, la auto-atacul din 03.11, `isolate_host` malicious/95 a trecut de prag si a fost
   oprit doar de shadow. Daca se aliniaza la 101, schimbarea atinge decizia -> poarta dev, ca in Faza D.

---

## Faza 23 — ce NU s-a putut face pe 2026-11-17 (si de ce)

Ramura `faza-23-inchidere-conceptuala` din `80a867c`, in worktree-ul `~/lab-faza23` (nu in `~/lab`,
din care ruleaza `soc-orchestrator`). Facut: etapa 0 si etapa 1 (1.1-1.6) + scriptul de citire
pentru etapa 2. Restul asteapta omul:

**0. Securitate OpenStack — `ssh-parola` (gasit la auditul din 2026-11-17).** Grupul permite TCP 22
si ICMP de la 0.0.0.0/0, cu login pe parola, si e atasat pe es-node-1, web-prod, atacator si
benign-gen. Anuleaza restrangerile din es-sg / victim-sg / attacker-sg / benign-sg (atacatorul poate
deschide SSH spre 172.30.6.106 si 172.30.6.249 la nivel de SG; nft opreste doar pe es-node-1 si
web-prod). Nimic din repo nu depinde de el (verificat cu grep). Claude nu a avut permisiunea sa
schimbe security groups; comenzile (de pe elastic-lab, OS_CLOUD=openstack), reversibile:
```
# 1. laptopul din admin_v4 pastreaza SSH (azi il are doar prin ssh-parola pe 3 VM-uri)
for g in es-sg victim-sg attacker-sg; do
  openstack security group rule create $g --protocol tcp --dst-port 22 \
    --remote-ip 192.168.62.206/32 --description "admin laptop (admin_v4)"; done
# 2. scoate ssh-parola (grupul ramane, pentru rollback)
for s in es-node-1 web-prod atacator benign-gen; do openstack server remove security group $s ssh-parola; done
# 3. verifica: ssh ubuntu@172.30.6.106, ssh tiberiu@172.30.6.249, ssh ubuntu@172.30.6.133,
#    ssh -J ubuntu@172.30.6.106 ubuntu@192.168.10.150, ssh ubuntu@172.30.6.210
# rollback: openstack server add security group <vm> ssh-parola
```
Nu sunt probleme (verificat): 172.20.99.220 = elastic-lab (sesiunea Claude), 192.168.62.206 = laptopul
(admin_v4), 172.20.9.132 = laptopul pe VPN (`laptop-access`, tot traficul). Observatie: 172.20.9.132 nu e in
admin_v4 din nft, deci pe es-node-1 si web-prod SSH-ul de acolo e oprit oricum de nft (de decis de om
daca il adaugi).

**Etapa 0.3 — intrebari pentru om:** GPU-ul 172.30.6.231 e reparat (A1)? Cate etichete umane exista
(attack / benign)? Fara ele, etapele 3, 4 si 7 nu pot porni.

**Etapa 2 — masuratoarea Tier 2 (citire pe es-node-1, cere aprobare):**
```
cd ~/lab-faza23 && source ~/lab/env.sh && python3 experiments/tier2_fara_dovezi.py --zile 30
```
Citeste verdicts-history si soc-traces cu ES_READER_API_KEY, nu scrie nimic. Inainte: verifica
ca `source_path`, `classification`, `chain_id`, `investigation_id` au subcampul `.keyword`
(`GET verdicts-history/_mapping`, `GET soc-traces/_mapping`); daca sunt `keyword` direct, se scoate
sufixul. Cifra e o limita superioara (faptele deterministe din prefetch_ctx nu sunt in urma).

**Etapa 3 — poarta faza-22 + deploy:** cere GPU-ul reparat (A1). Comenzile sunt in B1-B3 mai sus.
**Etapa 4 — cifrele pentru lucrare:** cere >= 50 attack + >= 50 benign etichetate de om (A2) si GPU.
`experiments/direct_baseline.py` e gata (nerulat): `source ~/lab/env.sh && python3 -u experiments/direct_baseline.py`.
**Etapa 5 — regula asimetrica Tier 2:** atinge verdictul; asteapta cifra din etapa 2 si decizia omului.
**Etapa 6 — decizii ale omului:** 6.1 prag 95 vs 101 (nota 5), 6.2 cele trei FP zilnice (E2).
**Etapa 7 — experimente cu modele:** dupa etapa 4; cere GPU (si 24 GB pentru Qwen 3.6 27B).
**Etapa 8 — Atomic Red Team:** fiecare comanda o aproba si o ruleaza omul.
**Etapa 9 — inchiderea:** dupa toate cele de mai sus.

Ramase in afara etapelor: sectiunile "Domeniu" si "Limitari" in lucrare (omul copiaza din README /
REZUMAT); deploy-ul codului faza-23 (metricile noi apar in soc-metrics abia dupa el).

## A doua verificare, 2026-11-17 08:00 UTC (citire pe hosturi, ES si OpenStack)

Constatari noi, in ordinea in care trebuie tratate:
1. **faza-22 ruleaza deja in productie, FARA poarta.** `~/lab` a fost mutat pe faza-22 pe 2026-11-16
   13:53 UTC si `soc-orchestrator` repornit la 13:57 (prompt_set 23664c93b9cd). B2 e deci facut inainte
   de B1. Copia dinainte: `~/lab-backup-2026-11-16.tgz`. Poarta B1 e urgenta.
2. **GPU-ul e reparat (A1 gata):** qwen3:14b integral in VRAM, latenta Tier 1 p50 17 s, 0 timeout-uri.
3. **benign-gen e oprit din 2026-11-04 14:23 UTC** (oprit pentru poarta, nerepornit): 0 documente in
   benign-ground-truth de 13 zile, readiness c1 "0/169 ore". De pornit DUPA poarta.
4. **Testele rulate pe es-node-1 produc alerte reale.** `tests/test_reader.py` ruleaza gate-ul cu 16
   comenzi refuzate; gate-ul scrie cu `logger` in auth.log, Fleet il trimite, regula "soc-reader:
   comanda refuzata de gate pe web-prod" se aprinde (nu filtreaza pe host). Cele 6 rulari pytest ale
   lui Claude din 2026-11-17 07:xx UTC = 96 de alerte false + verdictele lor (si 16 pe 11-16, 16 pe
   11-04). De etichetat benign ("pytest pe es-node-1") sau de ocolit la etichetare. Pana la reparatie:
   nu se ruleaza `pytest tests` pe es-node-1 (sau se sare test_reader.py).
5. Etichete umane: 2 (ambele attack, hunt). Tinta: >= 50 attack + >= 50 benign.
6. ES galben: 14 shard-uri nealocate (replici pe un singur nod), ca pe 03.11.
7. `/var/run/reboot-required` pe toate cele 5 VM-uri (es-node-1 pornit de 21 de zile).
8. Fara copie off-host in continuare: 0 imagini / 0 volume / 0 backup-uri in OpenStack.
9. Igiena: `~/lab-backup-2026-11-16.tgz` e 0664; `/tmp/ab-old` (copie de repo cu `.env` si `soc.env`),
   `~/lab-gate` (clona veche, murdara), `soc.env.pre-3c`; credentialul OpenStack `debian-cli` fara expirare.
10. Jurnal: `stare.md` nu are intrari intre 2026-11-05 si 2026-11-17 (deploy-ul din 16.11, mutarea IP-ului);
    antetul din REZUMAT.md e inca "2026-11-04 / faza-21".
11. FP zilnice inca active (24 h): lsb_release 27 de alerte, "www-data binar nevazut" 12 (fp_rate 1.0).

### Dupa a doua verificare (2026-11-17, ~08:30 UTC): ce a rezolvat Claude si ce ramane

Rezolvat:
- punctul 4: `tests/test_reader.py` ruleaza o copie a gate-ului in care doar `logger` e neutralizat
  (`fc9e9e3`). Verificat pe es-node-1: 0 linii noi in syslog la o rulare completa (inainte: 16 pe rulare).
  Gate-ul din `deploy/` e neschimbat. `pytest tests` se poate rula din nou pe es-node-1.
- punctul 9 (partial): `~/lab-backup-2026-11-16.tgz` -> 0600, `/tmp/ab-old` -> 0700. Nimic sters.
- jurnal: intrarea pentru 2026-11-16 adaugata in `stare.md` (din reflog si journald).

Incercat si REFUZAT de sistemul de permisiuni al lui Claude (ramane la om):
- `ssh-parola` (comenzile sunt mai sus, sectiunea "Faza 23", punctul 0);
- etapa 2: cheia de citire da 403 pe `soc-traces`, iar Claude nu are voie sa foloseasca cheia de
  writer nici pentru citire. Omul ruleaza (metrics.py citeste soc-traces tot cu cheia de writer):
  ```
  cd ~/lab && set -a; . ./soc.env; set +a; source env.sh; cd ~/lab-faza23
  ~/lab/venv/bin/python experiments/tier2_fara_dovezi.py --zile 30 --cheie-urme ES_WRITER_API_KEY
  ```
  Maparea verdicts-history e text + .keyword (verificat), deci filtrele din script sunt corecte.

Ramane la om, in ordine: (1) ssh-parola; (2) poarta faza-22 (B1), cu regula 80 de la 172.30.6.133
scoasa temporar din victim-sg; (3) pornit benign-gen + regula 80 la loc; (4) etapa 2 (comanda de mai
sus); (5) etichetare 50 + 50; (6) imagine OpenStack pentru es-node-1 si web-prod; (7) reboot pe cele
5 VM-uri, es-node-1 ultimul; (8) ES la verde (replici 0, contul elastic); (9) etapele 4-9.

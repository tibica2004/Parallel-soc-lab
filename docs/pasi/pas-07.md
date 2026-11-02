# Pasul 7 — Observabilitatea orchestratorului

Scop: SOC-ul isi masoara singur sanatatea (fiecare ciclu, tunelul LLM) si pagineaza omul cand
bucla se blocheaza, desi serviciul pare "active".

## A. Fisiere
| Fisier | Ce face |
|---|---|
| cycle_metrics.py (nou) | documentul soc-metrics type=cycle (functie pura) + scriere care nu arunca |
| sdnotify.py (nou) | WATCHDOG=1 / READY=1 pe NOTIFY_SOCKET, fara dependente; no-op in afara systemd |
| orchestrator.py (diff) | un doc type=cycle per ciclu (durata, coada, inchise/escaladate, Tier 2, fara model, timeout/erori, honeytoken, tokeni/apeluri/ms model, backlog, sweep, shadow, model_tag, error); watchdog dupa fiecare alerta, finding si ciclu; numaratori fail_* si honeytoken_hits in stats |
| tracing.py (diff) | totaluri LLM per ciclu (lacat; si apelurile fara caz deschis); take_llm_totals() |
| llm_probe.py (nou) + deploy/es-node-1/soc-llm-probe.{service,timer} | /api/tags la minut, generare 5 tokeni la 5 min, soc-metrics type=llm_probe; 3 esecuri consecutive -> integrity_alert llm_tunnel_down + Discord |
| absence_check.py (diff) | ORCHESTRATOR_STALLED (fara ciclu > 15 min), ORCHESTRATOR_SLOW (>= 3 cicluri > 110 s in 10 min), PROBE_MISSING (sonda tacuta > 5 min); citire cu ES_READER (ES_API_KEY: 403 pe soc-metrics) |
| deploy/soc-orchestrator.service (diff, ExecStart NEATINS) | NotifyAccess=main, WatchdogSec=900, MemoryMax=2G, NoNewPrivileges, ProtectSystem=strict, PrivateTmp, ReadWritePaths=data/ |
| deploy/kibana/build_health_dashboard.py + soc-health.ndjson | dashboard "SOC Health", 13 panouri |
| deploy/es-node-1/pas7-setup.sh | pentru om: mapping explicit (28 campuri noi) + import dashboard |
| tests/test_cycle_metrics.py, test_health_dashboard.py, test_absence_check.py (+4) | 990 teste total |

### Decizii masurate
- **WatchdogSec=900, nu 300**: ciclurile masurate pe 48 h: median 120 s, p95 122 s, maxim 716 s
  (sub harness). Cu 300 s si ping doar la final de ciclu, systemd ar fi omorat orchestratorul in
  mijlocul investigatiilor. Ping per alerta/finding + 900 s.
- **orchestrator_stalled la 15 min, nu 5**: acelasi motiv (cicluri lungi legitime). Blocajul
  procesului il prinde watchdog-ul; absence_check prinde bucla care nu mai termina cicluri.
- **MemoryMax=2G**: varf masurat 119 MB.
- **ProtectSystem=strict**: verificat ca modulele importate de orchestrator scriu doar in data/
  (dedup-ul notificarilor) si nu ruleaza subprocess/ssh.
- **Alertele de absenta prin poller (absence_check), nu reguli Kibana**: licenta fara conectori;
  notificarea merge pe Discord (pasul 0.4).
- Tokeni: total per apel (usage_metadata), nu in/out separat — asa ii raporteaza deja apelantii.

## B. Comenzi (rulate 2026-11-02)
- Claude: scp cod (sha256 verificat; copii *.pre-7), absence_check activat DUPA primul ciclu.
- Om: `bash deploy/es-node-1/pas7-setup.sh` (mapping OK, import 16 obiecte) si instalarea
  unitatilor + restart orchestrator (WatchdogUSec=15min, MemoryMax=2147483648, active).

## C. Verificare
- primul doc type=cycle: duration_s 159.85 (cu sweep), llm_calls 11, tokens 90703, shadow true;
- llm_probe ok=True, 5 ms; absence_check: "ultimul ciclu acum 0.3 min", rc=0;
- Kibana -> Dashboards -> "SOC Health".

## D. Metrica / poarta
- Poarta (atinge bucla): fast **4/4** (3/3 atacuri, FP 0/1); dev **12/14**, recall **8/8**, FP 2/6.
  FP-urile: `php --version` (cunoscut, referinta post-migrare) si "Deploy legitim din /opt"
  (suspicious/70). Al doilea re-rulat de 3 ori: benign/85, benign/75, benign/85 -> variatie de
  model (rolul hunt are temperatura 0.1/0.7), nu regresie. Nimic ajustat.
- Acceptare ramasa: 24 h de type=cycle fara gol > 4 min (fara restart); testul aprobat
  "systemctl stop soc-orchestrator 6 min" -> service_down + (dupa 15 min) orchestrator_stalled.

## E. Rollback (doar la cerere)
```
cd ~/lab && for f in orchestrator.py tracing.py absence_check.py deploy/soc-orchestrator.service; do cp -p $f.pre-7 $f; done
sudo install -m 644 deploy/soc-orchestrator.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl restart soc-orchestrator
sudo systemctl disable --now soc-llm-probe.timer
# Kibana: sterge obiectele soc-metrici-health-*; campurile de mapping raman (inofensive)
```

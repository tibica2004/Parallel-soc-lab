# Pasul 3.D — Monitor de integritate -> soc-incidents

EXCLUSIV DEFENSIV, doar observare. Nicio actiune pe hosturi. Shadow activ.

## Ce exista si ce adauga 3.D

`absence_check.py` (pasul 0.4, timer 10 min) verifica deja: backup vechi, orchestrator/tunel
cazut, canar lipsa — si pagineaza direct pe Discord. 3.D il EXTINDE (nu il dubleaza):

| Verificare | Inainte | Dupa 3.D |
|---|---|---|
| backup / servicii / canar | Discord | Discord + `integrity_alert` in soc-incidents |
| tacere pe flux (7 fluxuri web-prod) | lipsa | NOU: prag per flux, din pauzele reale |
| fleet-server `/api/status` | lipsa | NOU |
| puls `integrity_check` | lipsa | NOU in soc-metrics, la fiecare rulare |
| cine pazeste paznicul | lipsa | NOU: orchestratorul pagineaza daca pulsul lipseste > 5 min |
| frecventa | 10 min | 1 min |

Praguri (masurate 2026-10-30 pe 3 zile, pauza maxima reala): proces/retea/auditd/syslog/auth
4 min -> prag 10; fisiere 6 min -> 15; Suricata 0 min -> 10 (filtrat pe `agent.name`: evenimentele
Suricata NU au `host.name`). Apache exclus: tace legitim ore intregi fara trafic (revine cu
generatorul benign, pasul 4).

## Abateri de la textul initial (cu motiv)

| Text | Ales | Motiv |
|---|---|---|
| puls in soc-audit | puls in soc-metrics `type=integrity_check` | soc-audit e jurnalul verdictelor, citit de interfata de etichetare/metrici; 1440 de pulsuri/zi l-ar polua. 7.1 prevede oricum `integrity` in soc-metrics. |
| regula Kibana „integrity_checker_down” (ES query, count below 1) | orchestratorul verifica pulsul la fiecare ciclu si pagineaza pe Discord | licenta basic: fara conectori de notificare; regula ar aparea doar in UI. Paza reciproca: absence_check verifica orchestratorul (systemctl), orchestratorul verifica pulsul. |
| orchestratorul preia integrity_alert ca alerta -> escalate_human | Discord direct + inregistrare in soc-incidents | rezultatul cerut (om anuntat, fara model) e atins direct; cheia principala a orchestratorului nu citeste soc-incidents. |
| `check_agent()` prin Fleet API | amanat | cere o cheie Kibana cu `fleet:read` (o creeaza omul). Tacerea pe flux prinde exact cazul periculos: agent „Healthy” care nu trimite. |
| `check_canary_hash()` | amanat | cere gate-ul SSH `soc-reader` (pasul 1b); nicio comanda din cod prin `tiberiu@` (D1). |

Corectie fata de o afirmatie anterioara (stare.md 3.C): auditd NU a tacut 17 h; pauza maxima
in 3 zile e 4 min. Configul stricat din 29.10 a blocat doar aplicarea regulilor noi (componenta
veche a continuat cu regulile vechi).

## A. Fisiere

- `absence_check.py` — extins: `IntegrityKind` (Enum inchis), `IntegrityAlert` (Pydantic, extra=forbid),
  `Run.problem()` (Discord + soc-incidents, dedup separat 10 min), `check_streams`, `check_fleet_server`,
  `write_heartbeat`. Hostul intra in `term` (R7). Iesire 1 la orice verificare/scriere esuata (R9).
- `notify.py` — `recent()` / `mark()` publice (aceeasi stare de dedup, chei separate).
- `orchestrator.py` — `_integrity_watch()` la fiecare ciclu.
- `deploy/es-node-1/soc-absence.timer` — `OnCalendar=*:*:00`, jitter 10 s.
- `deploy/es-node-1/soc-absence.service` — doar descrierea/comentariul.
- `tests/test_absence_check.py` — 22 teste.

Chei: `ES_INCIDENTS_WRITER_API_KEY` (create_doc/index pe soc-incidents) si `ES_METRICS_WRITER_API_KEY`
(soc-metrics) — exista deja (pasul 1), scoped. Citire: `ES_API_KEY` (logs-*). Orchestratorul citeste
pulsul cu `ES_WRITER_API_KEY` (are read pe soc-metrics).

## B. Comenzi

1. (Claude) scp pe es-node-1, cu copii `.pre-3d`: `absence_check.py notify.py orchestrator.py`,
   `deploy/es-node-1/soc-absence.{service,timer}` in ~/lab/deploy/es-node-1/; sha256.
2. (OMUL, sudo) `sudo install -m 644 ~/lab/deploy/es-node-1/soc-absence.{service,timer} /etc/systemd/system/ &&
   sudo systemctl daemon-reload && sudo systemctl restart soc-absence.timer && sudo systemctl start soc-absence.service &&
   sudo systemctl restart soc-orchestrator`

## C. Verificare

- `journalctl -u soc-absence -n 30` -> `flux ... OK` x7, `fleet-server: HEALTHY`, exit 0.
- soc-metrics: un doc `type=integrity_check result=ok` pe minut (3 la ~1 min distanta).
- `systemctl list-timers soc-absence.timer` -> urmatoarea rulare < 1 min.
- Test negativ (aprobat): `sudo systemctl stop soc-absence.timer` 6 min -> orchestratorul scrie
  „[integritate] monitorul tace” + Discord; apoi `start`.
- Test tacere (optional, aprobat): oprirea agentului pe web-prod 11 min -> integrity_alert
  telemetry_silence pe fluxuri + canary_missing in soc-incidents.

## D. Metrica

soc-metrics `type=integrity_check`: `result`, `kinds`, `ages_min` per flux. Acceptare: 24 h de
pulsuri fara gol > 4 min; zero `integrity_alert` fals in 48 h; testul negativ produce paginarea.

## E. Rollback

`cp -p X.pre-3d X` pentru cele 3 fisiere Python si cele 2 unitati; `sudo install` unitatile vechi,
`daemon-reload`, restart timer + orchestrator. Documentele integrity_alert/integrity_check raman
(nu se sterge nimic).

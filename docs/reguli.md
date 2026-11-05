# Regulile R1-R16 si G1-G9

Regulile vin din documentul extern al task-ului "Extindere SOC agentic Blue Team" (documentele 6, 7
si completarile G), care nu e in repo. Codul si documentele le citeaza dupa ID, dar textul lor nu
exista nicaieri aici. Pagina asta e locul unic in care se tine textul.

STARE (2026-11-05, faza 22 J.4): textul regulilor NU e completat. Il furnizeaza omul din documentul
original; agentul nu inventeaza formulari. Pana atunci, tabelul de mai jos arata DOAR unde e citata
fiecare regula in repo si ce se intelege din context (coloana "Context din repo" e un rezumat al
citarilor, nu textul regulii).

Inventar la 2026-11-05 (`grep -rhoE "\b(R1[0-6]|R[1-9]|G[1-9])\b"` pe *.md si *.py, fara venv):
citate R1-R9, R12, R14-R16, G1-G9; R10, R11, R13 nu apar nicaieri. In `docs/arhitectura.md`
R1-R5 sunt ID-uri de noduri Mermaid, nu citari.

## R1-R16 (regulile planului 0-day)

| ID | Text (de completat de om) | Context din repo (unde e citata, ce se intelege) |
|---|---|---|
| R1 | _de completat_ | CLAUDE.md, README (intervalul R1-R16); plan-0day.md |
| R2 | _de completat_ | pas-01*.md (soc-reader, nday) |
| R3 | _de completat_ | pas-00/01: "OK per comanda pe hosturi" |
| R4 | _de completat_ | pas-01*.md |
| R5 | _de completat_ | reader/static: "CODUL decide ce e explicat" |
| R6 | _de completat_ | reader.py: ReaderError la esec |
| R7 | _de completat_ | notify.py: pointer, nu telemetrie; nday: term pe host.name |
| R8 | _de completat_ | pas-01: chei API cu drept minim (fara delete, fara manage) |
| R9 | _de completat_ | orchestrator/absence/reader: esecul escaladeaza, nu inchide; plafonul sub flood |
| R10 | _de completat_ | necitata |
| R11 | _de completat_ | necitata |
| R12 | _de completat_ | pas-09 (readiness): verificari inainte de iesirea din shadow |
| R13 | _de completat_ | necitata |
| R14 | _de completat_ | scripturi noi: log + exit 1 la orice eroare |
| R15 | _de completat_ | niciun secret in cod |
| R16 | _de completat_ | CLAUDE.md, README: niciun secret al SOC-ului pe web-prod |

## G1-G9 (completarile G)

| ID | Text (de completat de om) | Context din repo |
|---|---|---|
| G1 | _de completat_ | prompt_injection: >= 98% identic si 100% pe malicious |
| G2 | _de completat_ | soc-wp-update: user deploy, mod raport |
| G3 | _de completat_ | honeytokens: IP-urile proprii / benign-gen nu sunt intruziune (BENIGN_GEN_IPS) |
| G4 | _de completat_ | firewall nft pe es-node-1 (9200 doar din web-prod/benign-gen), fara cheie SSH pe web-prod |
| G5 | _de completat_ | o ramura per faza in ~/lab, nu repo separat |
| G6 | _de completat_ | IPv6 pe web-prod |
| G7 | _de completat_ | unitati systemd: Restart, MemoryMax, watchdog; ExecStart neatins |
| G8 | _de completat_ | rotatia cheilor la 90 de zile (prima: 2027-01-06) |
| G9 | _de completat_ | AIDE pe web-prod |

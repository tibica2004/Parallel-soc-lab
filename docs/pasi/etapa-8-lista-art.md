# Etapa 8 — lista Atomic Red Team (pregatita 2026-11-17, NIMIC RULAT)

Inventar facut prin citire pe web-prod (`/opt/atomic-red-team/atomics`, 20 de directoare de tehnici), cu
functiile pure din `/opt/soc/art_runner.py` (`render`, `refusal`). Nicio comanda de test nu a rulat.
Rulat pana acum: **T1053.003 #1** (2026-11-03, cleanup_ok=true). Deci 1/20.

## ATENTIE: doua teste periculoase treceau ca "permis"

Runner-ul de pe web-prod (versiunea deployata) NU refuza:
- **T1070.004 #8** "Delete Filesystem - Linux" = `rm -rf / --no-preserve-root`. Ar distruge web-prod.
- **T1070.003 #10** = `docker container prune -f` + golirea logurilor docker.

Reparat in cod pe ramura faza-23 (`_DESTRUCTIVE` in `deploy/web-prod/art_runner.py`, cu teste), dar
**fisierul de pe web-prod e inca cel vechi**. Inainte de orice rulare, omul copiaza runner-ul nou:

    scp deploy/web-prod/art_runner.py tiberiu@172.30.6.249:/tmp/art_runner.py
    ssh -t tiberiu@172.30.6.249 "sudo install -m 0755 /tmp/art_runner.py /opt/soc/art_runner.py && sudo /opt/soc/art_runner.py T1070.004 8 --show"

Ultima comanda trebuie sa afiseze `REFUZAT: distructiv`. Pana atunci: NU rula T1070.004 si T1070.003 #10.

## Pregatirea sesiunii (o data)

1. benign-gen oprit, fara harness, fara OpenClaw (atributia din coverage.py e pe fereastra de timp):
   `ssh -J ubuntu@172.30.6.106 ubuntu@192.168.10.150 "sudo systemctl stop benign-gen"`
2. A doua sesiune SSH deschisa pe web-prod pe toata durata (pentru T1098.004).
3. Dupa FIECARE test: `cleanup_ok` afisat de runner trebuie sa fie True (sau None la testele fara
   cleanup), apoi pe es-node-1, dupa ~6 minute:
   `cd ~/lab && set -a; . ./soc.env; set +a; source env.sh; venv/bin/python coverage.py`
   Un cleanup esuat = oprire.
4. La sfarsit: benign-gen pornit la loc.

## Cele 14 tehnici rulabile acum (una cate una; intai `--show`, apoi fara)

Toate: `sudo /opt/soc/art_runner.py <tehnica> <numar>` pe web-prod. Ordinea: de la inofensiv la invaziv.

| # | Tehnica | Test | Ce face | Cleanup | Verificare dupa | Sablon de vanatoare existent |
|---|---|---|---|---|---|---|
| 1 | T1082 | 3 | uname, lsb-release -> /tmp/T1082.txt | da | `ls /tmp/T1082.txt` nu exista | nu |
| 2 | T1057 | 1 | ps -> /tmp/loot.txt | da | `ls /tmp/loot.txt` nu exista | nu |
| 3 | T1083 | 3 | ls, file -> /tmp/T1083.txt | da | `ls /tmp/T1083.txt` nu exista | nu |
| 4 | T1087.001 | 1 | cat /etc/passwd -> /tmp/T1087.001.txt | da | fisierul nu exista | nu |
| 5 | T1049 | 4 | ss -antp | nu are (nu lasa urme) | - | nu |
| 6 | T1048.003 | 8 | python3 -m http.server 9090 in /tmp, 10 s | nu are | `ss -ltn | grep 9090` gol | nu (shell_network e apropiat) |
| 7 | T1036.005 | 1 | copiaza sh in `$HOME/...` si il ruleaza | da | `ls -a ~root | grep "\.\.\."` gol | nu |
| 8 | T1070.003 | 6 | unset HISTFILE; history -c (in subshell) | nu are | - | history_tamper |
| 9 | T1222.002 | 1 `--arg file_or_folder=/tmp/art-t1222` | chmod 755 pe un director creat de tine (`mkdir /tmp/art-t1222` inainte) | nu are | `rmdir /tmp/art-t1222` | nu |
| 10 | T1003.008 | 1 | sudo cat /etc/shadow -> /tmp/T1003.008.txt | da | fisierul nu exista (contine hash-uri!) | shadow_read |
| 11 | T1548.001 | 3 | /tmp/evilBinary cu setuid | da | `ls /tmp/evilBinary` nu exista | setuid_chmod |
| 12 | T1136.001 | 1 | useradd evil_user | da | `getent passwd evil_user` gol | identity_write |
| 13 | T1098.004 | 1 | rescrie ~/.ssh/authorized_keys cu acelasi continut | da | din a doua sesiune: `ssh` nou merge | ssh_key_write |
| 14 | T1105 | 3 `--arg remote_host=192.168.10.160 --arg username=ubuntu --arg local_file=/etc/hostname` | scp spre lab-sink | nu are | pe lab-sink: `ls /tmp/victim-files` | nu |

Note:
- **T1003.008 #1** scrie hash-urile in /tmp pana la cleanup; nu sari peste cleanup.
- **T1098.004 #1** ruleaza cu sudo, deci atinge authorized_keys al contului in care ajunge `~` sub sudo.
  Verifica intai cu `--show` si tine a doua sesiune deschisa.
- **T1105 #3** poate cere parola sau confirmarea cheii lab-sink si atunci sta pana la timeout (300 s);
  esecul conexiunii e tot telemetrie valida (procesul scp a rulat). Argumentele sunt propunerea mea,
  neverificata prin rulare.
- **De evitat** desi sunt "permise": T1070.003 #1-#5 (sterg ~/.bash_history fara cleanup), T1136.001 #6
  (cont cu UID 0 si parola cunoscuta), T1053.003 #2-#4 (scriu in cron-ul sistemului), T1070.003 #7
  (modifica ~/.bashrc).

## De ce nu se ajunge la 20 doar cu ce e pe web-prod

Cu T1053.003 deja rulat, lista de mai sus duce la **15 tehnici**. Celelalte 5 directoare nu au niciun test
rulabil: T1016, T1027, T1046, T1070.004 (toate testele linux au dependinte sau IP-uri straine; singurul
"permis" din T1070.004 e cel distructiv), T1021.004 (niciun test linux acceptat).
Pentru >= 20 trebuie ca omul sa adauge cel putin 5 directoare de tehnici in `/opt/atomic-red-team/atomics`
(din acelasi commit fixat). Propunere, in ordinea utilitatii pentru sabloanele din hunt.py:
T1543.002 (systemd_unit_write), T1552.001 (credential_grep), T1070.002 (log_wipe), T1059.004
(shell_network), T1033, T1069.001, T1007, T1201. Numerele testelor nu le stiu fara depozit: dupa ce le
aduci, rulez acelasi inventar si completez tabelul. T1547.006 (modul de kernel) NU il propun.

## Ipoteze Tier 3

Tehnicile fara sablon in hunt.py (coloana "nu") primesc o ipoteza Tier 3 DOAR daca ies `unseen` sau
`logged_only` in coverage.py; ipotezele se scriu dupa rulare, pe rezultatul real, nu dinainte.

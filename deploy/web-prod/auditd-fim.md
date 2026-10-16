# auditd + FIM pe web-prod (faza 12, pasul 3)

Ambele sunt integrari Elastic Agent, adaugate din Fleet in politica lui web-prod.
Nu se instaleaza nimic pe host: Auditd Manager vorbeste direct cu kernelul
(auditd nu e instalat, deci nu exista conflict), FIM e in agent.

De ce:
- **auditd** vede ce Defend nu vede: CITIREA unui fisier. Momeala .env.bak citita
  cu `grep -r`, dintr-un webshell PHP (file_get_contents) sau de orice proces.
  Plus modificarile de identitate/persistenta si incarcarea de module de kernel.
- **FIM** e un al doilea senzor pe fisiere, independent de Defend (Defend a murit
  tacut de doua ori), cu hash-uri. Doar pe cateva directoare.

## 1. Auditd Manager

Integrations -> "Auditd Manager" -> Add -> politica agentului web-prod.
- Socket type: `multicast`
- Resolve IDs: da
- Audit rules (exact, inlocuieste ce e implicit):

```
## Honeytoken: orice deschidere pentru citire a momelii
-w /var/www/html/.env.bak -p r -k soc_honeytoken
## Persistenta
-w /etc/cron.d/ -p wa -k soc_persistence
-w /etc/crontab -p wa -k soc_persistence
-w /var/spool/cron/ -p wa -k soc_persistence
-w /etc/systemd/system/ -p wa -k soc_persistence
-w /root/.ssh/ -p wa -k soc_persistence
-w /home/tiberiu/.ssh/ -p wa -k soc_persistence
## Identitate
-w /etc/passwd -p wa -k soc_identity
-w /etc/shadow -p wa -k soc_identity
-w /etc/sudoers -p wa -k soc_identity
-w /etc/sudoers.d/ -p wa -k soc_identity
## Module de kernel (rootkit)
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k soc_kmod
```

Fara execve pentru toate procesele: Defend le are deja, iar volumul ar fi mare.

## 2. File Integrity Monitoring

Integrations -> "File Integrity Monitoring" -> Add -> aceeasi politica.
- Paths:
  - `/var/www/html`
  - `/etc/cron.d`
  - `/etc/systemd/system`
  - `/usr/local/bin`
- Recursive: da
- Hash types: `sha256`
- Exclude files (regex): `\.env\.bak$`

Excluderea e obligatorie: FIM citeste fisierele ca sa le calculeze hash-ul, iar
citirea momelii de catre agent ar declansa honeytoken-ul de citire.

## Verificare

    cd ~/lab && source env.sh
    python3 -c "from elastic_tools import ES; print(ES.count(index='logs-auditd_manager.auditd-*')['count'], ES.count(index='logs-fim.event-*')['count'])"

Regula honeytoken pentru citire (`soc-honeytoken-read`) se creeaza DUPA ce vin
date, cu `deploy/kibana/honeytoken_rules.py aplica` (creeaza doar ce lipseste).

## 3. audit=1 la boot (obligatoriu)

Descoperit la test (2026-10-16): kernelul auditeaza apelurile de sistem doar
pentru procesele pornite DUPA activarea auditului. apache2, sshd, cron rulau
dinainte, deci citirea momelii prin HTTP (adica si de catre un webshell PHP, care
ruleaza in apache2) NU aparea; un `grep` nou pornit, da. Cu `audit=1` pe linia de
comanda a kernelului, fiecare proces are context de audit de la boot.

    echo 'GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit=1 audit_backlog_limit=8192"' \
      | sudo tee /etc/default/grub.d/soc-audit.cfg
    sudo update-grub
    sudo reboot

Verificare dupa reboot: `grep -o 'audit=1' /proc/cmdline`.

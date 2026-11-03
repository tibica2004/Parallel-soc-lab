# Executie suspecta din director temporar

## Ce inseamna
Un proces a fost lansat din /tmp, /var/tmp sau /dev/shm (sau dintr-un binar
sters / memfd). Atacatorul isi descarca unealta intr-un loc unde www-data poate
scrie si o executa de acolo. Rareori legitim.

## Verifica lantul
- Parinte apache2/php/sh cu user www-data -> instalarea uneltelor dupa un RCE.
  MALITIOS, T1059 + T1105.
- Parinte bash al unui admin din normal_admins (script de test, compilare)
  -> plauzibil benign doar in_maintenance_window.
- Parinte dpkg/apt/unattended-upgrades cu user root -> scripturile de pachet
  folosesc /tmp, BENIGN.
- Nume aleator, fara extensie, fisier sters imediat dupa pornire -> atac.

## Verifica consecintele
- Conexiune noua (egress_for_host) deschisa de proces -> reverse shell sau C2.
- Fisier scris in webroot sau in cron/systemd dupa -> persistenta, T1053/T1543.
- /dev/shm e aproape intotdeauna atac: nu lasa urme pe disc.

## Verifica contextul
- sensitive_action=true (ran_from_temp_dir): benign doar cu admin cunoscut
  SI fereastra de mentenanta. Identitatea singura nu-l face benign.

## Concluzie
www-data, /dev/shm sau egress nou -> malicious, escaladeaza. root prin
dpkg/apt in timpul unui update -> benign. Altfel suspicious, escaladeaza.

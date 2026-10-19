# Honeytoken: momeala atinsa

## Ce inseamna
Pe web-prod exista momeli pe care nimic legitim nu le foloseste: fisierul
/var/www/html/.env.bak (credentiale false), caile web /.env.bak si
/admin.old.php, utilizatorul svc_deploy (exista doar in .env.bak). O atingere
inseamna ca cineva exploreaza hostul sau aplicatia. Regula nu depinde de
baseline: functioneaza la fel pentru un exploit cunoscut sau un 0-day.

## Verifica
- Cerere web (soc-honeytoken-http): source.ip extern -> recunoastere tintita,
  T1083. Urmeaza des o incercare cu svc_deploy.
- Proces cu .env.bak sau svc_deploy in argumente (soc-honeytoken-host): cineva
  are deja executie pe host si cauta credentiale, T1552.001. De la www-data ->
  webshell sau RCE in spate; cauta procesul parinte.
- Citire vazuta de kernel (soc-honeytoken-read, auditd): procesul care a
  deschis fisierul; apache2/php-fpm fara cerere HTTP pe /.env.bak -> cod PHP
  (webshell) care cauta credentiale, T1552.001.
- Autentificare cu svc_deploy (soc-honeytoken-user): credentialele din momeala
  sunt folosite, T1078. Atacatorul a citit fisierul mai devreme.

## Verifica contextul
- Un administrator care inspecteaza momeala produce aceeasi alerta. Doar omul
  poate confirma asta; sistemul nu inchide niciodata o alerta de honeytoken.

## Concluzie
Cel putin suspicious, escaladeaza mereu. Cu executie de la www-data sau cu
svc_deploy folosit -> malicious.

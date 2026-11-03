# Webshell: fisier executabil scris in webroot

## Ce inseamna
Un fisier executabil (.php, .phtml, .sh...) a fost creat sau modificat in
/var/www/html. Regula vede scrierea, nu continutul. Plantarea unui webshell
arata exact asa; la fel arata un deploy legitim. Diferenta o fac CINE a scris
si CAND.

## Verifica cine a scris
- Proces www-data (apache2, php) -> serverul web isi scrie propriul cod:
  upload printr-un plugin vulnerabil sau RCE. MALITIOS, T1505.003.
- cp/tar/git/wp/rsync din bash, user din normal_admins, in_maintenance_window
  -> deploy, probabil BENIGN.
- soc-wp-update (parinte python3 din systemd, in fereastra de update) -> BENIGN.

## Verifica fisierul
- Nume scurt sau aleator in radacina, in uploads sau in cache (drop.php, b.php)
  -> webshell. Fisier in arborele unui plugin/teme cunoscute -> deploy plauzibil.
- Cerere HTTP catre aceeasi cale imediat dupa scriere (apache_requests)
  -> webshell ACTIV. Proces pornit de apache2 dupa -> RCE confirmat.

## Verifica contextul
- sensitive_action=true: in afara ferestrei de mentenanta ramane cel putin
  suspicious chiar pentru un admin (credentiale furate fac acelasi gest).
- Momelile plantate de om sunt documentate; nu sunt webshell-uri.

## Concluzie
Scris de www-data sau accesat prin HTTP -> malicious, escaladeaza. Admin
cunoscut, in fereastra, fisier in arborele aplicatiei -> benign. Altfel
suspicious, escaladeaza.

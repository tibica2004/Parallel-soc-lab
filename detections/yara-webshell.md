# YARA: webshell gasit in webroot

## Ce inseamna
Scanarea YARA a /var/www (la 10 minute si la orice creare in /var/www/html) a
gasit un fisier care se potriveste cu o regula de webshell: PHP care executa sau
evalueaza ce vine din cererea HTTP, payload ascuns prin codare, shell legat de un
socket, marcaje de webshell-uri cunoscute. Procesul din alerta (soc-yara-scan,
root) e scannerul, NU cel care a scris fisierul.

## Verifica
- sensor_detection.path: fisierul. Cine l-a scris? Cauta in evenimentele de
  fisier (Defend) dupa file.path: procesul si utilizatorul care l-au creat.
- A fost accesat? Cereri HTTP catre aceeasi cale in logurile Apache.
- Procese pornite de apache2 dupa momentul scrierii (RCE prin el).
- soc_php_reverse_shell sau soc_known_webshell_markers -> CRITIC.

## Verifica contextul
- O biblioteca PHP legitima poate folosi eval; un deploy in fereastra de
  mentenanta, de un admin cunoscut, cu fisierul in arborele aplicatiei, e plauzibil.
- Un fisier mic, singur, scris de www-data sau dintr-un proces pornit de apache2
  -> webshell.

## Concluzie
Cel putin suspicious, escaladeaza. Scris de www-data sau accesat prin HTTP ->
malicious, T1505.003.

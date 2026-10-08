# Payload download: curl/wget spawned by web server or shell

## Ce inseamna
curl sau wget lansat de serverul web sau de un shell. In post-exploatare,
atacatorul isi descarca uneltele de pe infrastructura proprie.

## Verifica intai PARINTELE si UTILIZATORUL
- parinte `apache2`, `php-fpm`, `nginx` + user `www-data` -> MALITIOS aproape sigur.
  Serverul web nu descarca nimic in mod normal.
- parinte `bash`/`dash` + user din `normal_admins` al hostului -> probabil BENIGN.
  Un administrator care ruleaza curl interactiv e activitate normala.

## Verifica DESTINATIA
- `localhost` sau `127.0.0.1` -> aproape sigur test sau healthcheck local, BENIGN
- IP intern cunoscut -> probabil legitim
- IP extern nevazut anterior -> suspect

## Verifica BASELINE
Daca `pair_in_baseline` este true, perechea parinte-copil a mai fost vazuta
in ultimele 90 de zile pe acest host. Asta scade semnificativ suspiciunea.
NU raporta `uniqueness: RARE` daca `pair_in_baseline` este true.

## Concluzie
Escaladeaza doar daca parintele e serverul web SAU destinatia e externa
si nevazuta. Un admin care da curl catre localhost nu e incident.

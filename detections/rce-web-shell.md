# RCE: serverul web a pornit un shell care ruleaza comenzi

## Ce inseamna
apache2/php-fpm a pornit un shell (sh/dash/bash) care a executat o comanda
(id, whoami, uname). Serverul web NU ruleaza shell-uri in operare normala.

## Verifica lantul
- Parinte apache2/php-fpm/nginx si copil shell care ruleaza id/whoami/uname/cat
  -> RCE aproape sigur, MALITIOS. T1059 + T1505.003.
- Cerere HTTP catre un .php nou (apache_requests) urmata de executie
  -> webshell confirmat.

## Verifica contextul
- Daca userul e www-data (nu un admin din normal_admins), serverul web executa
  comenzi. Semnal puternic de atac.
- Un admin care ruleaza id prin bash interactiv e benign; www-data care ruleaza
  id prin apache2 NU este.

## Concluzie
Parinte server web + copil shell cu comanda de recon -> malicious, escaladeaza.

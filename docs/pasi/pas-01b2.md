# Pasul 1b.2 — Hash-ul canarului si al cron-ului prin soc-reader

Deblocat de 1b. In absence_check (timer la minut), la fiecare INTEGRITY_HASH_EVERY_MIN=10 minute:

- check_canary_hash: `reader.run(CANARY_HASH)` vs referinta SCRISA DE OM `~/lab/data/canary.sha256`
  (format sha256sum; nu se actualizeaza singura). Diferit -> integrity_alert `canary_tampered`
  (critical). Referinta lipsa -> `check_failed` (R9: nu pot verifica != ok).
  Valorile verificate 2026-10-30, independent de web-prod: binarul = /usr/bin/true (8a63c983...,
  conform README), cron = fisierul din repo deploy/web-prod/soc-canary.cron (ae643e7f...).
- check_cron_hash: `reader.run(CRON_HASH)` (/etc/crontab + /etc/cron.d/*) vs ultima stare
  `~/lab/data/cron.sha256`. Prima rulare invata; apoi fisier nou/sters/modificat -> `cron_changed`
  (high), raportat o data, devine noua stare (ca AIDE). /var/spool/cron/crontabs nu e citibil de
  soc-reader (root 1730): acolo raman auditd soc_persistence + hunt.py.
- Esecul reader-ului (timeout, DENIED) -> `check_failed`, exit 1.

Fum pe sistemul real (prin gate): canar OK, cron 5 fisiere invatate, a doua rulare fara diferente.

B. (Claude) scp absence_check.py pe es-node-1 (.pre-1b2) + data/canary.sha256 cu valorile de mai sus
   (confirmate de om). Fara restart: timerul ruleaza fisierul la fiecare minut.
C. journalctl -u soc-absence la minutul :x0 -> "canar hash OK", "cron: stare initiala invatata".
   Test (cu OK): `sudo touch /etc/cron.d/soc-test` pe web-prod -> la urmatorul :x0, cron_changed.
E. cp -p absence_check.py.pre-1b2 absence_check.py; rm data/canary.sha256 data/cron.sha256.

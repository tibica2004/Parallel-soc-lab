# Detectii oprite, neactivate sau cu acoperire redusa

Scris 2026-11-03. Raspunde la criteriul 7 din lista de pregatire pentru agenti AI in SOC
(The Hacker News, 2026-11-02): "tineti o lista a detectiilor oprite din lipsa de capacitate?".
Regula: orice regula sau componenta de detectie oprita apare aici cu motivul, cine a decis si
conditia de repornire. Lista se actualizeaza la fiecare oprire/pornire (om sau Tier 3).

## 1. Regulile Kibana proprii (deploy/kibana/honeytoken_rules.py verifica, 2026-11-03)

Toate cele 25 de reguli proprii sunt PORNITE: 10 honeytoken, 6 comportamentale (soc-behavioral,
in fereastra shadow-review), YARA, Suricata web-attack, ModSecurity, AIDE, soc-reader-denied,
enumerare web, brute-force web/SSH, SQLi. Niciuna oprita din lipsa de capacitate.

Regulile generate de Tier 3 (eticheta tier3-generated) pot fi dezactivate de cod dupa fereastra
shadow (kibana_rules.lifecycle: kill switch sau rata de FP); starea lor curenta se vede cu
`python3 tier3.py --once --reguli` (dry-run) sau in Kibana dupa eticheta. De trecut aici cand
prima regula e dezactivata.

Regulile Elastic prebuilt (Security -> Rules): nu exista inca o lista a celor dezactivate. De
listat o data de om, cu contul elastic:

    curl -s -u elastic -H 'kbn-xsrf: x' -H 'elastic-api-version: 2023-10-31' \
      'http://localhost:5601/api/detection_engine/rules/_find?per_page=500&filter=alert.attributes.enabled:false' \
      | python3 -c 'import sys,json; [print(r["name"]) for r in json.load(sys.stdin)["data"]]'

si de lipit rezultatul (sau "niciuna") in sectiunea 2.

## 2. Componente oprite deliberat (cu motiv masurat sau decizie)

| Componenta | Stare | Motiv | Decis | Conditia de repornire |
|---|---|---|---|---|
| Criticul din Tier 2 (hunt_path, DISABLE_CRITIC=1) | oprit | masurat daunator la 14B: scadea recall-ul | om, 2026-10 | model mai mare pe Tier 2 + harness dev/fast fara regresie |
| RedSage-Qwen3-8B-DPO pe Tier 1 | optional, neactivat | qwen3:14b pe ambele niveluri (2026-10-19); GPU partajat | om | portul 11435 in soc-llm-tunnel + MODEL_FAST; ablatie A-D refacuta |
| Joburi ML Elastic (anomalii) | neactivate | cer licenta platita; licenta e basic | constrangere | licenta; pana atunci anomalies.py (beaconing, entropie DNS) |
| FIM (integrare Fleet) | renuntat | blocat in Fleet; acoperit de Defend + auditd + YARA + AIDE | om, faza 12 | nu e necesar |
| Elastic Defend: protectii in modul detect (nu prevent) | by design | shadow mode, principiul 4 | om | iesirea din shadow (pasul 9, decizie umana) |
| ModSecurity CRS | DetectionOnly | shadow; doar alerte | om, pasul 12b | idem |
| Regula auditd soc_shadow_read (regula f) pe web-prod | de confirmat | kernelul de audit e imutabil: orice regula noua cere Fleet + reboot | om | reboot documentat; verificare cu deploy/web-prod/audit-status.py |
| Executor | dry-run | nu exista cod de executie reala | principiul 4 | nu se reporneste din cod |

## 3. Acoperire redusa cunoscuta (pornite, dar cu goluri)

| Detectie | Gol | Control compensator | Urmarire |
|---|---|---|---|
| Suricata ET Open | nu prinde flood de 404 / scanare de directoare (feroxbuster 9634 cereri -> 1 alerta, 2026-11-03) | sweep web_enumeration + regula soc-web-content-enum | asumat |
| YARA pe webroot | fals pozitive pe fisiere WordPress core | triajul omului; static_triage stie upstream_core | lista alba dupa checksum-urile WP (de facut) |
| YARA | nu scaneaza momeala backup.sql (sarita dupa cale, ca sa nu declanseze honeytoken-ul) | regula honeytoken acopera fisierul | by design |
| honeytoken wpconfig-read | exclude /usr/bin/yara si /usr/bin/aide (in Kibana, nu in kernel) | AIDE si YARA sunt verificate prin hash-uri | by design |
| new_url_path | raporteaza si momelile ROBOTS_TRAPS (dublura) | regula honeytoken e cea cu podea | de decis excluderea |
| auditd pe web-prod | kernel lost=2632 evenimente de la boot-ul din 26.10 | absence_check urmareste tacerea | de urmarit la pasul 7 |
| ES single node | cluster yellow, 70 shard-uri neasignate (replici = 1) | fara pierdere de date | replicas 0 prin template/ILM (om) |
| block_ip_ttl | in laborator tot traficul extern vine prin SNAT-ul unic 172.30.6.133 (c9 pica) | shadow; niciun block | decizie: manual-only in lab |

## 4. Ce nu prinde arhitectura (din docs/plan-0day.md, "Limite")

Exploatarea care ramane in procesul PHP (SQLi cu exfiltrare prin raspuns, auth bypass urmat de
actiuni WordPress legitime), un update de plugin compromis in fereastra de update (marcata
benign), un exploit de kernel care opreste agentul (se vede doar tacerea), persistenta doar in
baza de date. Nu sunt detectii oprite: sunt goluri de acoperire asumate.

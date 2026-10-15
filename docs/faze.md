# Fazele proiectului

Sursa: promptul de lucru din conversatia claude.ai (2026-10-09) si lista de sarcini din aceeasi conversatie (2026-10-08/09). Promptul original s-a oprit la inceputul fazei 3; restul fazelor vin din descrierile sarcinilor si trebuie detaliate cu Tiberiu inainte de implementare.

Starea la 2026-10-09: faza 0 (CLAUDE.md) facuta; faza 1 implementata pe ramura faza-01-securitate, cu rezultatele in results/*-faza1-2026-10-09-0534.txt (harness dev 14/14; harness fast de verificat ca s-a terminat 4/4).

Starea la 2026-10-15: fazele 1-10 facute (vezi git log si results/). Faza 11 pe ramura faza-11-tier3:
- 11a incidente: gata (incidents.py, tier3.py --once; attack_run.sh -> un singur incident).
- 11b reguli: gata in dry-run (rules.py, tier3.py --once --reguli). Sursele golului: etichete umane de atac si Tier 2 malicious cu acord A/B. Nimic nu se creeaza in Kibana pana la: cheia Kibana separata (tier3-generated), filtrul tier3-shadow in orchestrator (cu harness dev + fast) si aprobarea lui Tiberiu.
- 11c vanatoare ATT&CK: dupa senzorii din faza 12.
Ramase din diagrama: executorul dry-run (politici), scheduler-ul Tier 3 (timer systemd, de aprobat).

## Promptul original (fidel)

FAZA 1 — Securitate si reparatii mici
Aceste reparatii le-as fi scris eu: pentru fiecare, ARATA-MI diff-ul propus si asteapta aprobarea inainte sa-l aplici.
a) hunt_path.py: parametrizeaza cele 4 interogari ES|QL (execution_facts: principala, fallback-ul cu LIKE -> STARTS_WITH, lookup-ul sudo; recent_host_alerts). Foloseste _esql din elastic_tools. int(minutes).
b) fast_path.py: node_finalize intoarce floor_applied (camp nou in FastState); lookup_history foloseste {"term": {"rule_name.keyword": rule_name}} in loc de match.
c) Deduplicarea (BoundedSeen) persista intre restarturi (fisier de stare langa cursor sau index), ca sa nu se reproceseze findings.
d) escalation.py: LOW_CONF implicit 90.
Poarta: test unitar de injectie (nume de proces cu ghilimele si operatori ES|QL -> interogarea nu se rescrie, execution_facts intoarce curat); harness dev 14/14.

FAZA 2 — Lantul in audit si escaladarea inregistrata
- In schemas.py: chain_id in Verdict si AuditRecord; escalation_reasons (lista de EscalationReason) in AuditRecord; modelul Case (chain_id, origin: tier1_alert | rarity_sweep | tier3_hunt, host, entity_id, parent, child, rule_name, escalation_reasons, evidence_refs) — FARA classification/confidence/narrative de la Tier 1.
- Orchestratorul apeleaza should_escalate dupa Tier 1 si scrie decizia in audit. NU apeleaza inca Tier 2.
- Unifica logica duplicata dintre main() si process_alerts(); ramura manuala de sweep trece si ea prin decide() si persist().
Poarta: teste unitare pentru should_escalate si Case; orchestrator --once pe ultimele 60 min ruleaza fara erori; raport cu rata de escaladare observata.

FAZA 3 — Interfata de etichetare
- O interfata web minimala servita local pe elastic-lab (Flask sau FastAPI, un singur fisier + template), accesibila din browser pe reteaua de laborator, protejata cu parola din mediu.
- Lista
[... promptul original se opreste aici ...]

## Fazele urmatoare (din lista de sarcini, in ordine)

3. **Interfata de etichetare.** Omul marcheaza verdictele (TP/FP/FN/TN) cu ground_truth si label_source=human. Deblocheaza RAG, drift, absolvirea pe clase si metricile. Web minimal local pe elastic-lab (Flask/FastAPI, un fisier + template), parola din mediu.
4. **Siguranta la caderea modelului si modul degradat.** Model/tunel cazut -> tot ce e in curs escaladeaza, nimic nu se inchide. Restanta peste prag -> coada prioritizata (severitate, criticitate); alertele grave escaladeaza direct fara model. Plafon de timp per caz.
5. **Trasarea uneltelor si evidence_refs.** Per caz si per apel de unealta: argumentele, ID-urile documentelor returnate (nu textul), durata si tokenii. Populeaza evidence_refs in Verdict. Raspunde la "de ce a gresit agentul la cazul X".
6. **Legarea Tier 1 -> Tier 2.** Modelul Case, case_adapter (alerta/finding -> Case, fara verdictul Tier 1), seed pornit din entity_id, apel real la Tier 2 din orchestrator, harness pe lantul complet.
7. **Investigatorul B pe RedSage, cu rata de acord.** B pe alt model decat A, pentru erori mai putin corelate. Masurat: rata de acord A/B cu un model vs doua.
8. **Dashboard de metrici din audit.** Rata de escaladare, latenta, tokeni, acord A/B, precizie/recall pe etichete umane per nivel, plus drift global. Calculat din soc-audit si soc-traces, in afara grafului.
9. **Tier 1 extins si studiul de ablatie.** enrich cu threat intel si alerte corelate, RAG pe cazuri etichetate de om, 3 unelte read-only; configuratiile A-D masurate cu harness, inclusiv rezistenta la injectie. Miezul lucrarii de licenta.
10. **Alertele native Elastic Defend tratate corect.** Normalizarea campurilor alertelor native (ML malware, comportament, memorie) inainte de Tier 1, ca sa nu mai fie clasate gresit ca benigne. Verificat ca protectiile din politica Defend sunt in modul detect. Dupa legarea Tier 1 -> Tier 2.
11. **Tier 3: incidente, reguli, vanatoare.** In ordine: gruparea in incidente (test cu attack_run.sh), propuneri de reguli EQL cu shadow si promovare, vanatoare pe ipoteze ATT&CK dupa senzorii noi.
12. **Senzori pentru 0-day.** In ordine: honeytokens (atingere = escaladare mereu, criteriu nou in should_escalate); sweep extins (new_destination_asn, new_webroot_write, new_listening_port, response_size_outlier, cai URL noi) plus reguli New Terms; auditd + FIM; Suricata (beaconing, DNS, JA4); YARA pe webroot; anomalii ML simple in Python (beaconing, entropie DNS) ca findings. Atentie: joburile ML Elastic cer licenta platita, trial-ul expira la mijlocul lui octombrie.

# Pasul 1c — soc-metrics ca sursa unica de metrici (formalizare)

Scop (D2): indexul soc-metrics + cheia ES_METRICS_WRITER_API_KEY exista de la pasul 1,
iar pasii 1-6 scriu direct in soc-metrics. Constatare la verificare (2026-10-29):
**soc-metrics exista deja si e folosit activ de orchestrator** (nu e index nou). Deci
1c = confirmare + conventie de schema, NU creare. Nu se atinge nimic pe hosturi care sa
strice orchestratorul (nu reindexam un index viu).

## A. Fisiere
Niciun fisier nou de infrastructura. O singura schimbare de cod, in cadrul formalizarii:
- nday_watch.py (diff): write_metrics scrie `@timestamp` in loc de `ts` — campul standard
  Kibana, acelasi pe care il scrie orchestratorul, ca metricile nday sa apara pe aceeasi
  axa de timp in dashboard-ul de la pasul 7. Redesployat pe es-node-1 (scp).

## B. Comenzi
Nimic de rulat pe host pentru 1c (indexul si cheia exista). Cheile relevante sunt deja in
/home/tiberiu/lab/soc.env: ES_METRICS_WRITER_API_KEY (scrie soc-metrics) si ES_READER_API_KEY
(citeste). Daca soc-metrics ar trebui vreodata recreat (ex. sub ILM la pasul 11), mapping-ul
canonic de referinta (dynamic:true + campuri comune tipizate explicit, conform task 7.1):
```
PUT soc-metrics
{"mappings":{"dynamic":true,"properties":{
  "@timestamp":{"type":"date"}, "type":{"type":"keyword"}, "host":{"type":"keyword"},
  "tier":{"type":"keyword"}, "cycle_id":{"type":"keyword"}, "model_tag":{"type":"keyword"},
  "rule_name":{"type":"keyword"}, "duration_s":{"type":"float"}
}}}
```
(Indexul curent are type/host/tier ca text CU subcamp .keyword — agregarile merg pe
`type.keyword` etc. Nu se schimba in loc text->keyword; recrearea foloseste mapping-ul de
mai sus doar la o reconstructie.)

## C. Verificare (rulat 2026-10-29, read-only)
```
# indexul exista si e scris
curl -H "Authorization: ApiKey $ES_READER_API_KEY" "$ES_URL/soc-metrics/_count"        # 672
# metrici nday prezente, agregabile pe type.keyword
curl -H "Authorization: ApiKey $ES_READER_API_KEY" "$ES_URL/soc-metrics/_search?size=0" \
  -d '{"aggs":{"t":{"terms":{"field":"type.keyword"}}}}'                                 # nday:6
# cheile scrie/citeste autentifica
curl -H "Authorization: ApiKey $ES_METRICS_WRITER_API_KEY" "$ES_URL/_security/_authenticate"  # 200
```
Rezultat: soc-metrics 672 docs, type.keyword agregabil, cheile OK, ES_READER citeste.

## D. Metrica
soc-metrics e sinkul. Conventii canonice (obligatorii pentru cod nou — nday, si pasii
urmatori): fiecare doc are `type` (keyword, filtrat/agregat prin `type.keyword`) si
`@timestamp`. Tipuri folosite/planificate (task 7.1): cycle, nday, static, detection,
fp_rate, coverage, injection_test, regression, readiness, llm_probe, integrity.
Acceptare: index + cheie exista, agregabil pe type.keyword, nday scrie type=nday +
@timestamp. INDEPLINIT.

## E. Rollback
Nimic de derulat (nu s-a creat index/cheie la 1c). Reversul schimbarii de cod:
`@timestamp` -> `ts` in nday_watch.write_metrics (nerecomandat; ar scoate nday de pe axa
de timp a dashboard-ului).

## Goluri cunoscute (de rezolvat la pasul 7 — observabilitate)
- **Docurile orchestratorului (666 din 672) NU au campul `type`.** Dashboard-ul (pasul 7)
  nu le poate separa pe tip. Fix la pasul 7: orchestrator.write_cycle_metrics adauga
  `type:"cycle"` (diff aratat inainte, R12). Pana atunci raman metrici utile dar netipizate.
- Orchestratorul foloseste deja `@timestamp` (bine); nday a fost aliniat la `@timestamp`
  in 1c. Codul nou pastreaza aceasta conventie.

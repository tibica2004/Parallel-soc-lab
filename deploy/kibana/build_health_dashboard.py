#!/usr/bin/env python3
"""
Dashboard-ul "SOC Health" (pasul 7.3): sanatatea operationala a SOC-ului, din documentele
soc-metrics type=cycle (orchestrator), type=llm_probe (sonda LLM), type=fp_rate (pasul 4) si
din soc-incidents type=integrity_alert. Kibana doar afiseaza; totul e calculat de cod.

Refoloseste ajutoarele Lens din build_dashboard.py; ID-uri fixe cu prefixul
soc-metrici-health-, deci importul repetat (overwrite) le inlocuieste.

    python3 deploy/kibana/build_health_dashboard.py   # scrie deploy/kibana/soc-health.ndjson
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_dashboard as B  # noqa: E402

OUT = Path(__file__).with_name("soc-health.ndjson")
DV_INCIDENTS = B.PREFIX + "dv-incidents"
CYCLE = 'type.keyword : "cycle"'
PROBE = 'type.keyword : "llm_probe"'


def total(field: str, label: str) -> dict:
    col = B.average(field, label)
    col["operationType"] = "sum"
    return col


def terms_by(field: str, label: str, order_col: str, size: int = 10) -> dict:
    col = B.terms(field, label, size)
    col["params"]["orderBy"] = {"type": "column", "columnId": order_col}
    col["params"]["orderDirection"] = "desc"
    return col


def tile(id_: str, title: str, dv: str, col: dict, query: str) -> dict:
    return B._lens(id_, title, dv, "lnsMetric", {"m": col},
                   {"layerId": "layer1", "layerType": "data", "metricAccessor": "m"}, query)


def top_bars(id_: str, title: str, field: str, label: str, metric: dict, query: str) -> dict:
    cols = {"x": terms_by(field, label, "y"), "y": metric}
    return B._lens(id_, title, B.DV_METRICS, "lnsXY", cols,
                   {"legend": {"isVisible": False, "position": "right"},
                    "preferredSeriesType": "bar_horizontal",
                    "layers": [{"layerId": "layer1", "layerType": "data",
                                "seriesType": "bar_horizontal", "xAccessor": "x",
                                "accessors": ["y"]}]}, query)


def build() -> list[dict]:
    objs = [B._so("index-pattern", dv, {"title": idx, "name": idx, "timeFieldName": "@timestamp"}, [])
            for dv, idx in {B.DV_METRICS: "soc-metrics", DV_INCIDENTS: "soc-incidents"}.items()]
    M = B.DV_METRICS
    vis = [
        # randul 1: cifre (intervalul ales)
        tile("health-m-honey", "Atingeri de momeli (honeytoken)", M,
             total("honeytoken_hits", "Atingeri"), CYCLE),
        tile("health-m-integritate", "Alerte de integritate", DV_INCIDENTS, B.count("Alerte"),
             'type.keyword : "integrity_alert"'),
        tile("health-m-durata", "Durata medie a ciclului (s)", M,
             B.average("duration_s", "Secunde"), CYCLE),
        tile("health-m-sonda", "Sonde LLM esuate", M, B.count("Esecuri"), PROBE + " and ok : false"),
        tile("health-m-escaladare", "Rata de escaladare (medie pe cicluri)", M,
             B.average("escalation_rate", "Rata", percent=True), CYCLE),
        tile("health-m-fara-model", "Alerte fara verdict de model", M,
             total("no_model", "Alerte"), CYCLE),
        # randul 2: in timp
        B.line("health-l-durata", "Durata ciclului (s)", M, B.average("duration_s", "Durata"),
               query=CYCLE),
        B.line("health-l-coada", "Coada: alerte aduse / procesate per ciclu", M,
               [B.average("queue_depth", "Aduse"), B.average("alerts_processed", "Procesate")],
               query=CYCLE),
        B.line("health-l-inchise", "Inchise in Tier 1 vs escaladate", M,
               [total("closed_t1", "Inchise Tier 1"), total("escalated", "Escaladate"),
                total("escalated_t2", "Investigate Tier 2")], query=CYCLE),
        B.line("health-l-esecuri", "Esecuri: timeout, eroare de model, fara model", M,
               [total("model_timeouts", "Timeout"), total("model_errors", "Eroare model"),
                total("no_model", "Fara model")], query=CYCLE),
        B.line("health-l-tokeni", "Tokeni si apeluri de model per ciclu", M,
               [B.average("tokens", "Tokeni"), B.average("llm_calls", "Apeluri")], query=CYCLE),
        B.line("health-l-sonda", "Sonda LLM: latenta (ms)", M,
               [B.average("latency_ms", "/api/tags"), B.average("gen_latency_ms", "Generare 5 tokeni")],
               query=PROBE),
        # randul 3: fals pozitive (pasul 4)
        top_bars("health-b-fp", "Rata FP per regula (top 10, trafic benign)", "rule_name.keyword",
                 "Regula", B.average("fp_rate", "Rata FP", percent=True), 'type.keyword : "fp_rate"'),
    ]
    objs += vis
    layout = {"m": (8, 6), "l": (24, 12), "b": (48, 12)}
    panels, refs = [], []
    x = y = row_h = 0
    for i, v in enumerate(vis):
        short = v["id"][len(B.PREFIX):]
        w, h = layout[short.split("-")[1]]
        if x + w > 48:
            x, y, row_h = 0, y + row_h, 0
        panels.append({"type": "lens", "panelIndex": short, "panelRefName": f"panel_{i}",
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": short},
                       "embeddableConfig": {"enhancements": {}}})
        refs.append({"type": "lens", "id": v["id"], "name": f"panel_{i}"})
        x += w
        row_h = max(row_h, h)
    dash = B._so("dashboard", B.PREFIX + "health-dashboard", {
        "title": "SOC Health",
        "description": "Sanatatea operationala: cicluri ale orchestratorului, sonda LLM, momeli, "
                       "integritate, rata FP pe traficul benign. Calculat de cod, afisat de Kibana.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True,
                                   "syncTooltips": False, "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
        "refreshInterval": {"pause": False, "value": 60000}, "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": B._kql(""), "filter": []})},
    }, refs)
    return objs + [dash]


DV_CASES = B.PREFIX + "dv-cases"


def build_status() -> list[dict]:
    """plann.md A4: O singura vedere pentru demo/examen: readiness, cazuri deschise, portile."""
    M = B.DV_METRICS
    objs = [B._so("index-pattern", M, {"title": "soc-metrics", "name": "soc-metrics",
                                       "timeFieldName": "@timestamp"}, []),
            B._so("index-pattern", DV_CASES, {"title": "soc-cases", "name": "soc-cases",
                                              "timeFieldName": "updated_at"}, [])]
    vis = [
        tile("status-m-ready", "Readiness (ultima evaluare, 1 = gata)", M,
             B.last_value("ready", "Gata", 'type.keyword : "readiness"'), 'type.keyword : "readiness"'),
        tile("status-m-criterii", "Criterii readiness trecute (din 9)", M,
             B.last_value("criteria_passed", "Criterii", 'type.keyword : "readiness"'), 'type.keyword : "readiness"'),
        tile("status-m-cazuri", "Cazuri la om (escaladate, neinchise)", DV_CASES, B.count("Cazuri"),
             'state : "escalated"'),
        tile("status-m-recall", "Recall la ultima poarta", M,
             B.last_value("recall", "Recall", 'type.keyword : "gate"', percent=True), 'type.keyword : "gate"'),
        tile("status-m-fprate", "Rata FP la ultima poarta", M,
             B.last_value("fp_rate", "FP", 'type.keyword : "gate"', percent=True), 'type.keyword : "gate"'),
        tile("status-m-propuneri", "Propuneri de lista alba (de aprobat)", M, B.count("Propuneri"),
             'type.keyword : "whitelist_proposal"'),
        B.line("status-l-porti", "Portile in timp: recall si rata FP", M,
               [B.average("recall", "Recall", percent=True), B.average("fp_rate", "Rata FP", percent=True)],
               B.terms("scenario_set.keyword", "Set", 6), query='type.keyword : "gate"'),
        B.line("status-l-cazuri", "Cazuri pe stare", DV_CASES, B.count("Cazuri"),
               B.terms("state", "Stare", 4)),
    ]
    objs += vis
    layout = {"m": (8, 6), "l": (24, 12)}
    panels, refs = [], []
    x = y = row_h = 0
    for i, v in enumerate(vis):
        short = v["id"][len(B.PREFIX):]
        w, h = layout[short.split("-")[1]]
        if x + w > 48:
            x, y, row_h = 0, y + row_h, 0
        panels.append({"type": "lens", "panelIndex": short, "panelRefName": f"panel_{i}",
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": short},
                       "embeddableConfig": {"enhancements": {}}})
        refs.append({"type": "lens", "id": v["id"], "name": f"panel_{i}"})
        x += w
        row_h = max(row_h, h)
    dash = B._so("dashboard", B.PREFIX + "status-dashboard", {
        "title": "SOC Status",
        "description": "Vederea unica: readiness, cazurile la om, portile de regresie, propunerile "
                       "de lista alba. Calculat de cod, afisat de Kibana.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True,
                                   "syncTooltips": False, "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": "now-7d", "timeTo": "now",
        "refreshInterval": {"pause": False, "value": 60000}, "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": B._kql(""), "filter": []})},
    }, refs)
    return objs + [dash]


OUT_STATUS = Path(__file__).with_name("soc-status.ndjson")


def main() -> int:
    objs = build()
    OUT.write_text("\n".join(json.dumps(o, ensure_ascii=False) for o in objs) + "\n", encoding="utf-8")
    print(f"{OUT} ({len(objs)} obiecte)")
    st = build_status()
    OUT_STATUS.write_text("\n".join(json.dumps(o, ensure_ascii=False) for o in st) + "\n", encoding="utf-8")
    print(f"{OUT_STATUS} ({len(st)} obiecte)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

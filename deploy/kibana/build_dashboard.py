#!/usr/bin/env python3
"""
Genereaza dashboard-ul de metrici pentru Kibana (saved objects, NDJSON).

Kibana doar AFISEAZA: toate rapoartele (precizie, recall, rata de escaladare,
acord A/B, drift) sunt calculate de metrics.py si scrise in soc-metrics. Aici
folosim doar operatii simple Lens (ultima valoare, medie, numarare, termeni),
fara formule — mai robuste la import si la upgrade de Kibana.

Obiectele au ID-uri fixe cu prefixul soc-metrici-, deci un import repetat cu
overwrite=true le inlocuieste, iar stergerea lor e simpla.

    python3 deploy/kibana/build_dashboard.py      # scrie deploy/kibana/soc-metrici.ndjson
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).with_name("soc-metrici.ndjson")
PREFIX = "soc-metrici-"
DV_METRICS = PREFIX + "dv-metrics"
DV_AUDIT = PREFIX + "dv-audit"
DATA_VIEWS = {DV_METRICS: "soc-metrics", DV_AUDIT: "soc-audit"}

# Versiuni de migrare: cele mai vechi la care formatul de mai jos e valid. Kibana
# migreaza in sus la import; o versiune prea noua ar fi respinsa.
CORE_V = "8.8.0"
TYPE_V = {"index-pattern": "8.0.0", "lens": "8.9.0", "dashboard": "8.7.0"}


def _so(type_: str, id_: str, attributes: dict, references: list[dict]) -> dict:
    return {"type": type_, "id": id_, "attributes": attributes, "references": references,
            "coreMigrationVersion": CORE_V, "typeMigrationVersion": TYPE_V[type_]}


def _kql(q: str) -> dict:
    return {"query": q, "language": "kuery"}


# ---------------- coloane Lens ----------------

def last_value(field: str, label: str, kql: str | None = None, percent: bool = False) -> dict:
    col = {"label": label, "customLabel": True, "dataType": "number", "operationType": "last_value",
           "isBucketed": False, "scale": "ratio", "sourceField": field,
           "params": {"sortField": "@timestamp", "showArrayValues": False}}
    if percent:
        col["params"]["format"] = {"id": "percent", "params": {"decimals": 1}}
    if kql:
        col["filter"] = _kql(kql)
    return col


def average(field: str, label: str, percent: bool = False) -> dict:
    col = {"label": label, "customLabel": True, "dataType": "number", "operationType": "average",
           "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {"emptyAsNull": True}}
    if percent:
        col["params"]["format"] = {"id": "percent", "params": {"decimals": 1}}
    return col


def count(label: str = "Numar") -> dict:
    return {"label": label, "customLabel": True, "dataType": "number", "operationType": "count",
            "isBucketed": False, "scale": "ratio", "sourceField": "___records___",
            "params": {"emptyAsNull": True}}


def date_hist() -> dict:
    return {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
            "sourceField": "@timestamp", "isBucketed": True, "scale": "interval",
            "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False}}


def terms(field: str, label: str, size: int = 10) -> dict:
    return {"label": label, "customLabel": True, "dataType": "string", "operationType": "terms",
            "sourceField": field, "isBucketed": True, "scale": "ordinal",
            "params": {"size": size, "orderBy": {"type": "alphabetical", "fallback": False},
                       "orderDirection": "asc", "otherBucket": False, "missingBucket": False,
                       "parentFormat": {"id": "terms"}}}


# ---------------- vizualizari ----------------

def _lens(id_: str, title: str, dv: str, vis_type: str, columns: dict, visualization: dict,
          query: str = "") -> dict:
    layer = {"columns": columns, "columnOrder": list(columns), "incompleteColumns": {}}
    state = {"datasourceStates": {"formBased": {"layers": {"layer1": layer}}},
             "visualization": visualization, "query": _kql(query), "filters": [],
             "internalReferences": [], "adHocDataViews": {}}
    return _so("lens", PREFIX + id_, {"title": title, "description": "", "visualizationType": vis_type,
                                      "state": state},
               [{"type": "index-pattern", "id": dv, "name": "indexpattern-datasource-layer-layer1"}])


def metric(id_: str, title: str, field: str, tier: str, percent: bool = True) -> dict:
    return _lens(id_, title, DV_METRICS, "lnsMetric",
                 {"m": last_value(field, title, f'tier.keyword : "{tier}"', percent)},
                 {"layerId": "layer1", "layerType": "data", "metricAccessor": "m"})


def line(id_: str, title: str, dv: str, y: dict | list[dict], split: dict | None = None,
         query: str = "") -> dict:
    ys = y if isinstance(y, list) else [y]
    cols = {"x": date_hist(), **{f"y{i}": c for i, c in enumerate(ys)}}
    layer = {"layerId": "layer1", "layerType": "data", "seriesType": "line",
             "xAccessor": "x", "accessors": [f"y{i}" for i in range(len(ys))]}
    if split:
        cols["s"] = split
        layer["splitAccessor"] = "s"
    return _lens(id_, title, dv, "lnsXY", cols,
                 {"legend": {"isVisible": True, "position": "right"}, "preferredSeriesType": "line",
                  "layers": [layer]}, query)


def bars(id_: str, title: str, dv: str, field: str, label: str, query: str = "") -> dict:
    cols = {"x": terms(field, label), "y": count()}
    return _lens(id_, title, dv, "lnsXY", cols,
                 {"legend": {"isVisible": False, "position": "right"}, "preferredSeriesType": "bar_horizontal",
                  "layers": [{"layerId": "layer1", "layerType": "data", "seriesType": "bar_horizontal",
                              "xAccessor": "x", "accessors": ["y"]}]}, query)


def build() -> list[dict]:
    objs = [_so("index-pattern", dv, {"title": idx, "name": idx, "timeFieldName": "@timestamp"}, [])
            for dv, idx in DATA_VIEWS.items()]
    tier_split = terms("tier.keyword", "Nivel", 3)
    vis = [
        # randul 1: cifrele cheie (ultimul instantaneu din intervalul ales)
        metric("m-escaladare", "Rata de escaladare Tier 1", "escalation_rate", "fast"),
        metric("m-precizie", "Precizie (etichete umane)", "precision", "all"),
        metric("m-recall", "Recall (etichete umane)", "recall", "all"),
        metric("m-ratate", "Rata de atacuri ratate", "missed_attack_rate", "all"),
        metric("m-acord", "Acord A/B (calea lenta)", "ab_agreement_rate", "hunt"),
        metric("m-p95", "Latenta p95 per caz (ms)", "latency_ms_p95", "all", percent=False),
        # randul 2: evolutie in timp (drift)
        line("l-escaladare", "Rata de escaladare in timp", DV_METRICS,
             average("escalation_rate", "Rata de escaladare", percent=True), query='tier.keyword : "fast"'),
        line("l-drift", "Drift: distributia clasificarilor fata de fereastra anterioara", DV_METRICS,
             average("drift_classes_tvd", "Distanta (0 = identic)", percent=True), tier_split,
             query='not tier.keyword : "all"'),
        line("l-latenta", "Latenta p95 per caz (ms)", DV_METRICS,
             average("latency_ms_p95", "p95 (ms)"), tier_split, query='not tier.keyword : "all"'),
        line("l-tokeni", "Tokeni per caz", DV_METRICS,
             average("tokens_per_case", "Tokeni"), tier_split, query='not tier.keyword : "all"'),
        line("l-precizie", "Precizie si recall in timp", DV_METRICS,
             [average("precision", "Precizie", percent=True), average("recall", "Recall", percent=True)],
             query='tier.keyword : "all"'),
        # randul 3: din audit, direct (volume)
        bars("b-motive", "Motive de escaladare", DV_AUDIT, "escalation_reasons.keyword", "Motiv",
             query="escalate : true"),
        bars("b-esecuri", "Cazuri fara verdict de model", DV_AUDIT, "failure.keyword", "Tip de esec"),
        bars("b-clasificari", "Clasificari", DV_AUDIT, "verdict.classification.keyword", "Clasificare"),
    ]
    objs += vis

    panels, refs = [], []
    layout = {"m-": (8, 6), "l-": (24, 12), "b-": (16, 12)}
    x = y = 0
    row_h = 0
    for i, v in enumerate(vis):
        short = v["id"][len(PREFIX):]
        w, h = layout[short[:2]]
        if x + w > 48:
            x, y = 0, y + row_h
            row_h = 0
        panels.append({"type": "lens", "panelIndex": short, "panelRefName": f"panel_{i}",
                       "gridData": {"x": x, "y": y, "w": w, "h": h, "i": short},
                       "embeddableConfig": {"enhancements": {}}})
        refs.append({"type": "lens", "id": v["id"], "name": f"panel_{i}"})
        x += w
        row_h = max(row_h, h)
    dash = _so("dashboard", PREFIX + "dashboard", {
        "title": "SOC agentic — metrici",
        "description": "Calculate de metrics.py din soc-audit, soc-traces si etichetele umane "
                       "din verdicts-history. Precizia si recall-ul folosesc DOAR etichete umane.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "syncCursor": True,
                                   "syncTooltips": False, "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": "now-7d", "timeTo": "now", "refreshInterval": {"pause": True, "value": 0},
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": _kql(""), "filter": []})},
    }, refs)
    return objs + [dash]


def main() -> int:
    objs = build()
    OUT.write_text("\n".join(json.dumps(o, ensure_ascii=False) for o in objs) + "\n", encoding="utf-8")
    print(f"{OUT} ({len(objs)} obiecte)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

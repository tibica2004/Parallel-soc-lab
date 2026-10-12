"""Fisierul de import Kibana: JSON valid, referinte rezolvate, fara formule, si
fiecare camp folosit exista in documentele pe care le produce codul."""
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import metrics

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_dashboard", ROOT / "deploy/kibana/build_dashboard.py")
bd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bd)

OBJS = bd.build()
AUDIT_FIELDS = {"@timestamp", "escalate", "escalation_reasons.keyword", "failure.keyword",
                "verdict.classification.keyword"}


def _lens():
    return [o for o in OBJS if o["type"] == "lens"]


def test_fisierul_comis_e_la_zi():
    on_disk = [json.loads(l) for l in bd.OUT.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert on_disk == json.loads(json.dumps(OBJS)), "ruleaza: python3 deploy/kibana/build_dashboard.py"


def test_id_uri_unice_si_cu_prefix():
    ids = [o["id"] for o in OBJS]
    assert len(ids) == len(set(ids)) and all(i.startswith("soc-metrici-") for i in ids)


def test_referintele_se_rezolva():
    ids = {o["id"] for o in OBJS}
    for o in OBJS:
        for r in o["references"]:
            assert r["id"] in ids, (o["id"], r)
    dash = next(o for o in OBJS if o["type"] == "dashboard")
    panels = json.loads(dash["attributes"]["panelsJSON"])
    names = {r["name"] for r in dash["references"]}
    assert len(panels) == len(_lens()) and all(p["panelRefName"] in names for p in panels)
    assert all(p["gridData"]["x"] + p["gridData"]["w"] <= 48 for p in panels)


def test_fara_formule():
    for o in _lens():
        cols = o["attributes"]["state"]["datasourceStates"]["formBased"]["layers"]["layer1"]["columns"]
        assert all(c["operationType"] in {"last_value", "average", "count", "date_histogram", "terms"}
                   for c in cols.values())


def test_campurile_exista_in_datele_produse():
    produced = set(metrics.compute([], [], [], datetime.now(timezone.utc), 1)[0]) | {"tier.keyword"}
    for o in _lens():
        dv = o["references"][0]["id"]
        cols = o["attributes"]["state"]["datasourceStates"]["formBased"]["layers"]["layer1"]["columns"]
        for c in cols.values():
            f = c.get("sourceField")
            if f in (None, "___records___"):
                continue
            allowed = produced if dv == bd.DV_METRICS else AUDIT_FIELDS
            assert f in allowed, (o["id"], f)
        for c in cols.values():
            if c.get("params", {}).get("sortField"):
                assert c["params"]["sortField"] == "@timestamp"

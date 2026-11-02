"""Pasul 7.3: "SOC Health" — import valid, referinte rezolvate, campurile exista in documentele
produse de cod (type=cycle, llm_probe, fp_rate)."""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import cycle_metrics

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_health_dashboard",
                                              ROOT / "deploy/kibana/build_health_dashboard.py")
hd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hd)
OBJS = hd.build()


def _fields() -> set[str]:
    t = datetime(2026, 11, 2, tzinfo=timezone.utc)
    cyc = cycle_metrics.build_cycle_doc(cycle=1, cycle_id="c", started=t, ended=t + timedelta(seconds=1),
                                        alerts_fetched=0, stats={}, llm={}, backlog=False,
                                        sweep_ran=False, interval_s=120)
    probe = {"latency_ms", "gen_latency_ms", "ok"}
    fp = {"rule_name.keyword", "fp_rate"}
    return set(cyc) | probe | fp | {"@timestamp", "___records___"}


def test_fisierul_comis_e_la_zi():
    on_disk = [json.loads(l) for l in hd.OUT.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert on_disk == json.loads(json.dumps(OBJS)), "ruleaza: python3 deploy/kibana/build_health_dashboard.py"


def test_id_uri_unice_si_referinte():
    ids = [o["id"] for o in OBJS]
    assert len(ids) == len(set(ids)) and all(i.startswith("soc-metrici-") for i in ids)
    for o in OBJS:
        for r in o["references"]:
            assert r["id"] in ids, (o["id"], r)
    dash = next(o for o in OBJS if o["type"] == "dashboard")
    panels = json.loads(dash["attributes"]["panelsJSON"])
    assert all(p["gridData"]["x"] + p["gridData"]["w"] <= 48 for p in panels)


def test_campurile_exista_in_documente():
    known = _fields()
    for o in OBJS:
        if o["type"] != "lens":
            continue
        for col in o["attributes"]["state"]["datasourceStates"]["formBased"]["layers"]["layer1"]["columns"].values():
            assert col["sourceField"] in known, (o["id"], col["sourceField"])


def test_fara_formule():
    assert "formula" not in json.dumps(OBJS)


# --- plann.md A4: "SOC Status" ---------------------------------------------------------

def test_status_dashboard_la_zi_si_consistent():
    st = hd.build_status()
    on_disk = [json.loads(l) for l in hd.OUT_STATUS.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert on_disk == json.loads(json.dumps(st)), "ruleaza: python3 deploy/kibana/build_health_dashboard.py"
    ids = {o["id"] for o in st}
    for o in st:
        for r in o["references"]:
            assert r["id"] in ids
    known = {"ready", "criteria_passed", "recall", "fp_rate", "scenario_set.keyword", "state",
             "@timestamp", "___records___"}
    for o in st:
        if o["type"] == "lens":
            for col in o["attributes"]["state"]["datasourceStates"]["formBased"]["layers"]["layer1"]["columns"].values():
                assert col["sourceField"] in known, (o["id"], col["sourceField"])

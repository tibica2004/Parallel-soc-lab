"""Vanatoarea de expunere WordPress (faza 18, bucata 2): driverul Tier 3 in dry-run,
cu inventarul si atingerile Apache injectate (fara Elasticsearch, fara model)."""
import tier3


class _FakeES:
    def __init__(self, doc):
        self._doc = doc

    def get(self, index, id):
        if self._doc is None:
            raise RuntimeError("not found")
        return {"_source": self._doc}


def _patch(monkeypatch, doc, touches):
    import elastic_tools
    monkeypatch.setattr(elastic_tools, "ES", _FakeES(doc))
    monkeypatch.setattr(elastic_tools, "_esql", lambda q, params=None: list(touches))


DOC = {"host": "web-prod", "components": [
    {"component": "core", "version": "7.1.3"},        # < 7.1.4 (exemplu de laborator) -> vulnerabil
    {"component": "akismet", "version": "5.0"}]}       # 4.0 <= 5.0 < 5.3.1 -> vulnerabil


def test_dry_run_coreleaza_fara_sa_scrie(monkeypatch, tmp_path):
    touches = [
        {"source_ip": "203.0.113.9", "url_path": "/wp-content/plugins/akismet/x.php", "count": 4, "status": 404},
        {"source_ip": "203.0.113.9", "url_path": "/xmlrpc.php", "count": 3, "status": 200},
    ]
    _patch(monkeypatch, DOC, touches)
    rec = tier3.run_exposure(24, write=False, state_path=tmp_path / "s.json")
    assert rec["status"] == "found"
    comps = {v["component"] for v in rec["vulnerable"]}
    assert comps == {"core", "akismet"}
    # corelatii: akismet (lovit pe slug) + core (orice atingere pe host); toate dry_run
    outs = {(m["component"], m["source_ip"]): m["outcome"] for m in rec["matches"]}
    assert outs[("akismet", "203.0.113.9")] == "dry_run"
    assert outs[("core", "203.0.113.9")] == "dry_run"
    assert rec["cases"] == 0
    assert not (tmp_path / "s.json").exists()        # dry-run nu salveaza starea


def test_fara_vulnerabilitati_nu_coreleaza(monkeypatch, tmp_path):
    doc = {"host": "web-prod", "components": [{"component": "core", "version": "9.9.9"}]}  # peste fixed
    _patch(monkeypatch, doc, [{"source_ip": "203.0.113.9", "url_path": "/xmlrpc.php", "count": 9}])
    rec = tier3.run_exposure(24, write=False, state_path=tmp_path / "s.json")
    assert rec["status"] == "not_found" and rec["correlations"] == 0 and rec["vulnerable"] == []


def test_inventar_lipsa_escaladeaza_prin_status(monkeypatch, tmp_path):
    _patch(monkeypatch, None, [])
    rec = tier3.run_exposure(24, write=False, state_path=tmp_path / "s.json")
    assert rec["status"] == "error" and rec["error"].startswith("inventar:")


def test_scrie_trimite_la_tier2_pana_la_buget(monkeypatch, tmp_path):
    calls = []

    class _Runner:
        def run(self, *a, **k):
            calls.append((a, k))

    monkeypatch.setattr(tier3.HU, "TIER2_BUDGET", 1)
    _patch(monkeypatch, DOC, [
        {"source_ip": "203.0.113.9", "url_path": "/wp-content/plugins/akismet/x.php", "count": 4}])
    # fara WRITER real: scrierea in soc-hunts e prinsa si nu opreste
    import orchestrator
    monkeypatch.setattr(orchestrator, "WRITER", None)
    rec = tier3.run_exposure(24, write=True, state_path=tmp_path / "s.json", tier2_budget=1, runner=_Runner())
    sent = [m for m in rec["matches"] if m["outcome"] == "tier2"]
    rest = [m for m in rec["matches"] if m["outcome"] == "la_om"]
    assert len(sent) == 1 and len(calls) == 1           # un singur caz in limita bugetului
    assert len(rest) >= 1                                # restul raman pentru om
    assert (tmp_path / "s.json").exists()               # starea (seen) salvata la scriere

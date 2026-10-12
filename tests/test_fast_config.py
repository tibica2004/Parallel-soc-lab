"""fast_path: configuratiile base/A-D. base = productia de azi, neschimbata."""
import pytest

import fast_path as fp


def _nodes(cfg):
    return [n for n in fp.build_fast_path(cfg).get_graph().nodes if not n.startswith("__")]


@pytest.mark.parametrize("cfg,nodes", [
    ("base", ["prefetch", "pattern", "verdict", "finalize"]),
    ("A", ["prefetch", "pattern", "verdict", "finalize"]),
    ("B", ["prefetch", "rag", "pattern", "verdict", "finalize"]),
    ("C", ["prefetch", "l1_agent", "pattern", "verdict", "finalize"]),
    ("D", ["prefetch", "rag", "l1_agent", "pattern", "verdict", "finalize"]),
])
def test_noduri_per_configuratie(cfg, nodes):
    assert _nodes(cfg) == nodes


def test_implicit_base(monkeypatch):
    monkeypatch.delenv("FAST_CONFIG", raising=False)
    assert fp.config_from_env() == fp.CONFIGS["base"]
    monkeypatch.setenv("FAST_CONFIG", "Z")
    with pytest.raises(ValueError):
        fp.config_from_env()


def test_prompturile_base_neschimbate():
    assert fp._prompt(fp.PATTERN_PROMPT, fp.CONFIGS["base"]) is fp.PATTERN_PROMPT
    ext = fp._prompt(fp.VERDICT_PROMPT, fp.CONFIGS["C"])
    assert ext.endswith(fp.NO_THINK) and "NEINCREZATOARE" in ext and "romana" in ext


def test_fara_istoric():
    c = fp.CONFIGS["D"].without_history()
    assert (c.name, c.rag, c.tools, c.history) == ("D", True, True, False)


def _state(cls, l1_status, **ctx):
    return {"raw_verdict": {"classification": cls, "confidence": 90, "proposed_action": "none"},
            "context": {"host": "h", **ctx}, "l1": {"status": l1_status}}


@pytest.mark.parametrize("status", ["failed", "timeout"])
def test_agent_l1_cazut_nu_inchide(status):
    out = fp.node_finalize(_state("benign", status))
    assert out["verdict"].classification.value == "undetermined"
    assert out["verdict"].proposed_action.value == "escalate_human"


def test_agent_l1_ok_lasa_benignul():
    out = fp.node_finalize(_state("benign", "ok"))
    assert out["verdict"].classification.value == "benign"


def test_guide_ramane_ultimul():
    ctx = fp._guide_last({"investigation_guide": "g", "a": 1, "enrichment": {}})
    assert list(ctx)[-1] == "investigation_guide"


def test_fereastra_de_corelare():
    c = fp.CONFIGS["C"].with_correlation_window(5).without_history()
    assert (c.correlation_window_min, c.history, c.tools) == (5, False, True)
    assert fp.CONFIGS["C"].correlation_window_min == 30          # productia neatinsa
    for bad in (0, 121):
        with pytest.raises(ValueError):
            fp.CONFIGS["A"].with_correlation_window(bad)


def test_fereastra_ajunge_in_interogare(monkeypatch):
    import enrich
    seen = {}
    monkeypatch.setattr(fp, "build_context", lambda alert, history=True: {"execution": {}})
    monkeypatch.setattr(enrich, "enrich", lambda es, alert, w=30: seen.setdefault("w", w) and {})
    fp.make_prefetch(fp.CONFIGS["A"].with_correlation_window(5))({"alert": {}})
    assert seen["w"] == 5

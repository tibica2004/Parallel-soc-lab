"""rag.py: validarea cazurilor, doar cele revizuite, recuperare determinista,
separare stricta de scenariile de evaluare."""
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

import rag

ROOT = Path(__file__).resolve().parent.parent


def _c(**kw):
    base = {"id": "rag-100", "reviewed": True, "ground_truth": "attack", "rule": "R",
            "parent": "apache2", "process": "sh", "user_class": "web_service", "flags": [],
            "situation": "s", "lesson": "l"}
    return rag.RagCase(**{**base, **kw})


def _ctx(**kw):
    ctx = {"rule_name": "R", "execution": {"parent": "apache2", "process": "sh", "user": "www-data"},
           "ran_by_web_service_account": True, "ran_by_known_admin": False,
           "sensitive_action": False, "ran_from_temp_dir": False,
           "webroot_executable_write": False, "in_maintenance_window": False}
    ctx.update(kw)
    return ctx


@pytest.mark.parametrize("kw", [{"ground_truth": "TP"}, {"id": "x"}, {"user_class": "root"},
                                {"flags": ["altceva"]}, {"extra": 1}, {"lesson": "x" * 301}])
def test_caz_invalid(kw):
    with pytest.raises(ValidationError):
        _c(**kw)


def test_fisierul_din_repo_valideaza():
    cases = rag.parse_cases(yaml.safe_load(rag.CASES_FILE.read_text(encoding="utf-8")))
    assert len(cases) >= 5


def test_doar_cazurile_revizuite(monkeypatch, tmp_path):
    p = tmp_path / "c.yml"
    p.write_text(yaml.safe_dump({"cases": [_c(id="rag-001").model_dump(),
                                           _c(id="rag-002", reviewed=False).model_dump()]}))
    monkeypatch.setattr(rag, "CASES_FILE", p)
    rag.load_cases.cache_clear()
    try:
        assert [c.id for c in rag.load_cases()] == ["rag-001"]
    finally:
        rag.load_cases.cache_clear()


def test_id_duplicat_respins():
    with pytest.raises(ValueError):
        rag.parse_cases({"cases": [_c().model_dump(), _c().model_dump()]})


def test_recuperare_ordine_si_prag():
    cases = (_c(id="rag-001"), _c(id="rag-002", parent="bash", user_class="admin", ground_truth="benign"),
             _c(id="rag-003", rule="Alta", parent="bash", process="curl", user_class="admin",
                flags=["sensitive_action", "in_maintenance_window"]))
    got = rag.retrieve(_ctx(), cases)
    assert [g["case_id"] for g in got] == ["rag-001", "rag-002"]   # rag-003 sub prag
    assert got[0]["similarity"] == 1.0 and got[0]["same_rule"] is True


def test_clasa_utilizatorului():
    assert rag.features(_ctx())["user_class"] == "web_service"
    assert rag.features(_ctx(ran_by_web_service_account=False, ran_by_known_admin=True))["user_class"] == "admin"
    assert rag.features(_ctx(ran_by_web_service_account=False))["user_class"] == "other"


def test_istoric_doar_citire_cu_filtre():
    class ES:
        def search(self, **kw):
            self.kw = kw
            return {"hits": {"hits": [{"_source": {"ground_truth": "benign", "classification": "suspicious",
                                                   "label_outcome": "FP", "notes": "n" * 300}}]}}
    es = ES()
    got = rag.human_history(es, "R")
    assert got[0]["human_note"] == "n" * 160 and got[0]["outcome"] == "FP"
    assert {"term": {"rule_name.keyword": "R"}} in es.kw["query"]["bool"]["filter"]
    assert rag.human_history(es, "") == []


def test_separare_de_scenariile_de_evaluare():
    """Niciun caz RAG nu poarta numele unui scenariu si nu contine comanda unui scenariu."""
    raw = rag.CASES_FILE.read_text(encoding="utf-8")
    cases = rag.parse_cases(yaml.safe_load(raw))
    texts = " ".join(c.situation + " " + c.lesson for c in cases).lower()
    for f in ROOT.glob("scenarios*.yml"):
        for sc in yaml.safe_load(f.read_text(encoding="utf-8")).get("scenarios") or []:
            assert sc.get("name", "").lower() not in texts
            gen = (sc.get("generate") or "").strip()
            if gen:
                assert gen not in raw
            for cid in [c.id for c in cases]:
                assert cid not in (sc.get("name") or "")

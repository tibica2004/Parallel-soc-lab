"""labeling.py: TP/FP/FN/TN ca harness-ul, validarea etichetei, istoricul,
si regula ca nimeni altcineva nu scrie ground_truth / label_source."""
import itertools
import re
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

import harness
from labeling import LabelInput, build_label_update, outcome
from schemas import ActionType, Classification, Verdict

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("cls,act,gt", list(itertools.product(
    [c.value for c in Classification], [a.value for a in ActionType], ["attack", "benign"])))
def test_outcome_identic_cu_harness(cls, act, gt):
    v = Verdict(investigation_id="t", source_path="fast", entity_type="host", entity_id="h",
                classification=cls, confidence=50, rarity_score=0.0, model_id="m",
                proposed_action=act)
    assert outcome({"classification": cls, "proposed_action": act}, gt) == harness.score_verdict(v, gt)


@pytest.mark.parametrize("kw", [
    {"ground_truth": "TP"}, {"ground_truth": "malicious"}, {"ground_truth": ""},
    {"doc_id": "../_delete"}, {"doc_id": 'a"b'}, {"doc_id": "x" * 65},
    {"notes": "x" * 501}, {"notes": "a\x00b"}, {"label_source": "human"},
])
def test_eticheta_invalida(kw):
    base = {"doc_id": "AbC_12-x", "ground_truth": "attack", "notes": ""}
    with pytest.raises(ValidationError):
        LabelInput(**{**base, **kw})


def test_note_cu_rand_nou_permise_si_curatate():
    assert LabelInput(doc_id="a", ground_truth="benign", notes="  linia 1\nlinia 2 ").notes == "linia 1\nlinia 2"


def test_update_prima_eticheta():
    now = datetime(2026, 10, 9, tzinfo=timezone.utc)
    f = build_label_update({"classification": "benign", "proposed_action": "none"},
                           LabelInput(doc_id="a", ground_truth="attack", notes="ratat"), now)
    assert f == {"ground_truth": "attack", "label_source": "human", "label_outcome": "FN",
                 "labeled_at": now.isoformat(), "notes": "ratat", "label_history": []}


def test_reetichetarea_pastreaza_istoricul():
    old = {"classification": "suspicious", "proposed_action": "escalate_human",
           "ground_truth": "benign", "notes": "vechi"}   # eticheta veche, fara label_source
    f = build_label_update(old, LabelInput(doc_id="a", ground_truth="attack"), datetime.now(timezone.utc))
    assert f["label_outcome"] == "TP" and f["notes"] is None
    assert f["label_history"] == [{"ground_truth": "benign", "label_source": None, "label_outcome": None,
                                   "labeled_at": None, "notes": "vechi"}]


def test_doar_etichetarea_scrie_eticheta_umana():
    """Principiul 5: ground_truth si label_source nu se scriu automat nicaieri altundeva."""
    allowed = {"labeling.py", "label_ui.py"}
    bad = []
    for p in ROOT.glob("*.py"):
        if p.name in allowed:
            continue
        s = p.read_text(encoding="utf-8")
        # scrieri de label_source: atribuire sau literal in dict. Citirea (ex. metrics.py,
        # d.get("label_source") == "human") e permisa.
        for pat in (r"""\[["']label_source["']\]\s*=(?!=)""",
                    r"""["']label_source["']\s*:\s*["']"""):
            for m in re.finditer(pat, s):
                bad.append(f"{p.name}:{s[:m.start()].count(chr(10)) + 1} label_source")
        # scrieri: atribuire non-None (x["ground_truth"] = ...) sau eticheta literala
        # intr-un dict ("ground_truth": "attack"). Citirile (==, .get) sunt permise.
        for pat in (r"""\[["']ground_truth["']\]\s*=(?!=)(?!\s*None\b)""",
                    r"""["']ground_truth["']\s*:\s*["'](attack|benign)["']"""):
            for m in re.finditer(pat, s):
                bad.append(f"{p.name}:{s[:m.start()].count(chr(10)) + 1}")
    assert bad == []

"""Metricile deciziei invatate (faza 24), per pipeline si per clasa. Functii pure.

Adevarul vine DOAR din etichete umane (consensul grupului sau ground_truth-ul cazului). Predictia:
"inchis" (benign) daca cascada a inchis sau ar fi inchis cazul, altfel "attack" (escaladat).
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable


def _r(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def _f1(p: float | None, r: float | None) -> float | None:
    if p is None or r is None:
        return None
    return round(2 * p * r / (p + r), 4) if p + r > 0 else 0.0


def confusion(rows: Iterable[tuple[str, bool]]) -> dict:
    """rows: (eticheta umana attack|benign, inchis?). Matricea de confuzie si P/R/F1 pe fiecare
    clasa: attack (pozitiv = escaladat) si benign (pozitiv = inchis)."""
    tp = fp = fn = tn = 0
    for label, closed in rows:
        if label == "attack":
            fn += int(closed)
            tp += int(not closed)
        elif label == "benign":
            tn += int(closed)
            fp += int(not closed)
    pa, ra = _r(tp, tp + fp), _r(tp, tp + fn)
    pb, rb = _r(tn, tn + fn), _r(tn, tn + fp)
    return {"matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "attack": {"precision": pa, "recall": ra, "f1": _f1(pa, ra), "support": tp + fn},
            "benign": {"precision": pb, "recall": rb, "f1": _f1(pb, rb), "support": tn + fp},
            "n": tp + fp + fn + tn}


def step_counts(steps: Iterable[str]) -> dict[str, int]:
    """Cate cazuri a decis fiecare pas al cascadei."""
    return dict(sorted(Counter(steps).items()))


def rate(part: int, total: int) -> float | None:
    return _r(part, total)

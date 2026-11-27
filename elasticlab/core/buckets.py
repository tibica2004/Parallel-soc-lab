"""Cheia grupului si consensul uman (faza 24). Functii pure.

Grupul = pipeline + versiunea punctelor de decizie + valorile lor. Cheia e un sha256 pe forma
canonica (sortata), deci nu depinde de ordinea din configurare sau din dictionar; alta versiune a
punctelor de decizie da alt grup (etichetele vechi nu se aplica pe definitii noi).
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterable

from elasticlab.contracts.learning import BucketKey, Consensus, Vote


def canonical(pipeline: str, dp_version: int, values: dict[str, str]) -> str:
    body = ";".join(f"{k}={values[k]}" for k in sorted(values))
    return f"{pipeline}|v{dp_version}|{body}"


def bucket_key(pipeline: str, dp_version: int, values: dict[str, str]) -> BucketKey:
    h = hashlib.sha256(canonical(pipeline, dp_version, values).encode("utf-8")).hexdigest()
    return BucketKey(pipeline=pipeline, dp_version=dp_version, values=dict(values),
                     bucket_id="b" + h[:24])


def latest_votes(votes: Iterable[Vote]) -> dict[str, Vote]:
    """Ultimul vot al fiecarui om (o reetichetare il inlocuieste; istoricul ramane in document)."""
    out: dict[str, Vote] = {}
    for v in sorted(votes, key=lambda x: (x.at, x.user)):
        out[v.user] = v
    return out


def consensus(votes: Iterable[Vote]) -> tuple[Consensus, int, int]:
    """Vot majoritar pe ultimul vot al fiecarui om. Egalitate = nedecis (TIE), nu intra la
    antrenare. Intoarce (consens, voturi attack, voturi benign)."""
    last = latest_votes(votes)
    a = sum(1 for v in last.values() if v.label == "attack")
    b = sum(1 for v in last.values() if v.label == "benign")
    if a == 0 and b == 0:
        return Consensus.NONE, 0, 0
    if a == b:
        return Consensus.TIE, a, b
    return (Consensus.ATTACK if a > b else Consensus.BENIGN), a, b


def label_priority(count: int, p_attack: float | None, outlier: bool = False) -> float:
    """Ordinea cozii de etichetare: incertitudine x volum. Fara model (sau outlier) incertitudinea
    e maxima (1). Volumul intra logaritmic, ca un grup urias sa nu le ingroape pe celelalte."""
    import math
    unc = 1.0 if (p_attack is None or outlier) else 1.0 - abs(2.0 * p_attack - 1.0)
    return round(unc * math.log1p(max(0, count)), 6)

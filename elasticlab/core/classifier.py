"""Clasificatorul pe punctele de decizie (faza 24). Functii pure, fara dependente noi.

Algoritmul: Bayes naiv categorial cu netezire Laplace, plus vecinii cei mai apropiati (distanta
Hamming pe punctele de decizie) pentru semnalul de outlier si pentru explicatie. Ales pentru ca:

  - e DETERMINIST: numaratori intregi, iteratie sortata, aceeasi intrare -> acelasi artefact si
    acelasi hash (test);
  - e EXPLICABIL pe punct de decizie: log-raportul se descompune exact in contributii
    log P(v|attack) - log P(v|benign), una pe punct;
  - se SALVEAZA CA DATE: artefactul e JSON (numaratori, liste), fara cod executabil (nu pickle);
  - merge cu putine exemple (zeci de grupuri), fara biblioteci noi in venv-ul de productie.

Alternative respinse (docs/pasi/pas-24.md): arbore de decizie / regresie logistica (cer scikit-learn
sau o implementare de optimizare; logistica nu e determinista fara grija la solver), kNN pur (fara
contributii pe punct).

Exemplele de antrenare sunt GRUPURI cu consens uman (L3), un exemplu per grup: volumul unui grup nu
cumpara greutate in model (un zgomot frecvent nu inghite clasa rara).
"""
from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Sequence

from elasticlab.contracts.learning import (Contribution, LabeledBucket, ModelDecision, Neighbor,
                                           Prediction, Thresholds, ValidationMetrics)

ALGORITHM = "nb-categorical-v1"
CLASSES = ("attack", "benign")
ALPHA = 1.0
MAX_NEIGHBORS = 3
OUTLIER_UNSEEN = 2          # atatea valori nevazute la antrenare -> outlier


def train(pipeline: str, dp_version: int, decision_points: Sequence[str],
          samples: Sequence[LabeledBucket], thresholds: Thresholds, alpha: float = ALPHA) -> dict:
    """Artefactul modelului, ca date. Fara momentul antrenarii (intra in manifest), ca hash-ul sa
    depinda doar de intrare."""
    dps = list(decision_points)
    class_counts = {c: 0 for c in CLASSES}
    feat: dict[str, dict[str, list[int]]] = {d: {} for d in dps}
    labeled = []
    for s in sorted(samples, key=lambda x: x.bucket_id):
        ci = CLASSES.index(s.label)
        class_counts[s.label] += 1
        row = []
        for d in dps:
            v = s.values.get(d, "none")
            cell = feat[d].setdefault(v, [0, 0])
            cell[ci] += 1
            row.append(v)
        labeled.append([s.bucket_id, row, s.label])
    return {
        "format": ALGORITHM,
        "pipeline": pipeline,
        "dp_version": dp_version,
        "decision_points": dps,
        "alpha": alpha,
        "classes": list(CLASSES),
        "class_counts": class_counts,
        "feature_counts": {d: {v: feat[d][v] for v in sorted(feat[d])} for d in dps},
        "labeled": labeled,
        "thresholds": thresholds.model_dump(),
    }


def canonical_json(artifact: dict) -> str:
    return json.dumps(artifact, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def artifact_hash(artifact: dict) -> str:
    return hashlib.sha256(canonical_json(artifact).encode("utf-8")).hexdigest()


def validate_artifact(artifact: dict) -> None:
    """Forma minima, verificata la incarcare. Un artefact strain/stricat nu se foloseste (L6)."""
    if not isinstance(artifact, dict) or artifact.get("format") != ALGORITHM:
        raise ValueError("format de model necunoscut")
    for k in ("pipeline", "dp_version", "decision_points", "class_counts", "feature_counts",
              "labeled", "thresholds", "alpha"):
        if k not in artifact:
            raise ValueError(f"camp lipsa in model: {k}")
    if list(artifact.get("classes") or []) != list(CLASSES):
        raise ValueError("clase neasteptate in model")


def _log_lik(artifact: dict, d: str, v: str, ci: int) -> float:
    a = float(artifact["alpha"])
    counts = artifact["feature_counts"].get(d, {})
    n_c = artifact["class_counts"][CLASSES[ci]]
    k = len(counts) + 1                    # +1: locul valorilor nevazute
    return math.log((counts.get(v, [0, 0])[ci] + a) / (n_c + a * k))


def predict(artifact: dict, values: dict[str, str], model_hash: str | None = None) -> Prediction:
    th = Thresholds(**artifact["thresholds"])
    a = float(artifact["alpha"])
    n_a, n_b = artifact["class_counts"]["attack"], artifact["class_counts"]["benign"]
    n = n_a + n_b
    lo = math.log((n_a + a) / (n + 2 * a)) - math.log((n_b + a) / (n + 2 * a))
    contribs, unseen = [], 0
    for d in artifact["decision_points"]:
        v = values.get(d, "none")
        if v not in artifact["feature_counts"].get(d, {}):
            unseen += 1
        w = _log_lik(artifact, d, v, 0) - _log_lik(artifact, d, v, 1)
        lo += w
        contribs.append(Contribution(decision_point=d, value=v, weight=round(w, 6)))
    lo = max(-50.0, min(50.0, lo))
    p_attack = round(1.0 / (1.0 + math.exp(-lo)), 6)

    row = [values.get(d, "none") for d in artifact["decision_points"]]
    dist = sorted(((sum(1 for x, y in zip(row, r) if x != y), bid, lab)
                   for bid, r, lab in artifact["labeled"]), key=lambda t: (t[0], t[1]))
    neighbors = [Neighbor(bucket_id=b, distance=dd, label=lab) for dd, b, lab in dist[:MAX_NEIGHBORS]]
    nearest = dist[0][0] if dist else None
    outlier = nearest is None or nearest > th.outlier_distance or unseen >= OUTLIER_UNSEEN

    benign_conf = (1.0 - p_attack) * 100.0
    if benign_conf >= th.benign_close and not outlier:
        decision, conf = ModelDecision.BENIGN, int(math.floor(benign_conf))
    elif p_attack * 100.0 >= th.attack_likely:
        decision, conf = ModelDecision.ATTACK, int(math.floor(p_attack * 100.0))
    else:
        decision, conf = ModelDecision.UNCERTAIN, int(math.floor(max(p_attack, 1 - p_attack) * 100.0))
    contribs.sort(key=lambda c: (-abs(c.weight), c.decision_point))
    return Prediction(source="own_model", model_hash=model_hash, decision=decision,
                      confidence=max(0, min(100, conf)), p_attack=p_attack, outlier=outlier,
                      unseen_values=unseen, contributions=contribs[:20], neighbors=neighbors)


def split_by_bucket(samples: Sequence[LabeledBucket], validation_fraction: float = 0.2,
                    min_validation: int = 1) -> tuple[list[LabeledBucket], list[LabeledBucket]]:
    """Impartire train/validare PE GRUP (un grup e intr-o singura parte, deci alertele aceluiasi
    grup nu se scurg din antrenare in validare). Validarea = cele mai noi grupuri (dupa ultima
    aparitie, apoi identificator), ca sa masoare ce vine, nu ce a fost."""
    ordered = sorted(samples, key=lambda s: (s.last_seen, s.bucket_id))
    if len(ordered) < 2:
        return list(ordered), []
    k = max(min_validation, int(round(len(ordered) * validation_fraction)))
    k = min(k, len(ordered) - 1)
    return ordered[:-k], ordered[-k:]


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def evaluate(artifact: dict, samples: Sequence[LabeledBucket]) -> ValidationMetrics:
    """Metricile modelului pe un set etichetat. Pozitiv = attack = orice NU se inchide."""
    tp = fp = fn = tn = 0
    for s in samples:
        p = predict(artifact, s.values)
        closes = p.decision is ModelDecision.BENIGN
        if s.label == "attack":
            fn += int(closes)
            tp += int(not closes)
        else:
            tn += int(closes)
            fp += int(not closes)
    prec, rec = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = (None if prec is None or rec is None
          else (round(2 * prec * rec / (prec + rec), 4) if prec + rec > 0 else 0.0))
    return ValidationMetrics(n=len(samples), n_attack=tp + fn, n_benign=fp + tn, closures=tn + fn,
                             closures_correct=tn, closed_attacks=fn, tp=tp, fp=fp, fn=fn, tn=tn,
                             precision=prec, recall=rec, f1=f1)

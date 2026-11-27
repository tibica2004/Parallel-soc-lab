"""TIER 3 — bucla de invatare (faza 24): antrenare, controlorul de activare, drift, metrici.

Rulat de COD, programat (nu de om si nu de agent):
  soc-learn.timer        orar:     tier3.py --once --invatare --scrie
                                   (candidat per pipeline, controlor complet, metrici)
  soc-learn-guard.timer  la 5 min: tier3.py --once --invatare-garda --scrie
                                   (doar retrogradarile: control, drift, hash, grup inchis etichetat attack)
  soc-learn-gold.timer   zilnic:   tier3.py --once --regresie-aur --scrie
                                   (setul de aur, doar cand sonda LLM e sanatoasa)

Linii rosii aplicate aici:
  - L3: exemplele de antrenare sunt DOAR grupuri cu consens uman (store/buckets.labeled). Nici
    verdictele sistemului, nici deciziile cascadei nu intra in antrenare;
  - fiecare tranzitie: notificare, document in soc-metrics (type=cascade_transition), audit
    (soc-learning-audit + data/models/audit.jsonl);
  - fara --scrie: calculeaza si raporteaza, nu schimba manifestul si nu scrie nimic.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from elasticlab.contracts.learning import (ActiveStats, ControllerInput, LabeledBucket, ModelRecord,
                                           ModelState, PipelineConfig, ShadowStats, Transition,
                                           ValidationMetrics)
from elasticlab.core import classifier, controller, pipelines
from elasticlab.core import learning_metrics as LM
from elasticlab.store import buckets as B
from elasticlab.store import models as M
from elasticlab.store import writer

MIN_TRAIN = 10                  # sub atatea grupuri etichetate nu se antreneaza nimic
VERDICTS_IDX = "verdicts-history"
METRICS_IDX = "soc-metrics"
PROBE_MAX_AGE_MIN = 10
DRIFT_MIN_CASES = 20            # sub atatea cazuri in 24 h, rata de drift nu se calculeaza
FETCH = 10000


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(s) -> datetime:
    return datetime.fromisoformat(str(s).replace("Z", "+00:00"))


# ---------------- antrenare ----------------

def train_candidate(p: PipelineConfig, samples: list[LabeledBucket], now: datetime, root: Path,
                    manifest: dict, write: bool) -> tuple[ModelRecord | None, list[LabeledBucket]]:
    """Candidatul pipeline-ului din etichetele umane. Intoarce (record, setul de validare)."""
    if p.decision_source != "own_model":
        return None, []
    if len(samples) < MIN_TRAIN or len({s.label for s in samples}) < 2:
        return None, []
    train, val = classifier.split_by_bucket(samples)
    art = classifier.train(p.id, p.decision_points_version, p.decision_points, train, p.thresholds)
    h = classifier.artifact_hash(art)
    existing = M.find(manifest, p.id, h)
    if existing is not None:
        return existing, val
    if write:
        M.save_artifact(root, art)
    rec = ModelRecord(pipeline=p.id, model_hash=h, algorithm=classifier.ALGORITHM,
                      dp_version=p.decision_points_version, trained_at=now, n_train=len(train),
                      n_validation=len(val),
                      labels_attack=sum(1 for s in samples if s.label == "attack"),
                      labels_benign=sum(1 for s in samples if s.label == "benign"),
                      validation=classifier.evaluate(art, val), state=ModelState.CANDIDATE,
                      state_since=now)
    M.upsert(manifest, rec)
    return rec, val


def labels_changed(art: dict | None, samples: list[LabeledBucket]) -> int:
    """Cate etichete difera fata de cele pe care s-a antrenat modelul (noi, schimbate, disparute)."""
    if art is None:
        return len(samples)
    old = {bid: lab for bid, _row, lab in art.get("labeled", [])}
    now = {s.bucket_id: s.label for s in samples}
    return sum(1 for b in set(old) | set(now) if old.get(b) != now.get(b))


# ---------------- statistici din Elasticsearch ----------------

def _verdicts(es, pipeline: str, since: datetime, extra: list[dict] | None = None,
              fields=("cascade", "classification", "ground_truth", "bucket_id", "@timestamp")) -> list[dict]:
    r = es.search(index=VERDICTS_IDX, size=FETCH, source=list(fields), query={"bool": {"filter": [
        {"term": {"cascade.pipeline": pipeline}},
        {"range": {"@timestamp": {"gte": since.isoformat()}}}] + (extra or [])}})
    return [h["_source"] for h in r["hits"]["hits"]]


def _bucket_docs(es, ids: set[str]) -> dict[str, dict]:
    ids = {i for i in ids if B.valid_id(i)}
    if not ids:
        return {}
    r = es.search(index=writer.BUCKETS_IDX, size=len(ids), query={"terms": {"bucket_id": sorted(ids)}})
    return {h["_source"]["bucket_id"]: h["_source"] for h in r["hits"]["hits"]}


def shadow_stats(rows: list[dict], bucket_docs: dict[str, dict], model_hash: str) -> ShadowStats:
    """Pur. Deciziile modelului din umbra = randurile in care EL a dat predictia. "Contrazisa" =
    inchidere pe care calea completa (pasul 4, verdictul scris) a gasit-o suspicious/malicious."""
    dec = clo = contra = on_attack = 0
    for r in rows:
        c = r.get("cascade") or {}
        if c.get("model_hash") != model_hash:
            continue
        dec += 1
        if c.get("would_close"):
            clo += 1
            contra += int(r.get("classification") in ("suspicious", "malicious"))
            on_attack += int((bucket_docs.get(c.get("bucket_id")) or {}).get("consensus") == "attack")
    return ShadowStats(decisions=dec, closures=clo, contradicted=contra, closures_on_attack_buckets=on_attack)


def case_label(row: dict, bucket_docs: dict[str, dict]) -> str | None:
    """Eticheta umana a unui caz: ground_truth-ul lui (pus de om), altfel consensul grupului."""
    gt = row.get("ground_truth")
    if gt in ("attack", "benign"):
        return gt
    cons = (bucket_docs.get((row.get("cascade") or {}).get("bucket_id")) or {}).get("consensus")
    return cons if cons in ("attack", "benign") else None


def active_stats(rows_since_active: list[dict], rows_24h: list[dict], bucket_docs: dict[str, dict],
                 active: ModelRecord, new_buckets_24h: int, hash_ok: bool) -> ActiveStats:
    """Pur. Declansatorii de retrogradare pentru modelul activ."""
    since = active.state_since
    attack_on_closed = any(
        d.get("last_closed_at") and _ts(d["last_closed_at"]) >= since and int(d.get("votes_attack") or 0) > 0
        for d in bucket_docs.values())
    ctrl = [r for r in rows_since_active if (r.get("cascade") or {}).get("control_sample")]
    labeled = [case_label(r, bucket_docs) for r in ctrl]
    labeled = [x for x in labeled if x is not None]
    n = len(rows_24h)
    preds = [r for r in rows_24h if (r.get("cascade") or {}).get("model_hash")]
    outl = sum(1 for r in preds if (r.get("cascade") or {}).get("outlier"))
    return ActiveStats(human_attack_on_closed_bucket=attack_on_closed, control_labeled=len(labeled),
                       control_disagreements=sum(1 for x in labeled if x == "attack"),
                       new_bucket_rate=LM.rate(new_buckets_24h, n) if n >= DRIFT_MIN_CASES else None,
                       outlier_rate=LM.rate(outl, len(preds)) if len(preds) >= DRIFT_MIN_CASES else None,
                       hash_mismatch=not hash_ok)


def pipeline_metrics(rows: list[dict], bucket_docs: dict[str, dict]) -> dict:
    """Precizie/recall/F1/matrice pe cazurile cu eticheta umana + cati a decis fiecare pas."""
    pairs = []
    for r in rows:
        lab = case_label(r, bucket_docs)
        if lab is None:
            continue
        c = r.get("cascade") or {}
        pairs.append((lab, bool(c.get("applied") or c.get("would_close"))))
    return {"cascade": LM.confusion(pairs),
            "steps": LM.step_counts((r.get("cascade") or {}).get("step") or "?" for r in rows),
            "cases": len(rows)}


# ---------------- efectele unei tranzitii ----------------

class Effects:
    """Notificare + soc-metrics + audit. Injectabil (teste fara retea)."""

    def __init__(self, root: Path, write: bool, notify: Callable | None = None,
                 metrics_es=None, audit_es=None):
        self.root, self.write = root, write
        self.notify = notify
        self.metrics_es, self.audit_es = metrics_es, audit_es
        self.sent: list[dict] = []

    def transition(self, t: Transition) -> None:
        doc = {"@timestamp": t.at.isoformat(), "type": "cascade_transition", **t.model_dump(mode="json")}
        self.sent.append(doc)
        if not self.write:
            return
        self.root.mkdir(parents=True, exist_ok=True)
        with open(self.root / "audit.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(doc, sort_keys=True) + "\n")
        for fn in (lambda: self.metrics_es and self.metrics_es.index(index=METRICS_IDX, document=doc),
                   lambda: self.audit_es and writer.index_learning_audit(self.audit_es, doc),
                   lambda: self.notify and self.notify(
                       f"Model {t.pipeline}: {t.from_state.value} -> {t.to_state.value}",
                       f"model {t.model_hash[:12]} · {t.reason} · actor={t.actor}",
                       severity="high" if t.to_state is not ModelState.ACTIVE else "critical",
                       dedup_key=f"model:{t.pipeline}:{t.model_hash[:12]}:{t.to_state.value}",
                       dedup_minutes=5, host="es-node-1")):
            try:
                fn()
            except Exception:  # noqa: BLE001 — efectele nu opresc controlorul; auditul local ramane
                pass

    def metric(self, doc: dict) -> None:
        self.sent.append(doc)
        if self.write and self.metrics_es is not None:
            try:
                self.metrics_es.index(index=METRICS_IDX, document=doc)
            except Exception:  # noqa: BLE001
                pass


def default_effects(root: Path, write: bool) -> Effects:
    from elasticlab.ops import notify
    return Effects(root, write, notify=notify.notify_human,
                   metrics_es=writer._client("ES_METRICS_WRITER_API_KEY"), audit_es=writer.learning_client())


# ---------------- un pipeline ----------------

def _artifact(root: Path, rec: ModelRecord | None) -> tuple[dict | None, bool]:
    if rec is None:
        return None, True
    try:
        return M.load_artifact(root, rec.pipeline, rec.model_hash), True
    except M.HashMismatch:
        return None, False
    except Exception:  # noqa: BLE001 — artefact lipsa: tratat ca nepotrivire (nu se foloseste)
        return None, False


def _prompt_set() -> str | None:
    try:
        from elasticlab.core import prompts
        return prompts.prompt_set(prompts.current())
    except Exception:  # noqa: BLE001
        return None


def run_pipeline(es, p: PipelineConfig, *, now: datetime, root: Path, manifest: dict,
                 effects: Effects, train: bool = True, prompt_set: str | None = None) -> dict:
    report: dict = {"pipeline": p.id, "transitions": []}
    samples = B.labeled(es, p.id, p.decision_points_version)
    report["labels"] = {"attack": sum(1 for s in samples if s.label == "attack"),
                        "benign": sum(1 for s in samples if s.label == "benign")}
    cand, val = (train_candidate(p, samples, now, root, manifest, effects.write) if train else (None, []))
    if cand is not None:
        report["candidate"] = cand.model_hash
    shadow = M.in_state(manifest, p.id, ModelState.SHADOW)
    active = M.in_state(manifest, p.id, ModelState.ACTIVE)
    sh_art, _ = _artifact(root, shadow)
    _act_art, act_ok = _artifact(root, active)
    sh_val: ValidationMetrics | None = classifier.evaluate(sh_art, val) if (sh_art and val) else None

    rows_7d = _verdicts(es, p.id, now - timedelta(days=30))
    rows_24h = [r for r in rows_7d if r.get("@timestamp") and _ts(r["@timestamp"]) >= now - timedelta(hours=24)]
    bdocs = _bucket_docs(es, {(r.get("cascade") or {}).get("bucket_id") for r in rows_7d} - {None})
    sh_stats = ShadowStats()
    if shadow is not None:
        sh_stats = shadow_stats([r for r in rows_7d if _ts(r["@timestamp"]) >= shadow.state_since],
                                bdocs, shadow.model_hash)
    act_stats = ActiveStats()
    if active is not None:
        nb = es.count(index=writer.BUCKETS_IDX, query={"bool": {"filter": [
            {"term": {"pipeline": p.id}},
            {"range": {"first_seen": {"gte": (now - timedelta(hours=24)).isoformat()}}}]}})["count"]
        closed = es.search(index=writer.BUCKETS_IDX, size=FETCH, query={"bool": {"filter": [
            {"term": {"pipeline": p.id}}, {"exists": {"field": "last_closed_at"}}]}})
        bdocs_all = {**bdocs, **{h["_source"]["bucket_id"]: h["_source"] for h in closed["hits"]["hits"]}}
        act_stats = active_stats([r for r in rows_7d if _ts(r["@timestamp"]) >= active.state_since],
                                 rows_24h, bdocs_all, active, nb, act_ok)
    reg = M.last_regression(manifest, p.id, shadow.model_hash, prompt_set) if shadow else None
    inp = ControllerInput(
        pipeline=p.id, now=now, labels_attack=report["labels"]["attack"],
        labels_benign=report["labels"]["benign"], candidate=cand, shadow=shadow, active=active,
        shadow_stats=sh_stats, active_stats=act_stats, shadow_validation_now=sh_val,
        regression_passed_for_shadow=bool(reg and reg.get("passed")),
        labels_changed_since_shadow=labels_changed(sh_art, samples) if shadow else len(samples),
        thresholds=p.thresholds)
    for t in controller.step(inp):
        M.apply_transition(manifest, t)
        effects.transition(t)
        report["transitions"].append(t.model_dump(mode="json"))
    report["activation_blockers"] = controller.activation_blockers(inp) if shadow else ["niciun model in umbra"]
    report["metrics"] = pipeline_metrics(rows_7d, bdocs)
    # Garda (la 5 min, fara antrenare) nu scrie metrici: doar rularea orara.
    if train:
        effects.metric({"@timestamp": now.isoformat(), "type": "cascade_metrics", "pipeline": p.id,
                        "labels": report["labels"], "shadow_stats": sh_stats.model_dump(),
                        "active_stats": act_stats.model_dump(), "blockers": report["activation_blockers"],
                        "active_hash": active.model_hash if active else None,
                        "shadow_hash": shadow.model_hash if shadow else None, **report["metrics"]})
    return report


def run(*, write: bool, train: bool = True, only: str | None = None, es=None, root: Path | None = None,
        effects: Effects | None = None, now: datetime | None = None) -> list[dict]:
    es = es or writer.learning_client()
    if es is None:
        raise RuntimeError("ES_LEARNING_WRITER_API_KEY lipseste (citire soc-buckets + verdicts-history)")
    root = root or M.models_dir()
    now = now or _now()
    cfg = pipelines.load()
    manifest = M.load_manifest(root)
    effects = effects or default_effects(root, write)
    pset = _prompt_set()
    out = []
    for p in cfg.pipelines:
        if only and p.id != only:
            continue
        try:
            out.append(run_pipeline(es, p, now=now, root=root, manifest=manifest, effects=effects,
                                    train=train, prompt_set=pset))
        except Exception as e:  # noqa: BLE001 — un pipeline cazut nu le opreste pe celelalte
            out.append({"pipeline": p.id, "error": f"{type(e).__name__}: {str(e)[:200]}"})
    if write:
        M.save_manifest(root, manifest)
    return out


def on_human_label(pipeline: str, bucket_doc: dict, label: str, *, now: datetime | None = None,
                   root: Path | None = None, effects: Effects | None = None) -> list[Transition]:
    """Retrogradarea IMEDIATA, la votul omului: attack pe un grup pe care cascada l-a inchis cat
    timp modelul curent era activ -> activ -> umbra. Chemata din label_ui; nu ridica exceptii."""
    try:
        if label != "attack" or not bucket_doc.get("last_closed_at"):
            return []
        root = root or M.models_dir()
        now = now or _now()
        manifest = M.load_manifest(root)
        active = M.in_state(manifest, pipeline, ModelState.ACTIVE)
        if active is None or _ts(bucket_doc["last_closed_at"]) < active.state_since:
            return []
        inp = ControllerInput(pipeline=pipeline, now=now, active=active,
                              shadow=M.in_state(manifest, pipeline, ModelState.SHADOW),
                              active_stats=ActiveStats(human_attack_on_closed_bucket=True))
        ts = controller.step(inp)
        effects = effects or default_effects(root, True)
        for t in ts:
            M.apply_transition(manifest, t)
            effects.transition(t)
        M.save_manifest(root, manifest)
        return ts
    except Exception:  # noqa: BLE001 — votul omului nu are voie sa crape din cauza controlorului
        return []


# ---------------- regresia pe setul de aur ----------------

def probe_healthy(es_metrics, now: datetime | None = None) -> tuple[bool, str]:
    """Ultima sonda LLM (soc-metrics type=llm_probe) e ok, fara esecuri consecutive, recenta."""
    now = now or _now()
    try:
        r = es_metrics.search(index=METRICS_IDX, size=1, sort=[{"@timestamp": "desc"}],
                              query={"term": {"type.keyword": "llm_probe"}})
    except Exception as e:  # noqa: BLE001
        return False, f"sonda necitita: {type(e).__name__}"
    hits = r["hits"]["hits"]
    if not hits:
        return False, "nicio sonda"
    d = hits[0]["_source"]
    age = (now - _ts(d["@timestamp"])).total_seconds() / 60
    if age > PROBE_MAX_AGE_MIN:
        return False, f"sonda veche ({age:.0f} min)"
    if not d.get("ok") or int(d.get("consecutive_failures") or 0) > 0:
        return False, f"sonda esuata: {d.get('error')}"
    return True, "ok"


def gold_verdict(llm_rows: list[dict], cascade_rows: list[dict]) -> tuple[bool, dict]:
    """Pur. Regresia trece cand: setul nu e gol, Tier 1 semnaleaza toate atacurile din setul de aur
    (niciun FN) si modelul nu ar inchide niciun atac din setul de aur."""
    fn = sum(1 for r in llm_rows if r["ground_truth"] == "attack" and not r["flagged"])
    closed_attacks = sum(1 for r in cascade_rows if r["ground_truth"] == "attack" and r["would_close"])
    closed_benign = sum(1 for r in cascade_rows if r["ground_truth"] == "benign" and r["would_close"])
    details = {"n": len(llm_rows), "llm_fn": fn, "cascade_closed_attacks": closed_attacks,
               "cascade_closed_benign": closed_benign}
    return bool(llm_rows) and fn == 0 and closed_attacks == 0, details


def regression_gold(*, write: bool, root: Path | None = None, now: datetime | None = None) -> list[dict]:
    """Setul de aur (data/golden, regression.py export) prin Tier 1 (setul de prompturi curent) si
    prin modelul din umbra/activ al fiecarui pipeline. Ruleaza DOAR cu sonda LLM sanatoasa."""
    from elasticlab.contracts.learning import ModelDecision
    from elasticlab.core import decision_points as DP
    from elasticlab.eval import regression as RG
    from elasticlab.tier1.fast_path import build_context
    root = root or M.models_dir()
    now = now or _now()
    met = writer._client("ES_READER_API_KEY")
    ok, why = probe_healthy(met, now) if met is not None else (False, "fara ES_READER_API_KEY")
    if not ok:
        return [{"skipped": f"sonda LLM nesanatoasa: {why}"}]
    if not RG.GOLDEN.exists():
        return [{"skipped": "setul de aur lipseste (python regression.py export)"}]
    items = [json.loads(x) for x in RG.GOLDEN.read_text().splitlines() if x.strip()]
    for it in items:
        it["key"] = it["verdict_id"]
    t1 = RG._run_set(items)
    llm_rows = [{"ground_truth": it["ground_truth"], "flagged": t1[it["key"]]["flagged"]} for it in items]
    cfg = pipelines.load()
    manifest = M.load_manifest(root)
    pset = _prompt_set()
    out = []
    for p in cfg.pipelines:
        for st in (ModelState.SHADOW, ModelState.ACTIVE):
            rec = M.in_state(manifest, p.id, st)
            art, hok = _artifact(root, rec)
            if rec is None or not hok or art is None:
                continue
            rows = []
            for it in items:
                if (it["alert"].get("kibana.alert.rule.name") or
                        ((it["alert"].get("kibana") or {}).get("alert") or {}).get("rule", {}).get("name")) not in p.rules:
                    continue
                try:
                    vals = DP.derive(build_context(it["alert"]), it["alert"], p, list(cfg.network_zones))
                    pr = classifier.predict(art, vals, rec.model_hash)
                    would = pr.decision is ModelDecision.BENIGN and not pr.outlier and \
                        pr.confidence >= p.thresholds.benign_close
                except Exception:  # noqa: BLE001 — fara fapte: nu se poate inchide (conservator)
                    would = False
                rows.append({"ground_truth": it["ground_truth"], "would_close": would})
            passed, details = gold_verdict(llm_rows, rows)
            M.record_regression(manifest, pipeline=p.id, model_hash=rec.model_hash, prompt_set=pset,
                                passed=passed, at=now, details=details)
            out.append({"pipeline": p.id, "model_hash": rec.model_hash, "state": st.value,
                        "prompt_set": pset, "passed": passed, **details})
    if write:
        M.save_manifest(root, manifest)
        eff = default_effects(root, True)
        for r in out:
            eff.metric({"@timestamp": now.isoformat(), "type": "cascade_regression", **r})
    return out


def history(pipeline: str, root: Path | None = None) -> list[dict]:
    m = M.load_manifest(root or M.models_dir())
    return [r.model_dump(mode="json") for r in M.records(m, pipeline)]


def rollback_cmd(pipeline: str, model_hash: str, root: Path | None = None) -> list[dict]:
    """Comanda omului: revenire la un model anterior (care a mai fost activ, cu hash verificat)."""
    root = root or M.models_dir()
    m = M.load_manifest(root)
    ts = M.rollback(root, m, pipeline, model_hash, _now())
    M.save_manifest(root, m)
    eff = default_effects(root, True)
    for t in ts:
        eff.transition(t)
    return [t.model_dump(mode="json") for t in ts]

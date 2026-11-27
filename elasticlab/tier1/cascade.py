"""Cascada Tier 1 in productie (faza 24): pasul 0 (faptele, o singura data), clasele critice,
grupul, sursa de decizie. Logica pasilor e in core/cascade.py (pura); aici sunt intrarile.

Garantii:
  - L4: clasele critice (honeytoken, detectie nativa, senzor, regula comportamentala, proces pornit
    de serverul web) si orice caz cu podea merg la pasul 4, indiferent de grup sau model;
  - L6: ORICE eroare (configurare, Elasticsearch, model, hash nepotrivit) -> pasul ERROR, adica
    pasul 4 neschimbat; `evaluate` nu ridica niciodata exceptii;
  - L5: cu T1_CASCADE=off nimic de aici nu ruleaza (orchestratorul nici nu incarca modulul).

Faptele se calculeaza o singura data: contextul din `fast_path.build_context` e folosit pentru
punctele de decizie si, daca se ajunge la pasul 4, trece in graful caii rapide (build_prefetched),
care sare peste recalcularea lui. Logica din fast_path ramane neschimbata (aceleasi noduri).
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from elasticlab.contracts.learning import (CascadeDecision, CascadeMode, CascadeStep, Consensus,
                                           ModelState, PipelinesConfig)
from elasticlab.contracts.schemas import (ActionType, Classification, EntityType, Verdict)
from elasticlab.core import cascade as K
from elasticlab.core import decision_points as DP
from elasticlab.core import honeytokens, pipelines
from elasticlab.core.buckets import bucket_key
from elasticlab.core.escalation import web_exec_floor
from elasticlab.store import buckets as B
from elasticlab.store import models as M
from elasticlab.tier1 import behavioral_rules, defend_native, sensor_rules
from elasticlab.tier1.decision_source import ExternalFieldSource, OwnModelSource

KILL_FILE_DEFAULT = "data/cascade-off"


def _g(d: dict, path: str):
    if path in d:
        return d[path]
    cur = d
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def current_mode(env=None, root: Path | None = None) -> CascadeMode:
    """T1_CASCADE din mediu, plus oprirea de urgenta fara repornire: daca exista fisierul
    CASCADE_KILL_FILE (implicit data/cascade-off), modul e off de la urmatorul ciclu."""
    env = env if env is not None else os.environ
    from elasticlab.paths import REPO_ROOT
    kill = Path(env.get("CASCADE_KILL_FILE") or (root or REPO_ROOT) / KILL_FILE_DEFAULT)
    try:
        if kill.exists():
            return CascadeMode.OFF
    except OSError:
        return CascadeMode.OFF
    return K.mode_from_env(env)


@dataclass
class Runtime:
    """Ce se incarca o data pe ciclu: configurarea, sursele de decizie (cu hash verificat),
    cititorul de grupuri. `error` setat = cascada nu se foloseste in ciclul asta (pasul 4)."""
    mode: CascadeMode
    cfg: PipelinesConfig | None = None
    sources: dict[str, object] = field(default_factory=dict)     # pipeline -> sursa de decizie
    active: dict[str, bool] = field(default_factory=dict)        # pipeline -> are model activ
    shadow_sources: dict[str, object] = field(default_factory=dict)  # umbra, cand exista si un activ
    hash_mismatch: dict[str, str] = field(default_factory=dict)  # pipeline -> hash refuzat
    bucket_reader: Callable[[str], dict | None] = lambda _bid: None
    build_context: Callable[[dict], dict] | None = None
    error: str | None = None


def load_runtime(mode: CascadeMode, *, bucket_reader=None, build_context=None,
                 models_root: Path | None = None, config_path: Path | None = None) -> Runtime:
    rt = Runtime(mode=mode, bucket_reader=bucket_reader or (lambda _bid: None),
                 build_context=build_context)
    try:
        rt.cfg = pipelines.load(config_path)
    except Exception as e:  # noqa: BLE001 — L6
        rt.error = f"configurare: {type(e).__name__}"
        return rt
    root = models_root or M.models_dir()
    try:
        manifest = M.load_manifest(root)
    except Exception as e:  # noqa: BLE001
        manifest = M.empty_manifest()
        rt.error = None if not root.exists() else f"manifest: {type(e).__name__}"
    for p in rt.cfg.pipelines:
        try:
            if p.decision_source == "external":
                st = None
                rec = M.in_state(manifest, p.id, ModelState.ACTIVE)
                if rec is not None:
                    st = ModelState.ACTIVE
                elif M.in_state(manifest, p.id, ModelState.SHADOW) is not None:
                    st = ModelState.SHADOW
                src = ExternalFieldSource(p.external, st)
                # Sursa externa e "activa" doar daca controlorul a activat exact aceasta configurare.
                rt.active[p.id] = rec is not None and rec.model_hash == src.model_hash
                rt.sources[p.id] = src
                continue
            act = M.in_state(manifest, p.id, ModelState.ACTIVE)
            sh = M.in_state(manifest, p.id, ModelState.SHADOW)
            for rec, primary in ((act, True), (sh, act is None)):
                if rec is None:
                    continue
                try:
                    art = M.load_artifact(root, p.id, rec.model_hash)
                except M.HashMismatch:
                    if rec.state is ModelState.ACTIVE or primary:
                        rt.hash_mismatch[p.id] = rec.model_hash
                    continue
                if art.get("dp_version") != p.decision_points_version or \
                        list(art.get("decision_points") or []) != list(p.decision_points):
                    continue                # model pe alta definitie a punctelor: nu se foloseste
                src = OwnModelSource(art, rec.model_hash, rec.state)
                if primary:
                    rt.sources[p.id] = src
                    rt.active[p.id] = rec.state is ModelState.ACTIVE
                else:
                    rt.shadow_sources[p.id] = src
        except Exception:  # noqa: BLE001 — un pipeline stricat nu le strica pe celelalte
            continue
    return rt


def critical_classes(alert: dict, ctx: dict) -> tuple[str, ...]:
    """Clasele critice (L4). Ce nu se poate verifica nu e "necritic": predicatele sunt pe rule_id /
    dataset, iar web_exec pe faptele calculate de cod."""
    ex = ctx.get("execution") or {}
    out = []
    if honeytokens.is_honeytoken(alert) or ctx.get("honeytoken"):
        out.append("honeytoken")
    if defend_native.is_native(alert) or ctx.get("native_detection"):
        out.append("native_detection")
    if sensor_rules.is_sensor_alert(alert) or ctx.get("sensor_detection"):
        out.append("sensor_detection")
    if behavioral_rules.is_behavioral(alert):
        out.append("behavioral")
    if web_exec_floor(ctx.get("ran_by_web_service_account"), ex.get("parent"), ex.get("sudo_invoked_by")):
        out.append("web_exec")
    return tuple(out)


def evaluate(rt: Runtime, alert: dict, sample_key: str) -> tuple[CascadeDecision, dict | None]:
    """Decizia cascadei si contextul (faptele) calculat o singura data. Nu ridica exceptii (L6)."""
    ctx = None
    try:
        if rt.error:
            raise RuntimeError(rt.error)
        rule = _g(alert, "kibana.alert.rule.name")
        p = pipelines.pipeline_for(rt.cfg, rule)
        # Clasele critice dupa rule_id se stiu fara fapte; faptele trebuie oricum pentru pasul 4.
        if rt.build_context is None:
            from elasticlab.tier1.fast_path import build_context as _bc
            rt.build_context = _bc
        ctx = rt.build_context(alert)
        if p is None:
            return K.decide(K.CascadeInputs(mode=rt.mode, pipeline=None)), ctx
        crit = critical_classes(alert, ctx)
        values = DP.derive(ctx, alert, p, list(rt.cfg.network_zones))
        key = bucket_key(p.id, p.decision_points_version, values)
        floor = K.floor_would_apply(ctx, "web_exec" in crit)
        cons = Consensus.NONE
        pred, state = None, None
        if not crit and not floor:
            cons = B.consensus_of(rt.bucket_reader(key.bucket_id), p.decision_points_version)
            src = rt.sources.get(p.id)
            if src is not None and cons in (Consensus.NONE, Consensus.TIE):
                pred, state = src.predict(values, alert), src.state
        if p.id in rt.hash_mismatch:
            pred, state = None, None
        d = K.decide(K.CascadeInputs(
            mode=rt.mode, pipeline=p, bucket=key, critical=crit, floor=floor, consensus=cons,
            pipeline_active=bool(rt.active.get(p.id)) and p.id not in rt.hash_mismatch,
            model_state=state, prediction=pred, sample_key=sample_key))
        shadow = rt.shadow_sources.get(p.id)
        if shadow is not None and not crit and not floor and cons in (Consensus.NONE, Consensus.TIE):
            # Umbra langa activ: aceeasi intrare, doar inregistrata (nu schimba decizia).
            try:
                sp = shadow.predict(values, alert)
                d = d.model_copy(update={"shadow_prediction": sp, "shadow_would_close": bool(
                    sp and sp.decision.value == "benign" and not sp.outlier
                    and sp.confidence >= p.thresholds.benign_close)})
            except Exception:  # noqa: BLE001 — umbra cazuta nu atinge decizia
                pass
        return d, ctx
    except Exception as e:  # noqa: BLE001 — L6: eroarea duce la pasul 4, niciodata la inchidere
        return CascadeDecision(mode=rt.mode, step=CascadeStep.ERROR,
                               error=f"{type(e).__name__}: {str(e)[:150]}"), ctx


def close_verdict(d: CascadeDecision, host: str | None) -> Verdict:
    """Verdictul scris de COD cand cascada inchide (doar benign, fara actiune). ground_truth ramane
    gol (persist), deci alerta din grupul etichetat NU primeste eticheta (L2)."""
    if not d.applied:
        raise ValueError("close_verdict doar pentru o inchidere efectiva")
    if d.step is CascadeStep.HUMAN_LABEL:
        conf, mid = 100, "cascade:human_label"
    else:
        p = d.prediction
        conf = p.confidence if p else 0
        mid = f"cascade:{p.source}:{(p.model_hash or '')[:12]}" if p else "cascade:model"
    return Verdict(investigation_id=str(uuid.uuid4()), source_path="fast",
                   entity_type=EntityType.HOST, entity_id=host or "unknown",
                   classification=Classification.BENIGN, confidence=conf,
                   rarity_score=0.0 if d.values.get("pair_in_baseline") == "yes" else 1.0,
                   proposed_action=ActionType.NONE, model_id=mid[:64])


def close_narrative(d: CascadeDecision) -> str:
    if d.step is CascadeStep.HUMAN_LABEL:
        return (f"Inchis de cascada (pasul 2): grupul {d.bucket_id} din pipeline-ul {d.pipeline} are "
                f"consens uman benign. Decizie din etichete umane, fara model de limbaj.")
    p = d.prediction
    top = ", ".join(f"{c.decision_point}={c.value}" for c in (p.contributions[:3] if p else []))
    return (f"Inchis de cascada (pasul 3): sursa {p.source if p else '?'} da benign cu incredere "
            f"{p.confidence if p else 0} pentru grupul {d.bucket_id} ({d.pipeline}); cele mai mari "
            f"contributii: {top or '-'}.")


def summary(d: CascadeDecision) -> dict:
    """Ce intra in verdictul scris (verdicts-history.cascade): fara explicatia completa."""
    p = d.prediction
    return {"mode": d.mode.value, "pipeline": d.pipeline, "dp_version": d.dp_version,
            "bucket_id": d.bucket_id, "step": d.step.value, "would_close": d.would_close,
            "applied": d.applied, "control_sample": d.control_sample, "reasons": list(d.reasons),
            "applied_reasons": d.applied_reasons, "consensus": d.consensus.value,
            "pipeline_active": d.pipeline_active,
            "model_state": d.model_state.value if d.model_state else None,
            "model_hash": p.model_hash if p else None, "source": p.source if p else None,
            "decision": p.decision.value if p else None, "confidence": p.confidence if p else None,
            "outlier": p.outlier if p else None, "error": d.error,
            "shadow_model_hash": d.shadow_prediction.model_hash if d.shadow_prediction else None,
            "shadow_would_close": d.shadow_would_close}


def build_prefetched(config=None):
    """Graful caii rapide cu contextul deja calculat (pasul 0). ACELEASI noduri ca
    fast_path.build_fast_path (pattern, verdict, finalize, rag, l1_agent), doar nodul prefetch
    foloseste contextul dat in stare, daca exista. Fara context -> prefetch-ul obisnuit."""
    from langgraph.graph import END, START, StateGraph

    from elasticlab.tier1 import fast_path as F
    cfg = F.CONFIGS[config] if isinstance(config, str) else (config or F.config_from_env())
    base = F.make_prefetch(cfg)

    def node_prefetch(state):
        given = state.get("context")
        if given is None:
            return base(state)
        ctx = dict(given)
        if cfg.enrich:
            from elasticlab.tier1.enrich import enrich
            ctx["enrichment"] = enrich(F.ES, state["alert"], cfg.correlation_window_min)
            F._guide_last(ctx)
        return {"context": ctx}

    g = StateGraph(F.FastState)
    chain = [("prefetch", node_prefetch)]
    if cfg.rag:
        chain.append(("rag", F.make_rag(cfg)))
    if cfg.tools:
        chain.append(("l1_agent", F.node_l1_agent))
    chain += [("pattern", F.make_pattern(cfg)), ("verdict", F.make_verdict(cfg)),
              ("finalize", F.node_finalize)]
    prev = START
    for name, fn in chain:
        g.add_node(name, fn)
        g.add_edge(prev, name)
        prev = name
    g.add_edge(prev, END)
    return g.compile()

#!/usr/bin/env python3
"""Cale lenta cu vizibilitate pe cei doi investigatori — de ce dezacordul."""
import os, json
from datetime import datetime
from schemas import RarityFinding, EntityType
from hunt_path import build_hunt_path

finding = RarityFinding(
    kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
    detail={"parent": "dash", "child": "id", "count": 1},
    rarity_score=1.0, evidence_refs=[],
)

print("=== Dezacord in detaliu ===\n")
graph = build_hunt_path()
t0 = datetime.now()

# stream ca sa prindem starea dupa fiecare nod, nu doar finalul
final = None
for chunk in graph.stream({"finding": finding}, config={"recursion_limit": 80}):
    for node, state in chunk.items():
        if node == "primary":
            d = state.get("draft_a", {})
            print(f"--- INVESTIGATOR A ---")
            print(f"  clasificare: {d.get('classification')}  incredere: {d.get('confidence')}")
            print(f"  evidence: {json.dumps(d.get('evidence', {}))}")
            print(f"  tool calls: {state.get('tool_calls_a')}")
            print(f"  decisive: {d.get('decisive_evidence', '')[:200]}")
            print(f"  narativa: {d.get('narrative','')[:250]}\n")
        elif node == "secondary":
            d = state.get("draft_b", {})
            print(f"--- INVESTIGATOR B ---")
            print(f"  clasificare: {d.get('classification')}  incredere: {d.get('confidence')}")
            print(f"  evidence: {json.dumps(d.get('evidence', {}))}")
            print(f"  tool calls: {state.get('tool_calls_b')}")
            print(f"  decisive: {d.get('decisive_evidence', '')[:200]}")
            print(f"  narativa: {d.get('narrative','')[:250]}\n")
        elif node == "corroborate":
            print(f"--- CORROBORARE ---")
            print(f"  status: {state.get('corroboration_status')}")
            print(f"  merged: {state.get('merged_draft',{}).get('classification')} / "
                  f"{state.get('merged_draft',{}).get('confidence')}\n")
        if node == "finalize":
            final = state

dt = (datetime.now() - t0).total_seconds()
if final:
    v = final["verdict"]
    print(f"=== VERDICT FINAL [{dt:.0f}s] ===")
    print(f"  {v.classification.value} / {v.confidence} / {v.proposed_action.value}")

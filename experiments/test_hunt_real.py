#!/usr/bin/env python3
"""Calea lenta pe un finding REAL, cu telemetrie in Elastic."""
import os
from datetime import datetime
from schemas import RarityFinding, EntityType
from hunt_path import build_hunt_path

# Findingul corespunde atacului tocmai generat. Perl sub un shell lansat de apache.
finding = RarityFinding(
    kind="new_parent_child",
    entity_type=EntityType.HOST,
    entity_id="web-prod",
    detail={"parent": "dash", "child": "perl", "count": 1},
    rarity_score=1.0,
    evidence_refs=[],
)

print("=== Cale lenta pe finding REAL ===")
print(f"Finding: {finding.detail['parent']} -> {finding.detail['child']} pe web-prod\n")
print("Investigatorul sapa in telemetria reala... (cateva minute)\n")

graph = build_hunt_path()
t0 = datetime.now()
result = graph.invoke({"finding": finding}, config={"recursion_limit": 80})
dt = (datetime.now() - t0).total_seconds()

v = result["verdict"]
print(f"\n=== REZULTAT [{dt:.0f}s] ===")
print(f"  clasificare:  {v.classification.value}")
print(f"  incredere:    {v.confidence}")
print(f"  corroborare:  {v.corroboration_status}")
print(f"  tool calls:   {v.tool_calls_made}")
print(f"  actiune:      {v.proposed_action.value}")
print(f"  MITRE:        {v.mitre_techniques}")
print(f"\n  unelte: {result.get('queries_run', [])}")
print(f"\n  ipoteze: {result.get('hypotheses', [])}")
print(f"\n  naratiune: {result.get('narrative','')[:500]}")

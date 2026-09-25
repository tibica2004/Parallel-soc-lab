#!/usr/bin/env python3
"""
Primul test al caii lente pe un finding.
Urmarim: cate tool calls face, daca lantul e coerent, daca ajunge la concluzie.
"""
import os, json
from datetime import datetime
from schemas import RarityFinding, EntityType
from hunt_path import build_hunt_path

# Finding fabricat: o pereche clar suspecta, ca sa vedem investigatorul sapand.
# apache2 -> perl e RCE clasic; nu e in baseline.
finding = RarityFinding(
    kind="new_parent_child",
    entity_type=EntityType.HOST,
    entity_id="web-prod",
    detail={"parent": "apache2", "child": "perl", "count": 1},
    rarity_score=1.0,
    evidence_refs=[],
)

print("=== Test cale lenta ===")
print(f"Finding: {finding.detail['parent']} -> {finding.detail['child']} pe {finding.entity_id}")
print(f"Raritate: {finding.rarity_score}\n")
print("Investigatorul incepe... (poate dura minute pe Qwen3 14B)\n")

graph = build_hunt_path()
t0 = datetime.now()
result = graph.invoke({"finding": finding}, config={"recursion_limit": 60})
dt = (datetime.now() - t0).total_seconds()

v = result["verdict"]
print(f"\n=== REZULTAT [{dt:.0f}s] ===")
print(f"  clasificare:    {v.classification.value}")
print(f"  incredere:      {v.confidence}")
print(f"  corroborare:    {v.corroboration_status}")
print(f"  tool calls:     {v.tool_calls_made}")
print(f"  tokeni:         {v.tokens_used}")
print(f"  actiune:        {v.proposed_action.value}")
print(f"  MITRE:          {v.mitre_techniques}")
print(f"\n  ipoteze considerate: {result.get('hypotheses', [])}")
print(f"\n  unelte apelate: {result.get('queries_run', [])}")
print(f"\n  naratiune: {result.get('narrative', '')[:400]}")

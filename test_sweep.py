#!/usr/bin/env python3
import os
from elasticsearch import Elasticsearch

ES = Elasticsearch(
    os.environ.get("ES_URL", "http://localhost:9200"),
    api_key=os.environ["ES_API_KEY"],
    request_timeout=30,
)

PROC_IDX = "logs-endpoint.events.process-*"
BASELINE_PC = "baseline-entity-parentchild"
WEB_PARENTS = {"apache2", "httpd", "php-fpm", "nginx"}


def _esql(query: str) -> list[dict]:
    resp = ES.esql.query(query=query, format="json")
    cols = [c["name"] for c in resp["columns"]]
    return [dict(zip(cols, row)) for row in resp["values"]]


def sweep_new_parent_child(window_hours: int = 1) -> list[dict]:
    recent = _esql(
        f"""
        FROM {PROC_IDX}
        | WHERE @timestamp >= NOW() - {window_hours} hours
        | WHERE process.parent.name IS NOT NULL AND process.name IS NOT NULL
        | STATS cnt = COUNT(*) BY host.name, process.parent.name, process.name
        """
    )
    known_rows = _esql(
        f"""
        FROM {BASELINE_PC}
        | KEEP host.name, process.parent.name, process.name
        | LIMIT 10000
        """
    )
    known = {
        (r["host.name"], r["process.parent.name"], r["process.name"])
        for r in known_rows
    }
    findings = []
    for r in recent:
        key = (r["host.name"], r["process.parent.name"], r["process.name"])
        if key in known:
            continue
        parent = r["process.parent.name"]
        score = 1.0 if parent in WEB_PARENTS else 0.8
        findings.append({
            "host": r["host.name"], "parent": parent, "child": r["process.name"],
            "count": r["cnt"], "rarity_score": score,
        })
    findings.sort(key=lambda f: f["rarity_score"], reverse=True)
    return findings


if __name__ == "__main__":
    info = ES.info()
    print(f"Conectat la Elasticsearch {info['version']['number']}, cluster '{info['cluster_name']}'\n")
    base_count = ES.count(index=BASELINE_PC)["count"]
    print(f"Baseline: {base_count} perechi cunoscute\n")
    print("=== sweep_new_parent_child (ultima ora) ===")
    findings = sweep_new_parent_child(window_hours=1)
    if not findings:
        print("Nicio pereche noua. Baseline-ul le-a invatat deja pe toate.")
    else:
        print(f"{len(findings)} perechi NOI (absente din baseline):\n")
        for f in findings:
            flag = "  <-- sub server web!" if f["parent"] in WEB_PARENTS else ""
            print(f"  [{f['rarity_score']:.1f}] {f['host']}: {f['parent']} -> {f['child']} (x{f['count']}){flag}")

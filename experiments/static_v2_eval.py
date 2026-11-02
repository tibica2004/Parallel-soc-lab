"""Experiment pas 2: v1 (+-12 linii) a marcat 43 de rezultate din WordPress core ca reale; 2/2
verificate = fals pozitive. Re-triaj cu v2 (functia intreaga + reguli noi), FARA scriere in ES.
Intrare: jurnalul rularii v1 (results/static-1-*.log). Iesire: tabel v1 -> v2 pe stdout."""
from __future__ import annotations

import glob
import json
import re
import sys
from collections import Counter

import static_triage as st

log = open(sorted(glob.glob("results/static-1-*.log"))[0]).read()
v1_open = set(re.findall(r"soc.static: (\S+) (\S+):(\d+) -> open", log))
rep = json.load(open(st.SNAPSHOT.parent / "semgrep-results.json"))
tri = st.Triager()
out = Counter()
for r in rep["results"]:
    rid = r["check_id"].rsplit(".", 1)[-1]
    path = st.rel_path(r["path"], st.SNAPSHOT)
    start, end = r["start"]["line"], r["end"]["line"]
    if (rid, path, str(start)) not in v1_open:
        continue
    lines = st.read_lines(st.SNAPSHOT, path)
    fid = st.finding_id(rid, path, start, st.match_hash(lines, start, end))
    res, err = tri(fid, st.build_prompt(rid, r["extra"].get("message", ""), path, start,
                                        st.snippet(lines, start, end)))
    status, reason = st.decide_status(res)
    out[status.value] += 1
    conf = res.confidence if res else None
    print(f"{rid:28s} {path}:{start} -> {status.value} ({reason.value}, conf={conf})", flush=True)
print("TOTAL v1 open:", len(v1_open), "-> v2:", dict(out), flush=True)
sys.exit(0)

"""
TRASARE per caz — ce a facut agentul, pas cu pas, ca sa se poata raspunde la
"de ce a gresit la cazul X".

Per apel de unealta: numele, argumentele (trunchiate), durata, cate randuri a
intors si ID-urile documentelor (index + _id). NICIODATA continutul documentelor:
ala se recupereaza din Elasticsearch dupa ID, daca e nevoie.
Per apel de model: rolul, tokenii, durata, ce unelte a cerut.

Colectorul e legat de caz printr-un ContextVar: orchestratorul deschide un caz,
uneltele si nodurile de model scriu in el. Fara caz deschis (ex. in harness),
inregistrarea nu face nimic.

Urma e artefact de audit: poate contine text liber (argumentele alese de model),
dar nu alimenteaza niciodata o actiune. Din ea, codul extrage doar EvidenceRef-uri.
"""

from __future__ import annotations

import contextvars
import functools
import json
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable

from schemas import EvidenceRef

MAX_EVENTS = 200
MAX_REFS_PER_CALL = 50
MAX_ARGS_CHARS = 500

_current: contextvars.ContextVar["CaseTrace | None"] = contextvars.ContextVar("case_trace", default=None)


class CaseTrace:
    def __init__(self):
        self.events: list[dict] = []
        self.started = time.monotonic()

    def _add(self, ev: dict) -> None:
        if len(self.events) < MAX_EVENTS:
            self.events.append(ev)

    def refs(self) -> list[EvidenceRef]:
        """EvidenceRef-uri unice, in ordinea in care au aparut, cel mult 50
        (limita din Verdict)."""
        seen, out = set(), []
        for ev in self.events:
            for r in ev.get("doc_refs") or []:
                key = (r["index"], r["id"])
                if key in seen or not r.get("timestamp"):
                    continue
                seen.add(key)
                try:
                    out.append(EvidenceRef(index=r["index"], doc_id=r["id"],
                                           timestamp=datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00")),
                                           field_path=r.get("field")))
                except (ValueError, TypeError):
                    continue
                if len(out) >= 50:
                    return out
        return out

    def totals(self) -> dict:
        tools = [e for e in self.events if e["type"] == "tool"]
        llms = [e for e in self.events if e["type"] == "llm"]
        return {"tool_calls": len(tools), "tool_errors": sum(1 for e in tools if e.get("error")),
                "llm_calls": len(llms), "tokens": sum(e.get("tokens") or 0 for e in llms),
                "doc_refs": sum(len(e.get("doc_refs") or []) for e in tools),
                "duration_ms": int((time.monotonic() - self.started) * 1000)}

    def document(self, **meta) -> dict:
        """Documentul pentru soc-traces."""
        return {**meta, "@timestamp": datetime.now(timezone.utc).isoformat(),
                "events": self.events, "totals": self.totals()}


@contextmanager
def case():
    """Deschide un caz: tot ce se inregistreaza pana la iesire ajunge in el."""
    tr = CaseTrace()
    token = _current.set(tr)
    try:
        yield tr
    finally:
        _current.reset(token)


def current() -> CaseTrace | None:
    return _current.get()


def _args_text(args: dict) -> str:
    try:
        s = json.dumps(args, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        s = repr(args)
    return s[:MAX_ARGS_CHARS]


def extract_refs(result: Any) -> tuple[Any, list[dict], int | None]:
    """
    Scoate _id/_index din randurile intoarse de o unealta.
    Intoarce (rezultatul curatat pentru model, referintele, numarul de randuri).
    Modelul primeste exact ce primea inainte de trasare; ID-urile raman in urma.
    """
    if not isinstance(result, dict):
        return result, [], None
    refs: list[dict] = []
    out = dict(result)
    if isinstance(out.get("rows"), list):
        clean = []
        for row in out["rows"]:
            if isinstance(row, dict) and "_id" in row:
                row = dict(row)
                _id, _idx = row.pop("_id"), row.pop("_index", None)
                if _id and _idx and len(refs) < MAX_REFS_PER_CALL:
                    refs.append({"index": _idx, "id": _id, "timestamp": row.get("@timestamp")})
            clean.append(row)
        out["rows"] = clean
        return out, refs, len(clean)
    if isinstance(out.get("events"), list):   # EQL: hits cu _id/_index/_source
        for h in out["events"][:MAX_REFS_PER_CALL]:
            if isinstance(h, dict) and h.get("_id") and h.get("_index"):
                refs.append({"index": h["_index"], "id": h["_id"],
                             "timestamp": (h.get("_source") or {}).get("@timestamp")})
        return out, refs, len(out["events"])
    return out, refs, None


def traced_tool(name: str, fn: Callable[..., Any]) -> Callable[..., Any]:
    """Infasoara corpul unei unelte. Exceptiile trec mai departe (ToolNode le
    transforma in mesaj pentru model), dar raman in urma."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        tr = _current.get()
        t0 = time.monotonic()
        ev = {"type": "tool", "name": name, "args": _args_text(kwargs or {"_pos": list(args)})}
        try:
            result = fn(*args, **kwargs)
        except Exception as e:
            if tr is not None:
                tr._add({**ev, "duration_ms": int((time.monotonic() - t0) * 1000),
                         "error": type(e).__name__, "doc_refs": [], "rows": None})
            raise
        clean, refs, n = extract_refs(result)
        if tr is not None:
            tr._add({**ev, "duration_ms": int((time.monotonic() - t0) * 1000),
                     "error": None, "doc_refs": refs, "rows": n})
        return clean
    return wrapper


def record_llm(role: str, tokens: int | None, duration_ms: int, tool_calls: list[str] | None = None) -> None:
    tr = _current.get()
    if tr is not None:
        tr._add({"type": "llm", "role": role, "tokens": tokens or 0,
                 "duration_ms": duration_ms, "tool_calls": tool_calls or []})

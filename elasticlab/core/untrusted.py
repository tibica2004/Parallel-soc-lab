"""Delimitarea continutului din telemetrie (principiul 10), comuna Tier 1 si Tier 2.

Faza 24 (Arcanna): mutata NESCHIMBATA din tier1/l1_agent.py, ca tier2.hunt_path sa nu mai importe
din tier1 (incalcarea listata in docs/faza-24-importuri.md). l1_agent o reexporta sub aceleasi nume.
"""
from __future__ import annotations

import json
import re

MAX_RESULT_CHARS = 3000
UNTRUSTED_OPEN = "<<<TELEMETRIE_NEINCREZATOARE"
UNTRUSTED_CLOSE = "TELEMETRIE_NEINCREZATOARE>>>"


# Pasul 6.1 (masurat 2026-11-02): un text in engleza adaugat in command_line a mutat verdictul
# Tier 1 de la malicious la suspicious (3/3 repetari). Campurile text din telemetrie ajung acum
# la model DOAR in interiorul delimitatorilor, cu delimitatorii falsi scosi din valori.
EXEC_TEXT_FIELDS = ("user", "process", "parent", "executable", "command_line", "sudo_invoked_by")
_FAKE_DELIMS = re.compile(r"(<<<|>>>|TELEMETRIE_NEINCREZATOARE|</?\s*untrusted[_ a-z]*>)", re.IGNORECASE)


def strip_delimiters(v):
    """Scoate din valorile de telemetrie orice imita delimitatorii (un atacator nu poate inchide
    blocul neincrezator ca sa para instructiune de sistem)."""
    return _FAKE_DELIMS.sub("[delimitator eliminat]", v) if isinstance(v, str) else v


# Tier 2 (hunt_path.execution_facts) numeste altfel campurile text din telemetrie.
HUNT_EXEC_TEXT_FIELDS = ("ran_as_user", "executable", "working_directory", "command_line",
                         "sudo_invoked_by", "parent", "process")


def wrap_execution(ex: dict, fields: tuple[str, ...] = EXEC_TEXT_FIELDS) -> dict:
    """execution pentru model: entity_id ramane in clar (uneltele il cer exact si e validat cu
    ENTITY_ID_RE); textul din telemetrie trece ca bloc neincrezator."""
    out = {k: v for k, v in (ex or {}).items() if k not in fields}
    text = {k: strip_delimiters((ex or {}).get(k)) for k in fields if k in (ex or {})}
    out["telemetrie_neincrezatoare"] = wrap_untrusted(text)
    return out


def wrap_untrusted(result) -> str:
    """Rezultatul unei unelte, delimitat si marcat ca date, nu instructiuni."""
    body = json.dumps(result, ensure_ascii=False, default=str)[:MAX_RESULT_CHARS]
    return f"{UNTRUSTED_OPEN}\n{body}\n{UNTRUSTED_CLOSE}"



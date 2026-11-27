"""Faza 24: inlocuirea unui modul cu un fals in teste, pe numele vechi SI pe cel nou.

Modulele mutate in elasticlab/ importa intre ele pe calea noua (`from elasticlab.tier1.fast_path
import build_fast_path`), deci un fals pus doar in sys.modules["fast_path"] nu mai ajunge la ele.
swap_module il pune sub ambele nume si ca atribut al pachetului parinte (pentru
`from elasticlab.tier1 import fast_path`); monkeypatch le reface pe toate la sfarsitul testului."""
from __future__ import annotations

import importlib
import sys

from elasticlab._compat import MOVED


def swap_module(monkeypatch, old: str, fake: object) -> None:
    monkeypatch.setitem(sys.modules, old, fake)
    new = MOVED.get(old)
    if new is None:
        return
    monkeypatch.setitem(sys.modules, new, fake)
    parent, _, child = new.rpartition(".")
    monkeypatch.setattr(importlib.import_module(parent), child, fake, raising=False)

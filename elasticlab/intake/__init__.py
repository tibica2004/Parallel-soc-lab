"""Intrarea (faza 26): citire fara pierderi, normalizare, grupare, potop, clase critice.

Interfata publica (ce folosesc celelalte module):
  - adapter.read_window / adapter.normalize / adapter.next_cursor
  - grouping.plan_cycle -> PlanCiclu (cazuri, incidente de potop, alerte critice, contabilitate)
  - critical.notify_critical (trimiterea se injecteaza)

Depinde doar de contracts, core, store si de doua predicate pure din tier1 (sensor_rules,
defend_native). NU importa tier2, tier3, apps, bus, ops, eval, extras (.importlinter).
"""

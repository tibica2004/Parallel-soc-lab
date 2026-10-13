"""Gruparea in incidente: functii pure, fara ES si fara model."""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

import incidents as I

T0 = datetime(2026, 10, 13, 10, 0, tzinfo=timezone.utc)


def m(chain, minutes, lineage=(), host="web-prod", cls="suspicious", rules=("R",), tech=()):
    return I.Member(chain_id=f"chain-{chain:04d}", host=host, ts=T0 + timedelta(minutes=minutes),
                    verdict_ids=(f"v{chain}",), rules=tuple(rules), classification=cls,
                    techniques=tuple(tech), lineage=frozenset(lineage))


def chains(groups):
    return [[x.chain_id[-2:] for x in g] for g, _ in groups]


# ---------------- timp ----------------

def test_lant_in_timp_un_incident():
    g = I.cluster([m(1, 0), m(2, 20), m(3, 45)])
    assert chains(g) == [["01", "02", "03"]]
    assert g[0][1] == {I.LinkKind.TIME}


def test_pauza_mare_desparte():
    g = I.cluster([m(1, 0), m(2, 10), m(3, 100), m(4, 110)])
    assert chains(g) == [["01", "02"], ["03", "04"]]


def test_membru_singur_nu_e_incident():
    assert I.cluster([m(1, 0), m(2, 100)]) == []


def test_plafonul_de_6_ore():
    ms = [m(i, i * 25) for i in range(1, 20)]          # pauze de 25 min, 7.5 h in total
    g = I.cluster(ms)
    assert len(g) == 2
    assert all(gg[-1].ts - gg[0].ts <= timedelta(hours=I.SPAN_H) for gg, _ in g)


def test_hosturi_diferite_nu_se_unesc():
    g = I.cluster([m(1, 0, host="a"), m(2, 5, host="b"), m(3, 6, host="a"), m(4, 7, host="b")])
    assert sorted(chains(g)) == [["01", "03"], ["02", "04"]]


# ---------------- stramosi ----------------

def test_stramos_specific_uneste_peste_pauza():
    ms = [m(1, 0, {"atk1"}), m(2, 10, {"x"}), m(3, 200, {"atk1", "y"}), m(4, 210, {"z"}),
          m(5, 600, {"q"}), m(6, 610, {"w"})]
    g = I.cluster(ms)
    assert chains(g) == [["01", "02", "03", "04"], ["05", "06"]]
    assert g[0][1] == {I.LinkKind.TIME, I.LinkKind.ANCESTRY}


def test_stramos_peste_24h_nu_uneste():
    ms = [m(1, 0, {"atk"}), m(2, 5), m(3, 26 * 60, {"atk"}), m(4, 26 * 60 + 5)]
    assert len(I.cluster(ms)) == 2


def test_stramos_comun_la_majoritate_nu_uneste():
    # "svc" apare la 4 din 6 membri (>50%) -> radacina comuna
    ms = [m(1, 0, {"svc"}), m(2, 5, {"svc"}), m(3, 200, {"svc"}), m(4, 205, {"svc"}),
          m(5, 400), m(6, 405)]
    assert I.common_roots(ms) == {"svc"}
    assert len(I.cluster(ms)) == 3


def test_procesele_de_serviciu_nu_unesc():
    ms = [m(1, 0, {"apache-master"}), m(2, 5), m(3, 200, {"apache-master"}), m(4, 205),
          m(5, 400), m(6, 405), m(7, 600), m(8, 605)]
    assert len(I.cluster(ms)) == 3                                 # 2/8 -> nu e comun ca frecventa...
    assert len(I.cluster(ms, generic={"apache-master"})) == 4      # ...dar e serviciu dupa nume


def test_generic_ids_dupa_nume():
    assert I.generic_ids({"a": "apache2", "b": "dash", "c": "systemd", "d": "sshd-session"}) == {"a", "c"}


def test_determinist():
    ms = [m(i, i * 7, {f"l{i % 3}"}) for i in range(1, 12)]
    assert chains(I.cluster(ms)) == chains(I.cluster(list(reversed(ms))))


# ---------------- membri din verdicte ----------------

def V(chain, cls, ts="2026-10-13T10:00:00Z", doc="docAAAAAAAA", rule="RCE", _id=None, tech=("T1059",)):
    return {"_id": _id or f"id-{chain}-{cls}", "chain_id": chain, "entity_type": "host", "entity_id": "web-prod",
            "classification": cls, "rule_name": rule, "mitre_techniques": list(tech), "@timestamp": ts,
            "evidence_refs": [{"doc_id": doc, "timestamp": ts}]}


def test_membri_un_lant_tier1_tier2():
    alerts = {"docAAAAAAAA": {"process": {"entity_id": "eeeeAAAA", "parent": {"entity_id": "ppppAAAA"},
                                          "Ext": {"ancestry": ["ppppAAAA", "rootAAAA", "bad id!"]},
                                          "name": "dash", "command_line": "sh -c id"}}}
    ms = I.members_from([V("chain-0001", "suspicious"), V("chain-0001", "malicious", _id="t2")], alerts)
    assert len(ms) == 1
    assert ms[0].classification == "malicious"
    assert ms[0].verdict_ids == ("id-chain-0001-suspicious", "t2")
    assert ms[0].lineage == frozenset({"eeeeAAAA", "ppppAAAA", "rootAAAA"})   # id-ul invalid sarit
    assert ms[0].process["process"] == "dash"


def test_lant_inchis_benign_nu_intra():
    assert I.members_from([V("chain-0002", "benign")], {}) == []


def test_lant_cu_chain_id_invalid_sarit():
    assert I.members_from([V("x y", "malicious")], {}) == []


def test_timpul_membrului_e_al_dovezii():
    ms = I.members_from([V("chain-0003", "suspicious", ts="2026-10-13T09:00:00Z")], {})
    assert ms[0].ts == datetime(2026, 10, 13, 9, 0, tzinfo=timezone.utc)


# ---------------- incident si reconciliere ----------------

def test_incident_construit():
    inc = I.build_incident([m(1, 0, tech=("T1059",)), m(2, 5, cls="malicious", rules=("B", "A"))],
                           {I.LinkKind.TIME})
    assert inc.status is I.IncidentStatus.OPEN
    assert inc.max_classification == "malicious"
    assert inc.rules == ["A", "B", "R"]
    assert inc.incident_id == I.incident_id("web-prod", "chain-0001")
    assert len(inc.incident_id) == 32


def test_incident_refuza_campuri_straine():
    inc = I.build_incident([m(1, 0), m(2, 5)], {I.LinkKind.TIME})
    with pytest.raises(ValidationError):
        I.Incident(**inc.model_dump(), sters=True)
    with pytest.raises(ValidationError):
        I.Incident(**{**inc.model_dump(), "chain_ids": ["chain-0001"]})       # sub minim


def _existing(inc, status="open", **over):
    return {**inc.model_dump(mode="json"), "status": status, "_seq_no": 1, "_primary_term": 1, **over}


def test_reconciliere_uneste_cu_incident_deschis():
    old = I.build_incident([m(1, 0), m(2, 5)], {I.LinkKind.TIME})
    new = I.build_incident([m(2, 5), m(3, 10)], {I.LinkKind.TIME})
    out = I.reconcile([new], [_existing(old)])
    assert len(out) == 1
    assert out[0].incident_id == old.incident_id
    assert out[0].chain_ids == ["chain-0001", "chain-0002", "chain-0003"]   # membrii doar se adauga


def test_reconciliere_nu_atinge_incident_inchis():
    old = I.build_incident([m(1, 0), m(2, 5)], {I.LinkKind.TIME})
    new = I.build_incident([m(1, 0), m(2, 5), m(3, 10)], {I.LinkKind.TIME})
    assert I.reconcile([new], [_existing(old, status="closed")]) == []      # ramane 1 lant nou: sub minim
    new2 = I.build_incident([m(1, 0), m(2, 5), m(3, 10), m(4, 12)], {I.LinkKind.TIME})
    out = I.reconcile([new2], [_existing(old, status="closed")])
    assert len(out) == 1 and out[0].incident_id != old.incident_id
    assert out[0].chain_ids == ["chain-0003", "chain-0004"]
    assert out[0].status is I.IncidentStatus.OPEN


def test_reconciliere_nu_inchide_niciodata():
    old = I.build_incident([m(1, 0), m(2, 5)], {I.LinkKind.TIME})
    out = I.reconcile([old], [_existing(old)])
    assert all(x.status is I.IncidentStatus.OPEN for x in out)


def test_lanturile_inchise_scoase_inainte_de_grupare():
    old = I.build_incident([m(1, 0), m(2, 5)], {I.LinkKind.TIME})
    ms = I.without_closed([m(1, 0), m(2, 5), m(3, 10)], [_existing(old, status="closed")])
    assert [x.chain_id for x in ms] == ["chain-0003"]


def test_id_de_incident_inchis_nu_iese_niciodata():
    old = I.build_incident([m(1, 0), m(2, 5)], {I.LinkKind.TIME})
    clone = I.build_incident([m(1, 0), m(9, 5)], {I.LinkKind.TIME})   # alt lant, acelasi prim lant
    assert clone.incident_id == old.incident_id
    out = I.reconcile([clone], [_existing(old, status="closed", chain_ids=["chain-0002", "chain-0007"])])
    assert len(out) == 1 and out[0].incident_id != old.incident_id

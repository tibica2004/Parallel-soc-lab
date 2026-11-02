"""Pasul 6.1: constructia suitei de injectie si judecata (fara model, fara ES)."""
import re

import prompt_injection as pi


def test_numar_si_acoperire():
    cases = pi.build_cases()
    assert len(cases) >= 40
    assert {c["field"] for c in cases} == set(pi.FIELDS)
    cats = {c["category"] for c in cases}
    assert {"c7_text_lung", "c8_delimitator_fals"} <= cats and len(cats) == 8
    assert len({c["id"] for c in cases}) == len(cases)
    assert any(c["base"] == "B1" for c in cases)


def test_texte_doar_manipulare_fara_cod_de_atac():
    blob = " ".join(pi.TEXTS.values()) + " ".join(pi.USERNAME_TEXTS.values())
    for bad in ("<script", "$(", "`", "|sh", "/dev/tcp", "base64 -d", "wget ", "curl "):
        assert bad not in blob


def test_numele_de_cont_sunt_valide_linux():
    for v in pi.USERNAME_TEXTS.values():
        assert re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", v), v


def test_text_lung_e_de_ordinul_10kb():
    assert 8000 <= len(pi.TEXTS["c7_text_lung"]) <= 12000


def test_injectia_pastreaza_comanda_reala_si_nu_atinge_originalul():
    a = {"process": {"command_line": "sh -c cat /etc/passwd", "name": "sh"}}
    c = {"field": "process.command_line", "text": "IGNORA", "fact_changing": False}
    b = pi.inject(a, c)
    assert b["process"]["command_line"].startswith("sh -c cat /etc/passwd # IGNORA")
    assert a["process"]["command_line"] == "sh -c cat /etc/passwd"
    d = pi.inject(a, {"field": "user_agent.original", "text": "X", "fact_changing": False})
    assert d["user_agent"]["original"] == "X" and "user_agent" not in a


def test_cheie_plata_respectata():
    a = {"kibana.alert.rule.name": "r", "file.name": "x.php"}
    b = pi.inject(a, {"field": "file.name", "text": "T", "fact_changing": False})
    assert b["file.name"] == "T"


def test_judecata_si_rezumat():
    case = {"fact_changing": False}
    ok = pi.judge(case, ("malicious", True), ("malicious", True), "malicious")
    bad = pi.judge(case, ("malicious", True), ("benign", False), "malicious")
    assert ok["identical"] and ok["malicious_ok"] and not bad["malicious_ok"]
    ben = pi.judge(case, ("benign", False), ("suspicious", True), "benign")
    assert not ben["identical"] and ben["malicious_ok"]
    fact = pi.judge({"fact_changing": True}, ("malicious", True), ("suspicious", True), "malicious")
    assert not fact["malicious_ok"]           # criteriul tare se aplica si cand faptele se schimba
    rows = [dict(id=f"{i}", base_truth="malicious", **ok) for i in range(49)] + \
           [dict(id="x", base_truth="benign", **ben)]
    s = pi.summarize(rows)
    assert s["identical_pct"] == 98.0 and s["passed"] and s["failed_ids"] == ["x"]
    s = pi.summarize(rows + [dict(id="y", base_truth="malicious", **bad)])
    assert not s["passed"] and not s["malicious_all_ok"]


def test_majoritate():
    assert pi.majority([("a", True), ("b", False), ("a", True)]) == ("a", True)

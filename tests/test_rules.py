"""Propunerile de reguli Tier 3: functii pure, fara ES si fara model."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import rules as R

T0 = datetime(2026, 10, 15, 10, 0, tzinfo=timezone.utc)
CHAIN = "6dccbc7f-d2ef-4a6c-adb6-4e053199cf42"


def ev(parent="apache2", child="sh", args=("sh", "-c", "id"), exe="/usr/bin/dash", _id="evt00001"):
    return {"_id": _id, "@timestamp": T0.isoformat(), "event": {"type": ["start"]},
            "process": {"name": child, "parent": {"name": parent}, "args": list(args),
                        "executable": exe, "entity_id": "ENT1"}}


def draft(**kw):
    base = {"template": "parent_child", "parent": "apache2", "child": "sh", "technique": "T1505.003"}
    return R.RuleDraft.model_validate({**base, **kw})


# ---------------- granita Pydantic ----------------

def test_camp_in_plus_respins():
    with pytest.raises(ValidationError):
        draft(query='process where true')


def test_sablon_necunoscut_respins():
    with pytest.raises(ValidationError):
        draft(template="free_eql")


def test_campurile_trebuie_sa_se_potriveasca_sablonului():
    with pytest.raises(ValidationError):
        draft(arg="-c")                       # parent_child nu are arg
    with pytest.raises(ValidationError):
        R.RuleDraft.model_validate({"template": "exec_prefix", "technique": "T1059"})


@pytest.mark.parametrize("child", ['sh" or true or "', "sh\nx", "a b", "", "x" * 65])
def test_nume_de_proces_cu_injectie_respins(child):
    with pytest.raises(ValidationError):
        draft(child=child)


@pytest.mark.parametrize("arg", ['a"b', "a\\b", "a b", "x\x00"])
def test_argument_cu_ghilimele_sau_spatii_respins(arg):
    with pytest.raises(ValidationError):
        draft(template="parent_child_arg", arg=arg)


@pytest.mark.parametrize("d", ["/tmp", "tmp/", "/tmp/../etc/", "/usr/bin/", "/", "/a b/"])
def test_director_invalid_sau_prea_general(d):
    with pytest.raises(ValidationError):
        R.RuleDraft.model_validate({"template": "exec_prefix", "dir": d, "technique": "T1059"})


def test_tehnica_invalida_respinsa():
    with pytest.raises(ValidationError):
        draft(technique="Persistence")


# ---------------- EQL scris de cod ----------------

def test_render_parent_child():
    assert R.render_eql(draft()) == ('process where event.type == "start" and '
                                     'process.parent.name == "apache2" and process.name == "sh"')


def test_render_exec_prefix():
    d = R.RuleDraft.model_validate({"template": "exec_prefix", "dir": "/dev/shm/", "technique": "T1059"})
    assert R.render_eql(d).endswith('startsWith(process.executable, "/dev/shm/")')


def test_escapare_a_doua_plasa():
    assert R._q('a"b\\c') == '"a\\"b\\\\c"'


def test_rule_id_determinist():
    q = R.render_eql(draft())
    assert R.rule_id(q) == R.rule_id(q) and R.rule_id(q).startswith("t3-")
    assert R.rule_id(q) != R.rule_id(q + " ")


# ---------------- valorile vin din acelasi eveniment ----------------

def test_grounded_pereche_reala():
    assert R.grounded(draft(), [ev()])


def test_grounded_respinge_valori_inventate():
    assert not R.grounded(draft(child="python3"), [ev()])


def test_grounded_nu_amesteca_evenimente():
    # parintele dintr-un eveniment, copilul din altul: nu e o pereche reala
    assert not R.grounded(draft(parent="apache2", child="curl"),
                          [ev(parent="apache2", child="sh"), ev(parent="bash", child="curl")])


def test_grounded_argument_si_director():
    assert R.grounded(draft(template="parent_child_arg", arg="id"), [ev()])
    assert not R.grounded(draft(template="parent_child_arg", arg="whoami"), [ev()])
    d = R.RuleDraft.model_validate({"template": "exec_prefix", "dir": "/tmp/x/", "technique": "T1059"})
    assert R.grounded(d, [ev(exe="/tmp/x/payload")])
    assert not R.grounded(d, [ev(exe="/tmp/xy/payload")])


# ---------------- gap_detect ----------------

def test_surse_de_gol():
    assert R.gap_source({"label_source": "human", "ground_truth": "attack"}) is R.GapSource.HUMAN
    assert R.gap_source({"source_path": "hunt", "classification": "malicious",
                         "corroboration_status": "agreement"}) is R.GapSource.TIER2_CORROBORATED
    # fara acordul lui B, sau etichetat benign de om: nu e sursa
    assert R.gap_source({"source_path": "hunt", "classification": "malicious",
                         "corroboration_status": "not_required"}) is None
    assert R.gap_source({"label_source": "human", "ground_truth": "benign",
                         "source_path": "hunt", "classification": "suspicious"}) is None


def _v(refs=()):
    return {"chain_id": CHAIN, "evidence_refs": [{"index": i, "doc_id": "x" * 10} for i in refs]}


def test_gol_real():
    assert R.gap_reason(_v([".ds-logs-endpoint.events.process-default"]), set(), 0, 1) is None


def test_nu_e_gol_cand_exista_alerta():
    assert "Tier 1" in R.gap_reason(_v(), {CHAIN}, 0, 1)
    assert "alerta" in R.gap_reason(_v([".internal.alerts-security.alerts-default-000001"]), set(), 0, 1)
    assert "regula" in R.gap_reason(_v(), set(), 2, 1)
    assert "fara evenimente" in R.gap_reason(_v(), set(), 0, 0)


# ---------------- shadow si promovare ----------------

def st(hour=0, total=0, days=1.0, fp=0):
    return R.ShadowStats(alerts_last_hour=hour, alerts_total=total, days_in_status=days, human_fp=fp)


def test_shadow_ramane_inainte_de_7_zile():
    assert R.next_status(R.RuleStatus.SHADOW, st(days=3, total=2))[0] is R.RuleStatus.SHADOW


def test_promovare_dupa_7_zile_linistite():
    assert R.next_status(R.RuleStatus.SHADOW, st(days=7, total=14))[0] is R.RuleStatus.PROMOTED


def test_oprire_la_zgomot_pe_zi():
    assert R.next_status(R.RuleStatus.SHADOW, st(days=7, total=22))[0] is R.RuleStatus.DISABLED


def test_oprire_la_fp_uman():
    assert R.next_status(R.RuleStatus.SHADOW, st(days=8, total=1, fp=1))[0] is R.RuleStatus.DISABLED


def test_auto_oprire_intr_o_ora_si_in_productie():
    for s in (R.RuleStatus.SHADOW, R.RuleStatus.PROMOTED):
        assert R.next_status(s, st(hour=21))[0] is R.RuleStatus.DISABLED
    assert R.next_status(R.RuleStatus.SHADOW, st(hour=20))[0] is R.RuleStatus.SHADOW


def test_buton_de_oprire_globala():
    for s in (R.RuleStatus.SHADOW, R.RuleStatus.PROMOTED):
        assert R.next_status(s, st(), kill_switch=True)[0] is R.RuleStatus.DISABLED


def test_regula_oprita_nu_reporneste_singura():
    assert R.next_status(R.RuleStatus.DISABLED, st(days=30))[0] is R.RuleStatus.DISABLED


# ---------------- payload Kibana ----------------

def prop(status=R.RuleStatus.PROPOSED, source=R.GapSource.TIER2_CORROBORATED):
    d = draft()
    q = R.render_eql(d)
    return R.RuleProposal(rule_id=R.rule_id(q), created_at=T0, gap_source=source, chain_id=CHAIN,
                          host="web-prod", case_event_ids=["evt00001"], case_time=T0, draft=d, eql=q,
                          status=status)


def test_payload_shadow():
    p = R.kibana_payload(prop())
    assert R.TAG in p["tags"] and R.SHADOW_TAG in p["tags"] and "gap:tier2_corroborated" in p["tags"]
    assert p["severity"] == "low" and p["type"] == "eql" and p["rule_id"].startswith("t3-")
    assert "exceptions_list" not in p          # Tier 3 nu scrie exceptii
    # numele regulii nu contine valori din telemetrie
    assert "apache2" not in p["name"] and "apache2" in p["query"]


def test_payload_promovat_fara_eticheta_shadow():
    p = R.kibana_payload(prop(), promoted=True)
    assert R.SHADOW_TAG not in p["tags"] and R.TAG in p["tags"] and p["severity"] == "medium"


def test_propunerea_respinge_campuri_in_plus():
    with pytest.raises(ValidationError):
        R.RuleProposal.model_validate({**prop().model_dump(), "exceptions": ["x"]})


# ---------------- bucla draft -> validare (model si ES falsi) ----------------

class FakeLLM:
    def __init__(self, answers):
        self.answers, self.prompts = list(answers), []

    def invoke(self, msgs):
        self.prompts.append(msgs[-1].content)
        return SimpleNamespace(content=self.answers.pop(0))


def _propose(monkeypatch, answers, val):
    import tier3
    monkeypatch.setattr(R, "validate", lambda es, eql, host, ids, t, now: val(eql))
    llm = FakeLLM(answers)
    v = {"chain_id": CHAIN, "entity_id": "web-prod"}
    return tier3.propose(v, R.GapSource.TIER2_CORROBORATED, [ev()], T0, llm=llm), llm


OK = '{"template":"parent_child","parent":"apache2","child":"sh","arg":null,"dir":null,"technique":"T1505.003","rationale":"x"}'


def test_propunere_acceptata_la_prima(monkeypatch):
    p, _ = _propose(monkeypatch, [OK], lambda q: R.Validation(syntax_ok=True, catches=True, noise_hits=0, noise_ok=True))
    assert p.status is R.RuleStatus.PROPOSED and p.attempts == 1 and p.eql.startswith("process where")


def test_reincercare_cu_eroarea_apoi_respinsa(monkeypatch):
    bad = '{"template":"parent_child","parent":"apache2","child":"python3","technique":"T1059"}'
    noisy = lambda q: R.Validation(syntax_ok=True, catches=True, noise_hits=6, noise_ok=False, error="zgomotoasa")
    p, llm = _propose(monkeypatch, ["nu e json", bad, OK], noisy)
    assert p.status is R.RuleStatus.REJECTED and p.attempts == R.MAX_DRAFT_RETRIES + 1
    assert len(llm.prompts) == 3 and "respinsa" in llm.prompts[1] and "acelasi eveniment" in llm.prompts[2]
    # draft, EQL si validarea raman din aceeasi incercare
    assert p.draft.child == "sh" and '"sh"' in p.eql and p.validation.noise_hits == 6


def test_injectie_in_telemetrie_nu_ajunge_in_regula(monkeypatch):
    # modelul "convins" de telemetrie propune o valoare cu operatori EQL
    evil = '{"template":"parent_child","parent":"apache2","child":"sh\\" or true or \\"","technique":"T1059"}'
    p, _ = _propose(monkeypatch, [evil] * 3, lambda q: pytest.fail("nu trebuia validat"))
    assert p.status is R.RuleStatus.REJECTED and p.eql is None


# ---------------- dovezile sweep-ului (orchestrator) ----------------

def test_sweep_ataseaza_evenimentele_perechii(monkeypatch):
    import elastic_tools
    import orchestrator
    from schemas import EntityType, RarityFinding
    calls = []
    monkeypatch.setattr(elastic_tools, "pair_event_refs",
                        lambda h, p, c, window_hours: calls.append((h, p, c)) or ["ref"])
    f = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                      detail={"parent": "apache2", "child": "sh", "count": 1}, rarity_score=1.0)
    assert orchestrator.finding_pair_refs(f) == ["ref"] and calls == [("web-prod", "apache2", "sh")]


def test_sweep_fara_dovezi_nu_opreste(monkeypatch):
    import elastic_tools
    import orchestrator
    from schemas import EntityType, RarityFinding

    def boom(*a, **k):
        raise ConnectionError("es cazut")
    monkeypatch.setattr(elastic_tools, "pair_event_refs", boom)
    f = RarityFinding(kind="new_parent_child", entity_type=EntityType.HOST, entity_id="web-prod",
                      detail={"parent": "apache2", "child": "sh", "count": 1}, rarity_score=1.0)
    assert orchestrator.finding_pair_refs(f) == []


# ---------------- sablonul arg_prefix ----------------

def ap(dir_="/home/tiberiu/.cache/.kw/", **kw):
    return R.RuleDraft.model_validate({"template": "arg_prefix", "parent": "bash", "child": "dash",
                                       "dir": dir_, "technique": "T1059.004", **kw})


SCRIPT = dict(parent="bash", child="dash", args=("/bin/sh", "/home/tiberiu/.cache/.kw/kthreadd-0734"))


def test_arg_prefix_render():
    assert R.render_eql(ap()) == ('process where event.type == "start" and process.parent.name == "bash" '
                                  'and process.name == "dash" and startsWith(process.args, "/home/tiberiu/.cache/.kw/")')


def test_arg_prefix_cere_parinte_copil_si_director():
    with pytest.raises(ValidationError):
        R.RuleDraft.model_validate({"template": "arg_prefix", "dir": "/home/x/", "technique": "T1059"})
    with pytest.raises(ValidationError):
        ap(arg="x")


def test_arg_prefix_grounded():
    assert R.grounded(ap(), [ev(**SCRIPT)])
    assert not R.grounded(ap("/home/tiberiu/.cache/.kx/"), [ev(**SCRIPT)])
    # prefixul de director nu se potriveste pe jumatate de nume: .kw/ nu e .kwx/
    assert not R.grounded(ap(), [ev(parent="bash", child="dash", args=("/bin/sh", "/home/tiberiu/.cache/.kwx/a"))])
    # perechea parinte-copil trebuie sa fie tot din acelasi eveniment
    assert not R.grounded(ap(), [ev(parent="sshd-session", child="dash", args=SCRIPT["args"])])


@pytest.mark.parametrize("d", ["/home/", "/var/", "/etc/", "/root/"])
def test_arg_prefix_director_prea_general(d):
    with pytest.raises(ValidationError):
        ap(d)


# ---------------- rularile programate: registrul lanturilor procesate ----------------

def test_registru_lipsa_sau_stricat_inseamna_gol(tmp_path):
    import tier3
    assert tier3.load_done(tmp_path / "nu-exista.json") == set()
    (tmp_path / "r.json").write_text("{stricat")
    assert tier3.load_done(tmp_path / "r.json") == set()


def test_registru_dus_intors(tmp_path):
    import tier3
    tier3.save_done(tmp_path / "r.json", {CHAIN})
    assert tier3.load_done(tmp_path / "r.json") == {CHAIN}


def test_lant_procesat_nu_mai_ajunge_la_model(monkeypatch):
    import tier3
    v = {"chain_id": CHAIN, "entity_id": "web-prod", "label_source": "human", "ground_truth": "attack"}
    monkeypatch.setattr(R, "fetch_candidates", lambda es, a, b: [v])
    monkeypatch.setattr(R, "tier1_chains", lambda es, ids: set())
    monkeypatch.setattr(R, "fetch_events", lambda es, ids: pytest.fail("lant deja procesat"))
    monkeypatch.setattr(tier3, "propose", lambda *a, **k: pytest.fail("lant deja procesat"))
    assert tier3.run_rules(24, skip={CHAIN}) == []


def test_iesire_in_afara_proiectului_refuzata(monkeypatch, capsys):
    import sys
    import tier3
    monkeypatch.setattr(sys, "argv", ["tier3.py", "--once", "--reguli", "--iesire", "../../tmp"])
    assert tier3.main() == 1 and "directorul proiectului" in capsys.readouterr().out


# ---------------- tehnica ATT&CK: doar Linux ----------------

@pytest.mark.parametrize("t", ["T1059.003", "T1059.001", "T1547.001", "T1053.005", "T1003.001", "T9999"])
def test_tehnica_windows_sau_inexistenta_respinsa(t):
    # T1059.003 e cazul real (t3-ad858a1ca85a29c7): Windows Command Shell pe un atac Linux
    with pytest.raises(ValidationError) as e:
        draft(technique=t)
    assert "Linux" in str(e.value) and "T1059.004" in str(e.value)   # modelul afla din ce sa aleaga


@pytest.mark.parametrize("t", ["T1059.004", "T1036.005", "T1505.003", "T1105", "T1059"])
def test_tehnica_linux_acceptata(t):
    assert draft(technique=t).technique == t


def test_lista_linux_are_forma_valida():
    from schemas import MITRE_RE
    assert all(MITRE_RE.match(t) for t in R.LINUX_TECHNIQUES)
    assert "T1059.003" not in R.LINUX_TECHNIQUES


def test_promptul_cere_tehnica_linux():
    assert "Linux" in R.DRAFT_PROMPT and "Windows" in R.DRAFT_PROMPT

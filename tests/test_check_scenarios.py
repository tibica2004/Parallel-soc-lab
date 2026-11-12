"""Validatorul setului de ablatie: functie pura, fara ES si fara model."""
import check_scenarios as C

R = {"RCE: Web server spawns shell"}


def sc(**kw):
    base = {"name": "s1", "path": "fast", "ground_truth": "attack",
            "rule_name": "RCE: Web server spawns shell", "generate": "curl -s http://localhost/x"}
    base.update(kw)
    return base


def test_setul_real_trece():
    import yaml
    data = yaml.safe_load((C.ROOT / "scenarios_ablation.yml").read_text(encoding="utf-8"))
    rag = C.RAG_FILE.read_text(encoding="utf-8")
    errors, _, summ = C.check(data, C.KNOWN_RULES, rag)
    assert errors == [] and summ["total"] == 18


def test_structura_gresita():
    assert C.check({"x": 1}, R)[0]
    assert C.check([], R)[0]


def test_campuri_lipsa_si_necunoscute():
    s = sc(extra=1)
    del s["generate"]
    errors = C.check({"scenarios": [s]}, R)[0]
    assert any("lipseste `generate`" in e for e in errors)
    assert any("camp necunoscut `extra`" in e for e in errors)


def test_valori_invalide():
    errors = C.check({"scenarios": [sc(path="slow", ground_truth="maybe", rule_name="X",
                                       injection="da", generate="a\nb")]}, R)[0]
    assert len(errors) == 5


def test_nume_duplicat_eroare_comanda_repetata_avertisment():
    e, w, _ = C.check({"scenarios": [sc(), sc(), sc(name="s2")]}, R)
    assert any("apare de 2 ori" in x for x in e)
    assert any("repetata de 3 ori" in x for x in w)


def test_separarea_de_rag():
    e = C.check({"scenarios": [sc()]}, R, rag_text="... CURL -S http://localhost/x ...")[0]
    assert any("rag_cases" in x for x in e)


def test_echilibru_si_injectie():
    _, w, summ = C.check({"scenarios": [sc(), sc(name="s2", injection=True)]}, R)
    assert summ["attack"] == 1 and summ["injection"] == 1 and summ["benign"] == 0
    assert any("niciun scenariu benign" in x for x in w)


# --- faza 22 I: valori ramase de pe vechiul web-prod -------------------------------------

def test_find_stale_gaseste_markerii_pe_orice_schema():
    data = {"scenarios": [
        {"name": "a", "finding": {"detail": {"parent": "bash", "child": "php8.4"}}},
        {"name": "b", "generate": "curl http://172.20.99.240/x", "detail": {"child": "python3"}},
        {"name": "c", "finding": {"detail": {"child": "python3.13"}}},
    ]}
    hits = C.find_stale(data)
    assert len(hits) == 3
    assert any("scenarios[0].finding.detail.child" in h and "php8.4" in h for h in hits)
    assert any("scenarios[1].generate" in h and "172.20.99." in h for h in hits)
    assert any("scenarios[2]" in h and "python3.13" in h for h in hits)
    assert C.find_stale({"x": ["php8.3", "python3", 1, None]}) == []


def test_check_avertizeaza_la_marker_invechit():
    s = dict(name="s", path="fast", ground_truth="attack", rule_name=next(iter(C.KNOWN_RULES)),
             generate="sudo -u www-data php8.4 -r 'echo 1;'")
    _, warns, _ = C.check({"scenarios": [s]}, set(C.KNOWN_RULES))
    assert any("invechita" in w and "php8.4" in w for w in warns)

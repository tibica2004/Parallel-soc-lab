"""Faza 24: regula de importuri a monolitului modular, verificata automat (fara import-linter, pe
AST, inclusiv importurile lenese din functii), si regula scriitorului unic."""
import ast
import re
from pathlib import Path

from elasticlab.paths import REPO_ROOT

PKG = REPO_ROOT / "elasticlab"
NEUTRAL = {"paths", "_compat", ""}          # module de infrastructura, fara logica
LAYERS = {"contracts", "core", "bus", "store", "intake", "tier1", "tier2", "tier3", "ops", "extras",
          "eval", "apps"}
# Ce are voie sa importe fiecare strat (pe langa el insusi si modulele neutre).
ALLOWED = {
    "contracts": set(),
    "core": {"contracts"},
    "bus": {"contracts"},
    "store": {"contracts", "core"},
    "tier1": {"contracts", "core", "store"},
    "tier2": {"contracts", "core", "store"},
    "intake": {"contracts", "core", "store", "tier1"},
    "tier3": LAYERS - {"apps", "intake"},
    "ops": LAYERS - {"apps", "intake"},
    "extras": LAYERS - {"apps", "intake"},
    "eval": LAYERS - {"apps"},
    "apps": LAYERS,
}
# Exceptii mostenite, LISTATE (docs/faza-24-importuri.md); lista nu are voie sa creasca.
LEGACY = {("elasticlab.tier3.tier3", "elasticlab.apps"),
          ("elasticlab.tier3.tier3", "elasticlab.apps.orchestrator")}
# intake: doar cele doua predicate din tier1 (faza 26)
INTAKE_TIER1 = {"elasticlab.tier1.sensor_rules", "elasticlab.tier1.defend_native", "elasticlab.tier1"}


def module_name(f: Path) -> str:
    parts = f.relative_to(REPO_ROOT).with_suffix("").parts
    name = ".".join(parts)
    return name[:-9] if name.endswith(".__init__") else name


def imports() -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for f in PKG.rglob("*.py"):
        mod = module_name(f)
        deps = set()
        for n in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(n, ast.ImportFrom) and n.module and n.module.startswith("elasticlab"):
                deps.add(n.module)
                if n.module.count(".") == 1:            # from elasticlab.tier1 import fast_path
                    deps.update(f"{n.module}.{a.name}" for a in n.names)
            elif isinstance(n, ast.Import):
                deps.update(a.name for a in n.names if a.name.startswith("elasticlab"))
        out[mod] = deps
    return out


def layer(mod: str) -> str:
    p = mod.split(".")
    return p[1] if len(p) > 1 else ""


def test_regula_de_importuri_intr_o_singura_directie():
    bad = []
    for src, deps in sorted(imports().items()):
        ls = layer(src)
        if ls in NEUTRAL:
            continue
        for d in sorted(deps):
            ld = layer(d)
            if ld in NEUTRAL or ld == ls or (src, d) in LEGACY:
                continue
            if ld not in ALLOWED[ls]:
                bad.append(f"{src} -> {d}")
            elif ls == "intake" and ld == "tier1" and d not in INTAKE_TIER1:
                bad.append(f"{src} -> {d} (intake: doar predicatele din tier1)")
    assert bad == []


def test_tier1_si_tier2_nu_se_importa_intre_ele():
    for src, deps in imports().items():
        if layer(src) == "tier1":
            assert not any(layer(d) == "tier2" for d in deps), src
        if layer(src) == "tier2":
            assert not any(layer(d) == "tier1" for d in deps), src


def test_doar_punctele_de_intrare_importa_apps_iar_exceptiile_nu_cresc():
    seen = {(s, d) for s, deps in imports().items() for d in deps
            if layer(d) == "apps" and layer(s) != "apps"}
    assert seen <= LEGACY


def test_modulele_noi_ale_fazei_24_sunt_stricte():
    deps = imports()
    strict = {
        "elasticlab.contracts.learning": set(),
        "elasticlab.core.decision_points": {"contracts", "core"},
        "elasticlab.core.buckets": {"contracts", "core"},
        "elasticlab.core.classifier": {"contracts", "core"},
        "elasticlab.core.cascade": {"contracts", "core"},
        "elasticlab.core.controller": {"contracts", "core"},
        "elasticlab.core.pipelines": {"contracts", "core"},
        "elasticlab.bus.base": {"contracts", "bus"},
        "elasticlab.bus.rabbitmq": {"contracts", "bus"},
        "elasticlab.store.writer": {"contracts", "core", "store"},
        "elasticlab.tier1.cascade": {"contracts", "core", "store", "tier1"},
    }
    for mod, ok in strict.items():
        got = {layer(d) for d in deps[mod]} - NEUTRAL
        assert got <= ok, (mod, got - ok)


# ---------------- scriitorul unic ----------------

WRITE_RE = re.compile(r"\.(index|update|create|bulk)\(\s*index\s*=\s*([A-Z_]+|\"[^\"]+\"|'[^']+')")
GUARDED = {"verdicts-history", "soc-audit", "soc-traces", "soc-cases", "soc-buckets"}


def test_un_singur_modul_scrie_verdicte_audit_urme_cazuri_grupuri():
    bad = []
    for f in PKG.rglob("*.py"):
        if f.name == "writer.py" and f.parent.name == "store":
            continue
        s = f.read_text(encoding="utf-8")
        consts = dict(re.findall(r"^([A-Z_]+)\s*=\s*\"([^\"]+)\"", s, re.M))
        for m in WRITE_RE.finditer(s):
            target = m.group(2).strip("\"'")
            target = consts.get(target, target)
            if target in GUARDED or target in ("INDEX",) and "soc-cases" in s:
                bad.append(f"{f.relative_to(REPO_ROOT)}:{s[:m.start()].count(chr(10)) + 1} -> {target}")
    assert bad == []


def test_fisierele_vechi_raman_ca_alias_si_executabile():
    for old in ("orchestrator.py", "tier3.py", "label_ui.py"):
        s = (REPO_ROOT / old).read_text()
        assert "alias(" in s and "run_main(" in s, old
    for old in ("fast_path.py", "hunt_path.py", "policy.py"):
        assert "alias(" in (REPO_ROOT / old).read_text(), old

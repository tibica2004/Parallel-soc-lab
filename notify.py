"""
NOTIFICARE UMANA — pointer scurt catre om, prin webhook Discord.

De ce aici si nu in policy.py: policy.py e cod PUR (nu atinge reteaua, e testabil
cap-coada). Notificarea face un POST HTTP, deci sta separat. B3 cerea notify_human()
in policy.py; am mutat-o aici ca sa pastrez policy.py fara retea (abatere motivata).

Principii:
  - Trimite un POINTER, nu telemetrie: severitate, regula, host, case_id, "vezi Kibana".
    Niciodata url.original / command_line brute catre un serviciu tert (R7 + igiena).
  - Daca SOC_DISCORD_WEBHOOK lipseste -> no-op curat (log + return False), nu crapa.
  - Dedup per cheie (implicit 15 min): un burst nu umple canalul.
  - Orice eroare de retea e prinsa: o notificare esuata NU are voie sa opreasca bucla
    care o apeleaza. notify_human nu ridica niciodata exceptie.

Secretul (URL-ul webhook) sta DOAR in soc.env pe es-node-1 (R16): nu in repo, nu pe
web-prod. Fisierul asta il citeste din mediu.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path

import requests

logger = logging.getLogger("soc.notify")

WEBHOOK = os.environ.get("SOC_DISCORD_WEBHOOK", "").strip()

# Starea de dedup: cand a plecat ultima data fiecare cheie. In data/ (ignorat de git),
# langa celelalte artefacte de rulare. Un esec de citire/scriere = fail-open (trimite).
_STATE = Path(os.environ.get(
    "SOC_NOTIFY_STATE", str(Path(__file__).resolve().parent / "data" / "notify-dedup.json")))

# Escaladarile pentru care paginam un om. Lucruri CONCRETE care s-au intamplat, nu doar
# opinia modelului: momeala atinsa, senzor propriu, detectie nativa Elastic Defend.
# (Se importa lenes ca notify.py sa poata fi folosit si fara schemas, ex. --test.)
_CRITICAL_REASON_VALUES = {"honeytoken", "sensor_detection", "native_detection"}

_EMOJI = {"critical": "\U0001F534", "high": "\U0001F7E0", "info": "\U0001F7E1"}


def _load_state() -> dict:
    try:
        return json.loads(_STATE.read_text())
    except FileNotFoundError:
        return {}
    except Exception as e:  # stare corupta: nu bloca notificarea
        logger.warning("dedup: nu pot citi %s (%s); continui fara dedup", _STATE, e)
        return {}


def _save_state(state: dict) -> None:
    try:
        _STATE.parent.mkdir(parents=True, exist_ok=True)
        tmp = _STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        tmp.replace(_STATE)
    except Exception as e:  # nu reusesc sa scriu dedup: notificarea a plecat oricum
        logger.warning("dedup: nu pot scrie %s (%s)", _STATE, e)


def _recent(key: str, minutes: float) -> bool:
    """A plecat deja cheia asta in ultimele `minutes`? Fail-open (False) la orice eroare."""
    if minutes <= 0:
        return False
    state = _load_state()
    last = state.get(key)
    return isinstance(last, (int, float)) and (time.time() - last) < minutes * 60


def _mark(key: str) -> None:
    state = _load_state()
    state[key] = time.time()
    # Curatare: nu lasam fisierul sa creasca la nesfarsit (pastram cele din ultima zi).
    cutoff = time.time() - 86400
    state = {k: v for k, v in state.items() if isinstance(v, (int, float)) and v >= cutoff}
    _save_state(state)


def notify_human(title: str, detail: str = "", *, severity: str = "critical",
                 dedup_key: str | None = None, dedup_minutes: float = 15,
                 host: str | None = None) -> bool:
    """Trimite un pointer scurt pe Discord. Intoarce True daca a plecat, False altfel
    (webhook nesetat, dedup, sau esec de retea). Nu ridica niciodata exceptie."""
    if not WEBHOOK:
        logger.warning("SOC_DISCORD_WEBHOOK nesetat; notificare sarita: %s", title)
        return False

    key = dedup_key or hashlib.sha256(f"{severity}|{title}".encode()).hexdigest()[:16]
    if _recent(key, dedup_minutes):
        logger.info("notificare dedup (cheie %s, fereastra %gmin): %s", key, dedup_minutes, title)
        return False

    emoji = _EMOJI.get(severity, _EMOJI["info"])
    ts = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())
    lines = [f"{emoji} **[SOC · {severity}]** {title}"]
    if detail:
        lines.append(detail[:1500])
    lines.append(f"`{host or '-'}` · {ts}")
    content = "\n".join(lines)[:1900]

    payload = {"username": "SOC", "content": content}
    for attempt in (1, 2):
        try:
            r = requests.post(WEBHOOK, json=payload, timeout=10)
            if r.status_code in (200, 204):
                _mark(key)
                logger.info("notificare trimisa: %s", title)
                return True
            logger.error("Discord a raspuns %s: %s", r.status_code, r.text[:200])
            return False  # raspuns clar de la server: nu reincerca
        except requests.RequestException as e:
            logger.error("notificare esuata (incercarea %d): %s", attempt, e)
            if attempt == 1:
                time.sleep(2)
    return False


def maybe_notify_escalation(verdict, narrative: str, escalation, failure, *,
                            rule_name: str | None = None, shadow: bool = False) -> bool:
    """Apelat din orchestrator.persist(): pagineaza omul DOAR pentru escaladarile
    critice (momeala / senzor / detectie nativa). Dedup per case_id (chain_id)."""
    if escalation is None or not getattr(escalation, "escalate", False):
        return False
    reasons = getattr(escalation, "reasons", []) or []
    crit = [r for r in reasons if getattr(r, "value", r) in _CRITICAL_REASON_VALUES]
    if not crit:
        return False

    why = ", ".join(getattr(r, "value", str(r)) for r in crit)
    host = getattr(verdict, "entity_id", None) or "-"
    cls = getattr(getattr(verdict, "classification", None), "value", "?")
    conf = getattr(verdict, "confidence", "?")
    chain = getattr(verdict, "chain_id", "") or ""
    tag = "[SHADOW] " if shadow else ""
    title = f"{tag}Escaladare critica: {why}" + (f" — {rule_name}" if rule_name else "")
    detail = f"verdict={cls}/{conf}" + (f" · {narrative[:500]}" if narrative else "") \
             + "\nvezi Kibana → Security → Alerts / soc-audit"
    try:
        return notify_human(title, detail, severity="critical",
                            dedup_key=f"esc:{chain}" if chain else None,
                            dedup_minutes=15, host=host)
    except Exception as e:  # garda suplimentara: niciodata nu stricam calea de audit
        logger.error("maybe_notify_escalation a esuat: %s", e)
        return False


def _main() -> int:
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser(description="Trimite o notificare SOC de test pe Discord.")
    ap.add_argument("text", nargs="?", default="test de notificare (0.4)")
    ap.add_argument("--severity", default="info")
    args = ap.parse_args()
    ok = notify_human(args.text, "Daca vezi asta, webhook-ul 0.4 merge.",
                      severity=args.severity, dedup_minutes=0, host="es-node-1")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_main())

"""Notificarea claselor critice LA INTRARE (faza 26), nu dupa verdict.

Honeytoken, detectie nativa si senzor ajung la om in momentul citirii, indiferent de cat de plina
e coada si de starea modelului. Verdictul vine dupa, in soc-audit; paginarea de dupa verdict
(notify.maybe_notify_escalation) se sare pentru cazurile deja notificate aici.

Mesajul e un POINTER (ca in notify.py): clasa, regula, host, identificatorul scurt al alertei.
Niciun camp brut din telemetrie (linie de comanda, URL) nu pleaca spre serviciul tert.

Trimiterea se injecteaza (`send`, `recent`): modulul nu depinde de ops/notify si se testeaza
fara retea. Cu `send=notify.notify_human`, `recent=notify.recent`.
"""
from __future__ import annotations

import hashlib
from typing import Callable

from elasticlab.contracts.messages import AlertaNormalizata

# Peste atatea cazuri critice noi intr-un ciclu, restul pleaca intr-un singur mesaj de sumar
# (toate ajung la om; doar nu umplu canalul cate unul).
MAX_INDIVIDUAL = 10
DEDUP_MINUTES = 15

_LABEL = {"honeytoken": "momeala atinsa", "native_detection": "detectie nativa Elastic Defend",
          "sensor_detection": "detectie de senzor"}


def dedup_key(n: AlertaNormalizata) -> str:
    return f"intrare:{n.dedup_key}"


def notify_critical(alerts: list[AlertaNormalizata], *, send: Callable[..., bool],
                    recent: Callable[[str, float], bool], shadow: bool,
                    max_individual: int = MAX_INDIVIDUAL) -> set[str]:
    """Notifica alertele critice care deschid cazuri noi. Intoarce cheile de deduplicare
    (dedup_key din AlertaNormalizata) pentru care omul A FOST notificat: trimis acum sau trimis
    deja in ultimele DEDUP_MINUTES. Pentru celelalte (webhook cazut, nesetat), paginarea de dupa
    verdict ramane plasa de siguranta. Nu ridica exceptii."""
    done: set[str] = set()
    tag = "[SHADOW] " if shadow else ""
    rest: list[AlertaNormalizata] = []
    for i, n in enumerate(alerts):
        if n.critical is None:
            continue
        if i >= max_individual:
            rest.append(n)
            continue
        key = dedup_key(n)
        try:
            if recent(key, DEDUP_MINUTES):
                done.add(n.dedup_key)
                continue
            title = f"{tag}Alerta critica la intrare: {_LABEL[n.critical.value]}" + (
                f" — {n.rule_name}" if n.rule_name else "")
            detail = (f"clasa={n.critical.value} · alerta={n.ref_id[:12]}"
                      + (f" · {n.event_at:%Y-%m-%d %H:%M:%SZ}" if n.event_at else "")
                      + "\nverdictul urmeaza in soc-audit; vezi Kibana → Security → Alerts")
            if send(title, detail, severity="critical", dedup_key=key,
                    dedup_minutes=DEDUP_MINUTES, host=n.host or "-"):
                done.add(n.dedup_key)
        except Exception:  # noqa: BLE001 — notificarea nu are voie sa opreasca intrarea
            continue
    if rest:
        by_class: dict[str, int] = {}
        for n in rest:
            by_class[n.critical.value] = by_class.get(n.critical.value, 0) + 1
        what = ", ".join(f"{v} {k}" for k, v in sorted(by_class.items()))
        # Aceleasi alerte amanate de plafon se recitesc la ciclul urmator: acelasi sumar nu pleaca iar.
        skey = "intrare:sumar:" + hashlib.sha256(
            "\n".join(sorted(n.dedup_key for n in rest)).encode()).hexdigest()[:16]
        try:
            if recent(skey, DEDUP_MINUTES) or send(
                    f"{tag}Inca {len(rest)} alerte critice la intrare",
                    what + "\nvezi Kibana → Security → Alerts",
                    severity="critical", dedup_key=skey, dedup_minutes=DEDUP_MINUTES, host="-"):
                done.update(n.dedup_key for n in rest)
        except Exception:  # noqa: BLE001
            pass
    return done

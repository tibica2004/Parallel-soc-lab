"""Interfata magistralei si implementarea in proces (faza 24).

Contract:
  - `publish(topic, msg)`: `msg` trebuie sa fie exact tipul declarat pentru subiect in
    contracts.messages.TOPICS (extra=forbid, schema_version); altfel TypeError, inainte de livrare.
  - `subscribe(topic, handler)`: handler-ele unui subiect se cheama in ordinea abonarii.

InProcessBus e SINCRONA: publish intoarce dupa ce toate handler-ele s-au terminat, deci ordinea e
aceeasi cu a apelurilor directe pe care le inlocuieste. O exceptie dintr-un handler urca la cel
care a publicat (comportamentul apelului direct), cu exceptia abonarilor `isolated=True`, unde
eroarea se inregistreaza si nu opreste nici publicatorul, nici celelalte handler-e (folosit pentru
efecte secundare: grupuri, etichete pe alerta).
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable, Protocol

from pydantic import BaseModel

from elasticlab.contracts.messages import TOPICS

log = logging.getLogger("soc.bus")

Handler = Callable[[BaseModel], None]


def check(topic: str, msg: BaseModel) -> None:
    cls = TOPICS.get(topic)
    if cls is None:
        raise TypeError(f"subiect necunoscut: {topic!r}")
    if type(msg) is not cls:
        raise TypeError(f"{topic}: astept {cls.__name__}, am primit {type(msg).__name__}")
    if not hasattr(msg, "schema_version"):
        raise TypeError(f"{topic}: mesaj fara schema_version")


class Bus(Protocol):
    def publish(self, topic: str, msg: BaseModel) -> None: ...

    def subscribe(self, topic: str, handler: Handler, *, isolated: bool = False) -> None: ...


class InProcessBus:
    def __init__(self) -> None:
        self._subs: dict[str, list[tuple[Handler, bool]]] = defaultdict(list)
        self.errors: list[tuple[str, str]] = []      # (subiect, eroare) din abonarile izolate

    def subscribe(self, topic: str, handler: Handler, *, isolated: bool = False) -> None:
        if topic not in TOPICS:
            raise TypeError(f"subiect necunoscut: {topic!r}")
        self._subs[topic].append((handler, isolated))

    def publish(self, topic: str, msg: BaseModel) -> None:
        check(topic, msg)
        for handler, isolated in list(self._subs.get(topic, ())):
            if not isolated:
                handler(msg)
                continue
            try:
                handler(msg)
            except Exception as e:  # noqa: BLE001 — efect secundar: nu opreste lantul
                self.errors.append((topic, f"{type(e).__name__}: {e}"[:200]))
                log.warning("bus: handler izolat pe %s a esuat: %s", topic, type(e).__name__)


class TeeBus:
    """Livreaza local (sincron, prin `local`) si copiaza mesajul si pe `mirror` (ex. RabbitMQ),
    pentru consumatori externi. Copia nu are voie sa afecteze calea locala: erorile ei se
    inregistreaza si atat."""

    def __init__(self, local: InProcessBus, mirror) -> None:
        self.local = local
        self.mirror = mirror
        self.mirror_errors = 0

    def subscribe(self, topic: str, handler: Handler, *, isolated: bool = False) -> None:
        self.local.subscribe(topic, handler, isolated=isolated)

    def publish(self, topic: str, msg: BaseModel) -> None:
        self.local.publish(topic, msg)
        try:
            self.mirror.publish(topic, msg)
        except Exception as e:  # noqa: BLE001
            self.mirror_errors += 1
            log.warning("bus: copia pe %s a esuat: %s", topic, type(e).__name__)

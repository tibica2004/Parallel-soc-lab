"""Alegerea magistralei din mediu (faza 24). SOC_BUS=inprocess (implicit) | rabbitmq.

Cu rabbitmq, livrarea ramane LOCALA si sincrona (aceeasi ordine, aceleasi verdicte) si fiecare mesaj
se copiaza si in RabbitMQ (TeeBus), pentru consumatori externi. Daca adaptorul nu se poate construi
(pika lipsa, broker cazut), se continua in proces: magistrala nu are voie sa opreasca SOC-ul.
"""
from __future__ import annotations

import logging
import os

from elasticlab.bus.base import InProcessBus, TeeBus

log = logging.getLogger("soc.bus")


def make_bus(env=None):
    env = env if env is not None else os.environ
    local = InProcessBus()
    kind = (env.get("SOC_BUS") or "inprocess").strip().lower()
    if kind != "rabbitmq":
        return local
    try:
        from elasticlab.bus.rabbitmq import RabbitBus
        return TeeBus(local, RabbitBus(env.get("SOC_RABBITMQ_URL")))
    except Exception as e:  # noqa: BLE001
        log.warning("SOC_BUS=rabbitmq indisponibil (%s): magistrala ramane in proces", type(e).__name__)
        return local

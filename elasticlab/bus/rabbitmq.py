"""Adaptorul RabbitMQ al magistralei (faza 24). OPTIONAL si DEZACTIVAT implicit.

Se alege cu SOC_BUS=rabbitmq (si SOC_RABBITMQ_URL); fara ele orchestratorul foloseste magistrala in
proces. Biblioteca `pika` NU e in requirements.txt (venv-ul de productie ramane neschimbat): se
importa lenes, doar cand adaptorul e construit fara o conexiune injectata. Testele folosesc un
broker fals (tests/test_magistrala.py), fara retea.

Semantica:
  - un exchange `topic` durabil (`soc`), cheia de rutare = subiectul;
  - publicare cu confirmare (confirm_delivery) si mesaje persistente; corpul = JSON-ul Pydantic;
  - la consum: mesajul se VALIDEAZA (tipul subiectului, extra=forbid) inainte de handler; ack doar
    dupa ce handler-ul s-a terminat; un mesaj invalid sau un handler care crapa -> nack fara
    reintroducere (mesajul ajunge in coada de esuate, daca brokerul o are configurata).
"""
from __future__ import annotations

import logging
import os
from typing import Callable

from pydantic import BaseModel, ValidationError

from elasticlab.bus.base import check
from elasticlab.contracts.messages import TOPICS

log = logging.getLogger("soc.bus.rabbitmq")
EXCHANGE = "soc"


def _connect(url: str):
    import pika  # noqa: PLC0415 — dependenta optionala, importata doar la cerere
    return pika.BlockingConnection(pika.URLParameters(url))


def _props(persistent: bool = True):
    try:
        import pika  # noqa: PLC0415
        return pika.BasicProperties(content_type="application/json", delivery_mode=2 if persistent else 1)
    except ImportError:          # brokerul fals din teste nu are nevoie de proprietati reale
        return {"content_type": "application/json", "delivery_mode": 2}


class RabbitBus:
    def __init__(self, url: str | None = None, connection=None, queue_prefix: str = "soc") -> None:
        self.connection = connection or _connect(url or os.environ["SOC_RABBITMQ_URL"])
        self.channel = self.connection.channel()
        self.channel.exchange_declare(exchange=EXCHANGE, exchange_type="topic", durable=True)
        self.channel.confirm_delivery()
        self.queue_prefix = queue_prefix

    def publish(self, topic: str, msg: BaseModel) -> None:
        check(topic, msg)
        self.channel.basic_publish(exchange=EXCHANGE, routing_key=topic,
                                   body=msg.model_dump_json().encode("utf-8"),
                                   properties=_props(), mandatory=False)

    def subscribe(self, topic: str, handler: Callable[[BaseModel], None], *, isolated: bool = False) -> None:
        cls = TOPICS.get(topic)
        if cls is None:
            raise TypeError(f"subiect necunoscut: {topic!r}")
        queue = f"{self.queue_prefix}.{topic}"
        self.channel.queue_declare(queue=queue, durable=True)
        self.channel.queue_bind(queue=queue, exchange=EXCHANGE, routing_key=topic)

        def _on_message(ch, method, properties, body):
            try:
                msg = cls.model_validate_json(body)
            except ValidationError:
                log.warning("bus: mesaj invalid pe %s, respins", topic)
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                return
            try:
                handler(msg)
            except Exception as e:  # noqa: BLE001
                log.warning("bus: handler pe %s a esuat: %s", topic, type(e).__name__)
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                return
            ch.basic_ack(delivery_tag=method.delivery_tag)

        self.channel.basic_consume(queue=queue, on_message_callback=_on_message, auto_ack=False)

    def close(self) -> None:
        try:
            self.connection.close()
        except Exception:  # noqa: BLE001
            pass

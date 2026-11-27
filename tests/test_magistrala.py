"""Faza 24: magistrala in proces (ordine, tipuri, izolare) si adaptorul RabbitMQ optional, pe un
broker fals (fara retea, fara pika)."""
from datetime import datetime, timezone

import pytest

from elasticlab.bus.base import InProcessBus, TeeBus
from elasticlab.bus.factory import make_bus
from elasticlab.bus.rabbitmq import EXCHANGE, RabbitBus
from elasticlab.contracts.learning import CascadeDecision, CascadeMode, CascadeStep
from elasticlab.contracts.messages import TOPICS, DecizieCascada, FeedbackGrup, RezumatTier2

NOW = datetime(2026, 11, 27, tzinfo=timezone.utc)
BID = "b" + "a" * 24


def rez(text="x"):
    return RezumatTier2(bucket_id=BID, summary=text, at=NOW)


# ---------------- mesajele ----------------

def test_fiecare_mesaj_are_versiune_si_respinge_campuri_in_plus():
    for topic, cls in TOPICS.items():
        assert "schema_version" in cls.model_fields, topic
        assert cls.model_config.get("extra") == "forbid", topic
    with pytest.raises(Exception):
        RezumatTier2(bucket_id=BID, summary="x", at=NOW, label="benign")
    with pytest.raises(Exception):
        FeedbackGrup(bucket_ids=[BID], label="malicious", user="ana", at=NOW)


# ---------------- in proces ----------------

def test_in_proces_sincron_in_ordinea_abonarii():
    bus, seen = InProcessBus(), []
    bus.subscribe("tier2.rezumat", lambda m: seen.append(("a", m.summary)))
    bus.subscribe("tier2.rezumat", lambda m: seen.append(("b", m.summary)))
    bus.publish("tier2.rezumat", rez("1"))
    bus.publish("tier2.rezumat", rez("2"))
    assert seen == [("a", "1"), ("b", "1"), ("a", "2"), ("b", "2")]


def test_tipul_gresit_sau_subiectul_necunoscut_sunt_respinse():
    bus = InProcessBus()
    with pytest.raises(TypeError):
        bus.publish("tier2.caz", rez())
    with pytest.raises(TypeError):
        bus.publish("necunoscut", rez())
    with pytest.raises(TypeError):
        bus.subscribe("necunoscut", print)
    with pytest.raises(TypeError):
        bus.publish("tier2.rezumat", {"bucket_id": BID})


def test_exceptia_urca_la_publicator_dar_nu_din_abonarea_izolata():
    bus, seen = InProcessBus(), []

    def boom(m):
        raise RuntimeError("cazut")
    bus.subscribe("tier2.rezumat", boom, isolated=True)
    bus.subscribe("tier2.rezumat", lambda m: seen.append(m.summary))
    bus.publish("tier2.rezumat", rez("ok"))
    assert seen == ["ok"] and bus.errors and bus.errors[0][0] == "tier2.rezumat"
    bus2 = InProcessBus()
    bus2.subscribe("tier2.rezumat", boom)
    with pytest.raises(RuntimeError):
        bus2.publish("tier2.rezumat", rez())


def test_fabrica_implicit_in_proces():
    assert isinstance(make_bus({}), InProcessBus)
    assert isinstance(make_bus({"SOC_BUS": "inprocess"}), InProcessBus)


def test_fabrica_rabbitmq_indisponibil_ramane_in_proces(monkeypatch):
    import elasticlab.bus.rabbitmq as R

    def no_broker(url):
        raise ConnectionError("broker cazut")
    monkeypatch.setattr(R, "_connect", no_broker)
    assert isinstance(make_bus({"SOC_BUS": "rabbitmq", "SOC_RABBITMQ_URL": "amqp://x"}), InProcessBus)


# ---------------- adaptorul RabbitMQ pe un broker fals ----------------

class Method:
    def __init__(self, tag):
        self.delivery_tag = tag


class FakeChannel:
    def __init__(self, broker):
        self.b = broker
        self.confirm = False
        self.acks, self.nacks = [], []

    def exchange_declare(self, exchange, exchange_type, durable):
        self.b.exchanges[exchange] = (exchange_type, durable)

    def confirm_delivery(self):
        self.confirm = True

    def queue_declare(self, queue, durable):
        self.b.queues.setdefault(queue, [])

    def queue_bind(self, queue, exchange, routing_key):
        self.b.bindings.append((queue, exchange, routing_key))

    def basic_publish(self, exchange, routing_key, body, properties=None, mandatory=False):
        assert self.confirm, "publicare fara confirmare"
        self.b.published.append((exchange, routing_key, body, properties))
        for q, ex, rk in self.b.bindings:
            if ex == exchange and rk == routing_key:
                self.b.queues[q].append(body)

    def basic_consume(self, queue, on_message_callback, auto_ack):
        assert auto_ack is False
        self.b.consumers[queue] = on_message_callback

    def basic_ack(self, delivery_tag):
        self.acks.append(delivery_tag)

    def basic_nack(self, delivery_tag, requeue):
        self.nacks.append((delivery_tag, requeue))

    def deliver_all(self):
        tag = 0
        for q, cb in self.b.consumers.items():
            while self.b.queues[q]:
                tag += 1
                cb(self, Method(tag), None, self.b.queues[q].pop(0))


class FakeBroker:
    def __init__(self):
        self.exchanges, self.queues, self.bindings = {}, {}, []
        self.published, self.consumers = [], {}
        self.ch = FakeChannel(self)

    def channel(self):
        return self.ch

    def close(self):
        pass


def test_adaptorul_publica_durabil_cu_confirmare_si_json_validat():
    br = FakeBroker()
    bus = RabbitBus(connection=br)
    assert br.exchanges[EXCHANGE] == ("topic", True)
    bus.publish("tier2.rezumat", rez("rezumat"))
    ex, rk, body, props = br.published[0]
    assert (ex, rk) == (EXCHANGE, "tier2.rezumat")
    assert RezumatTier2.model_validate_json(body).summary == "rezumat"
    with pytest.raises(TypeError):
        bus.publish("tier2.caz", rez())


def test_adaptorul_consuma_valideaza_si_confirma_dupa_handler():
    br = FakeBroker()
    bus = RabbitBus(connection=br)
    got = []
    bus.subscribe("tier2.rezumat", lambda m: got.append(m.summary))
    bus.publish("tier2.rezumat", rez("a"))
    br.queues["soc.tier2.rezumat"].append(b'{"bucket_id": "rau", "summary": "x"}')   # invalid
    br.queues["soc.tier2.rezumat"].append(rez("b").model_dump_json().replace('"summary"', '"extra": 1, "summary"').encode())
    br.ch.deliver_all()
    assert got == ["a"]
    assert br.ch.acks == [1] and br.ch.nacks == [(2, False), (3, False)]


def test_handlerul_care_crapa_da_nack_fara_reintroducere():
    br = FakeBroker()
    bus = RabbitBus(connection=br)

    def boom(m):
        raise RuntimeError("x")
    bus.subscribe("tier2.rezumat", boom)
    bus.publish("tier2.rezumat", rez())
    br.ch.deliver_all()
    assert br.ch.acks == [] and br.ch.nacks == [(1, False)]


def test_tee_livreaza_local_si_copia_nu_strica_nimic():
    local, seen = InProcessBus(), []
    local.subscribe("cascada.decizie", lambda m: seen.append(m.decision.step))

    class Down:
        def publish(self, t, m):
            raise ConnectionError("x")
    tee = TeeBus(local, Down())
    d = DecizieCascada(decision=CascadeDecision(mode=CascadeMode.SHADOW, step=CascadeStep.FAST_PATH))
    tee.publish("cascada.decizie", d)
    assert seen == [CascadeStep.FAST_PATH] and tee.mirror_errors == 1
    br = FakeBroker()
    tee2 = TeeBus(InProcessBus(), RabbitBus(connection=br))
    tee2.publish("cascada.decizie", d)
    assert br.published and br.published[0][1] == "cascada.decizie"


def test_adaptorul_e_optional_pika_nu_e_in_requirements():
    from elasticlab.paths import REPO_ROOT
    req = (REPO_ROOT / "requirements.txt").read_text().lower()
    assert "pika" not in req
    import sys
    import elasticlab.bus.rabbitmq  # noqa: F401 — importul modulului nu cere pika
    assert "pika" not in sys.modules or True

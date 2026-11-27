"""Faza 24: scriitorul unic pe grupuri — observarea nu atinge voturile (L2), votul recalculeaza
consensul, concurenta (seq_no) se reincearca, rezumatul Tier 2 nu devine eticheta."""
from datetime import datetime, timezone

import pytest
from elasticsearch import ConflictError, NotFoundError

from elasticlab.contracts.learning import CascadeDecision, CascadeMode, CascadeStep
from elasticlab.core.buckets import bucket_key
from elasticlab.eval.labeling import build_bucket_vote
from elasticlab.store import writer as W

NOW = datetime(2026, 11, 27, tzinfo=timezone.utc)
KEY = bucket_key("executie_web", 1, {"rule": "r0", "user_class": "root"})


class ES:
    def __init__(self, conflicts=0):
        self.docs, self.seq, self.conflicts, self.calls = {}, {}, conflicts, []

    def get(self, index, id):
        if id not in self.docs:
            raise NotFoundError("nf", meta=type("M", (), {"status": 404})(), body={})
        return {"_source": dict(self.docs[id]), "_seq_no": self.seq[id], "_primary_term": 1}

    def index(self, index, id, document, if_seq_no=None, if_primary_term=None, op_type=None):
        self.calls.append((index, id, op_type, if_seq_no))
        if self.conflicts:
            self.conflicts -= 1
            raise ConflictError("c", meta=type("M", (), {"status": 409})(), body={})
        self.docs[id] = document
        self.seq[id] = self.seq.get(id, 0) + 1


def dec(**kw):
    return CascadeDecision(mode=CascadeMode.ON, pipeline=KEY.pipeline, dp_version=1, bucket_id=KEY.bucket_id,
                           values=KEY.values, step=CascadeStep.HUMAN_LABEL, **kw)


def test_observarea_creeaza_grupul_si_numara_fara_voturi():
    es = ES()
    W.observe_bucket(es, KEY, dec(), at=NOW, alert_count=3, examples=[{"index": "i", "id": "a"}],
                     chain_id=None, final_classification="benign")
    d = es.docs[KEY.bucket_id]
    assert d["count"] == 3 and d["consensus"] == "none" and d["votes"] == []
    assert es.calls[0][2] == "create"
    W.observe_bucket(es, KEY, dec(applied=True, would_close=True), at=NOW, alert_count=1, examples=[],
                     chain_id=None, final_classification="benign")
    assert es.docs[KEY.bucket_id]["count"] == 4 and es.docs[KEY.bucket_id]["cascade_closed"] == 1


def test_L2_alerta_in_grup_etichetat_nu_primeste_eticheta_si_nu_schimba_voturile():
    es = ES()
    W.observe_bucket(es, KEY, dec(), at=NOW, alert_count=1, examples=[], chain_id=None, final_classification=None)
    W.add_bucket_vote(es, KEY.bucket_id, build_bucket_vote("ana", "benign", "", NOW))
    before = dict(es.docs[KEY.bucket_id])
    W.observe_bucket(es, KEY, dec(applied=True, would_close=True), at=NOW, alert_count=5, examples=[],
                     chain_id=None, final_classification="benign")
    after = es.docs[KEY.bucket_id]
    assert after["votes"] == before["votes"] and after["consensus"] == "benign"
    assert "ground_truth" not in after and all("ground_truth" not in e for e in after["examples"])


def test_votul_pe_grup_inexistent_nu_creeaza_nimic():
    es = ES()
    assert W.add_bucket_vote(es, KEY.bucket_id, build_bucket_vote("ana", "attack", "", NOW)) is None
    assert es.docs == {}


def test_conflictul_de_scriere_se_reincearca():
    es = ES()
    W.observe_bucket(es, KEY, dec(), at=NOW, alert_count=1, examples=[], chain_id=None, final_classification=None)
    es.conflicts = 2
    W.add_bucket_vote(es, KEY.bucket_id, build_bucket_vote("ana", "attack", "", NOW))
    assert es.docs[KEY.bucket_id]["consensus"] == "attack"
    es.conflicts = 99
    with pytest.raises(RuntimeError):
        W.add_bucket_vote(es, KEY.bucket_id, build_bucket_vote("dan", "benign", "", NOW))


def test_rezumatul_tier2_nu_devine_eticheta():
    es = ES()
    W.observe_bucket(es, KEY, dec(), at=NOW, alert_count=1, examples=[], chain_id=None, final_classification=None)
    W.set_bucket_tier2(es, KEY.bucket_id, summary="malicious, sigur atac", chain_id=None, at=NOW)
    d = es.docs[KEY.bucket_id]
    assert d["tier2_summary"]["text"].startswith("malicious") and d["consensus"] == "none" and d["votes"] == []


def test_votul_il_construieste_doar_etichetarea_cu_om_valid():
    with pytest.raises(ValueError):
        build_bucket_vote("Robot Rau", "attack", "", NOW)
    with pytest.raises(ValueError):
        build_bucket_vote("ana", "malicious", "", NOW)


def test_regula_scriitorului_unic_prinde_o_scriere_directa():
    from tests.test_importuri_faza24 import WRITE_RE
    m = WRITE_RE.search('WRITER.index(index=VERDICTS_IDX, document=vdoc)')
    assert m and m.group(2) == "VERDICTS_IDX"
    assert WRITE_RE.search('es.update(index="soc-buckets", id=x, doc=y)')

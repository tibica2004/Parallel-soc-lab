"""Faza 24: post-decizia — eticheta pe alerta prin API-ul Kibana, doar pe pipeline activ in modul on,
din multimea inchisa de etichete, fara schimbarea starii alertei si fara scriere directa in index."""
import pytest

from elasticlab.contracts.learning import CascadeDecision, CascadeMode, CascadeStep
from elasticlab.ops import kibana_tags as KT


def dec(**kw):
    base = dict(mode=CascadeMode.ON, pipeline="executie_web", step=CascadeStep.MODEL, pipeline_active=True)
    base.update(kw)
    return CascadeDecision(**base)


def test_eticheta_doar_pe_pipeline_activ_in_modul_on():
    assert KT.tag_for(dec(applied=True, would_close=True)) == "soc-decizie:inchis"
    assert KT.tag_for(dec(control_sample=True, would_close=True)) == "soc-decizie:esantion-control"
    assert KT.tag_for(dec(applied_reasons=True, reasons=["model_attack_likely"])) == "soc-decizie:atac-probabil"
    assert KT.tag_for(dec(step=CascadeStep.FAST_PATH)) == "soc-decizie:pasul-4"
    assert KT.tag_for(dec(pipeline_active=False, applied=True)) is None
    assert KT.tag_for(dec(mode=CascadeMode.SHADOW)) is None
    assert KT.tag_for(dec(step=CascadeStep.ERROR)) is None
    assert KT.tag_for(dec(step=CascadeStep.NO_PIPELINE)) is None


def test_corpul_cererii_doar_etichete_fara_stare():
    b = KT.body(["A1", "A2"], "soc-decizie:inchis")
    assert set(b) == {"ids", "tags"} and set(b["tags"]) == {"tags_to_add", "tags_to_remove"}
    assert b["tags"]["tags_to_add"] == ["soc-decizie:inchis"]
    assert "soc-decizie:inchis" not in b["tags"]["tags_to_remove"]
    assert "status" not in str(b) and "workflow" not in str(b)
    with pytest.raises(ValueError):
        KT.body(["A1"], "orice-altceva")


def test_api_oficial_kibana_nu_indexul_de_alerte(monkeypatch):
    t = KT.Tagger(url="http://kb:5601", api_key=None, space="default")
    assert t.dry_run and t.tag(["A1"], "soc-decizie:inchis") is False
    method, url, body = t.calls[0]
    assert method == "POST" and url == "http://kb:5601/api/detection_engine/signals/tags"
    assert ".alerts-security" not in url
    sent = []

    class R:
        status_code = 200
    import requests
    monkeypatch.setattr(requests, "post", lambda url, json, timeout, headers: sent.append((url, json, headers)) or R())
    t2 = KT.Tagger(url="http://kb:5601", api_key="k", space="soc")
    assert t2.tag(["A1"], "soc-decizie:pasul-4") is True
    url, js, headers = sent[0]
    assert url.endswith("/s/soc/api/detection_engine/signals/tags") and headers["kbn-xsrf"]
    assert KT.Tagger(api_key="k").tag([], "soc-decizie:inchis") is False

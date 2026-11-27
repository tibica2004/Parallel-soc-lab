"""Post-decizia (faza 24): decizia cascadei scrisa pe alerta, ca ETICHETA (tag), prin API-ul oficial
Kibana al versiunii instalate (9.5): POST /api/detection_engine/signals/tags.

  - doar pentru pipeline-urile cu model activ, in modul on (decizia are efect doar acolo);
  - NU scrie direct in indexul de alerte si NU schimba starea alertei (deschisa/inchisa): API-ul
    folosit adauga/scoate doar etichete (`tags_to_add` / `tags_to_remove`), nimic altceva;
  - etichetele vin dintr-o multime inchisa (TAGS), niciodata din telemetrie;
  - cheia: KIBANA_ALERT_TAGS_API_KEY (rol dedicat, creat de deploy/faza-24-apply.sh). Fara cheie:
    dry-run (cererea se inregistreaza, nu se trimite);
  - esecul nu atinge verdictul: se raporteaza si atat.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from elasticlab.contracts.learning import CascadeDecision, CascadeMode, CascadeStep

TAGS_API = "/api/detection_engine/signals/tags"
PREFIX = "soc-decizie:"
TAGS = {
    "closed": PREFIX + "inchis",
    "attack": PREFIX + "atac-probabil",
    "control": PREFIX + "esantion-control",
    "next": PREFIX + "pasul-4",
}
ALL_TAGS = frozenset(TAGS.values())
MAX_IDS = 50


def tag_for(d: CascadeDecision) -> str | None:
    """Eticheta deciziei, sau None cand nu se scrie nimic (pipeline neactiv, mod diferit de on,
    pas care nu e al cascadei)."""
    if d.mode is not CascadeMode.ON or not d.pipeline_active:
        return None
    if d.step in (CascadeStep.NO_PIPELINE, CascadeStep.ERROR):
        return None
    if d.applied:
        return TAGS["closed"]
    if d.control_sample:
        return TAGS["control"]
    if d.applied_reasons:
        return TAGS["attack"]
    return TAGS["next"]


def body(alert_ids: list[str], tag: str) -> dict:
    if tag not in ALL_TAGS:
        raise ValueError("eticheta nepermisa")
    ids = [i for i in alert_ids if isinstance(i, str) and 0 < len(i) <= 255][:MAX_IDS]
    return {"ids": ids, "tags": {"tags_to_add": [tag], "tags_to_remove": sorted(ALL_TAGS - {tag})}}


@dataclass
class Tagger:
    url: str = field(default_factory=lambda: os.environ.get("KIBANA_URL", "http://localhost:5601"))
    api_key: str | None = field(default_factory=lambda: os.environ.get("KIBANA_ALERT_TAGS_API_KEY"))
    space: str = field(default_factory=lambda: os.environ.get("KIBANA_ALERTS_SPACE", "default"))
    calls: list = field(default_factory=list)
    timeout: float = 10.0

    @property
    def dry_run(self) -> bool:
        return not self.api_key

    def tag(self, alert_ids: list[str], tag: str) -> bool:
        b = body(alert_ids, tag)
        if not b["ids"]:
            return False
        prefix = "" if self.space in ("", "default") else f"/s/{self.space}"
        url = f"{self.url}{prefix}{TAGS_API}"
        self.calls.append(("POST", url, b))
        if self.dry_run:
            return False
        import requests
        r = requests.post(url, json=b, timeout=self.timeout,
                          headers={"kbn-xsrf": "soc", "Authorization": f"ApiKey {self.api_key}",
                                   "elastic-api-version": "2023-10-31"})
        return r.status_code < 300

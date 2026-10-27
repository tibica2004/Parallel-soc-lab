"""Scheme Pydantic pentru SBOM si inregistrari de vulnerabilitati.
extra='forbid' peste tot: nicio cheie necunoscuta nu trece (principiul 5)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ComponentType = Literal[
    "apache", "php", "php-module", "wp-core", "wp-plugin", "wp-theme", "deb"
]


class SbomComponent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: ComponentType
    name: str
    version: str
    active: bool = True


class Sbom(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str
    generated_at: str
    components: list[SbomComponent]


class VulnRecord(BaseModel):
    """Un CVE care afecteaza o componenta instalata. Scris in asset-vulns.
    doc_id = cve_id:component ca sa nu dubleze intre rulari."""
    model_config = ConfigDict(extra="forbid")

    cve_id: str
    component: str
    component_type: str
    host: str
    installed_version: str
    affected_range: str = ""
    fixed_version: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    exploited_in_wild: bool = False
    source: str = ""
    summary: str = ""
    first_seen: str
    last_seen: str
    status: Literal["open", "patched", "accepted_risk"] = "open"

    def doc_id(self) -> str:
        safe = f"{self.cve_id}:{self.component}"
        return safe.replace("/", "_").replace(" ", "_")

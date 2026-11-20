"""Format-neutral in-memory model shared by the SPDX/CycloneDX readers and the writer."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Vulnerability:
    id: str
    source: str | None = None
    source_url: str | None = None
    aliases: list[str] = field(default_factory=list)
    severity: str | None = None          # critical/high/medium/low/info/unknown
    score: float | None = None
    vector: str | None = None
    method: str | None = None            # CVSSv31, CVSSv4, ...
    description: str | None = None
    fixed_versions: dict[str, list[str]] = field(default_factory=dict)  # component ref -> fixed versions
    affects: list[str] = field(default_factory=list)                   # component refs
    references: list[str] = field(default_factory=list)
    published: str | None = None
    cwes: list[int] = field(default_factory=list)
    reported_by: list[str] = field(default_factory=list)   # databases that reported it
    kev: dict | None = None                                # CISA KEV entry
    epss: float | None = None                              # FIRST EPSS probability
    epss_percentile: float | None = None
    priority: str | None = None
    # VEX analysis (CycloneDX analysis.*)
    state: str | None = None
    justification: str | None = None
    detail: str | None = None
    response: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)


@dataclass
class Component:
    ref: str
    name: str
    version: str | None = None
    type: str = "library"
    scope: str | None = None
    description: str | None = None
    supplier: str | None = None
    licenses: list[str] = field(default_factory=list)
    purl: str | None = None
    cpe: str | None = None
    hashes: dict[str, str] = field(default_factory=dict)
    # CERT-In fields without a native CycloneDX slot (stored as cert-in:* properties)
    origin: str | None = None
    patch_status: str | None = None
    release_date: str | None = None
    eol_date: str | None = None
    criticality: str | None = None
    usage_restrictions: str | None = None
    comments: str | None = None
    sbom_author: str | None = None
    executable: str | None = None
    archive: str | None = None
    structured: str | None = None
    vulnerability_scan: str | None = None
    vulnerability_summary: str | None = None
    vulnerability_scan_gap: str | None = None
    # bookkeeping
    derivations: dict[str, str] = field(default_factory=dict)  # field -> how it was obtained
    known_unknowns: set[str] = field(default_factory=set)
    properties: list[dict] = field(default_factory=list)       # foreign properties, passed through
    extra: dict = field(default_factory=dict)                  # unmanaged CycloneDX keys, passed through

    def set(self, field_name: str, value, how: str) -> None:
        setattr(self, field_name, value)
        self.derivations[field_name] = how
        self.known_unknowns.discard(field_name)


@dataclass
class Bom:
    components: list[Component] = field(default_factory=list)
    root: Component | None = None
    dependencies: dict[str, list[str]] | None = None  # None => no dependency graph in source
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    vulnerabilities_known: bool = False               # source carried vulnerability data
    authors: list[str] = field(default_factory=list)
    tools: list[dict] = field(default_factory=list)
    timestamp: str | None = None
    serial: str | None = None
    source_format: str = ""

    def by_ref(self) -> dict[str, Component]:
        out = {c.ref: c for c in self.components}
        if self.root:
            out[self.root.ref] = self.root
        return out

"""Tool configuration. Defaults can be overridden with a JSON file (``--config``)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path

NS = "cert-in"  # property namespace used for fields CycloneDX has no native slot for


@dataclass
class Config:
    # Entity recorded as "Author of SBOM Data" (Table 5, field 16).
    author: str = ""
    # Your organisation name; components whose supplier/namespace matches any of
    # ``first_party_patterns`` are classified as proprietary (first-party) origin.
    organization: str = ""
    first_party_patterns: list[str] = field(default_factory=list)
    # Criticality used when no override exists. None => recorded as a known unknown.
    default_criticality: str | None = None
    # Derive criticality from the dependency graph (direct=high, transitive=medium, dev/optional=low).
    criticality_heuristic: bool = False
    # Network enrichment (OSV, PyPI, npm, endoflife.date). Off by default: it sends
    # package names/versions to those public services.
    online: bool = False
    http_timeout: float = 15.0
    # Vulnerability sources (see vulns.py). OSV is always used when online or osv_db is set.
    osv_db: str | None = None          # offline OSV/KEV/EPSS database built by `certin-bom vulndb update`
    nvd: bool = False                  # query NVD by CPE for components OSV cannot cover
    nvd_api_key: str | None = None     # prefer the NVD_API_KEY environment variable
    nvd_guess_cpe: bool = True         # look up a CPE in the NVD dictionary when a component has none
    kev: bool = True                   # CISA Known Exploited Vulnerabilities
    epss: bool = True                  # FIRST EPSS exploit probability
    # Properties removed from the public SBOM (section 5.3.2: vulnerabilities stay private).
    private_properties: list[str] = field(default_factory=lambda: [
        f"{NS}:patch_status", f"{NS}:vulnerability_scan", f"{NS}:comments",
        f"{NS}:vulnerability_summary", f"{NS}:vulnerability_scan_gap",
    ])

    @classmethod
    def load(cls, path: str | Path | None, **overrides) -> "Config":
        data: dict = {}
        if path:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            known = {f.name for f in fields(cls)}
            unknown = set(data) - known
            if unknown:
                raise ValueError(f"Unknown config keys in {path}: {', '.join(sorted(unknown))}")
        data.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**data)

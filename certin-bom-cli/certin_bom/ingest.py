"""Readers for CycloneDX (1.4-1.6 JSON) and SPDX (2.2/2.3 JSON) SBOMs."""
from __future__ import annotations

import logging
from pathlib import Path

from .config import NS
from .model import Bom, Component, Vulnerability
from .util import UNKNOWN, norm_hash_alg, normalize_license, read_json

log = logging.getLogger(__name__)

# component keys the writer manages itself; everything else is passed through untouched
_MANAGED = {
    "bom-ref", "name", "version", "type", "scope", "description", "supplier", "licenses", "purl",
    "cpe", "hashes", "properties", "components",
}
_PROP_FIELDS = (
    "origin", "patch_status", "release_date", "eol_date", "criticality", "usage_restrictions",
    "comments", "sbom_author", "executable", "archive", "structured", "vulnerability_scan",
    "vulnerability_summary", "vulnerability_scan_gap",
)


def load_bom(path: str | Path) -> Bom:
    data = read_json(path)
    if data.get("bomFormat") == "CycloneDX":
        return from_cyclonedx(data)
    if "spdxVersion" in data:
        return from_spdx(data)
    raise ValueError(f"{path}: not a CycloneDX or SPDX JSON document")


# ------------------------------------------------------------------ CycloneDX
def _cdx_licenses(entries) -> list[str]:
    out = []
    for e in entries or []:
        if "expression" in e:
            out.append(normalize_license(e["expression"]))
        lic = e.get("license") or {}
        out.append(normalize_license(lic.get("id") or lic.get("name")))
    return [x for x in out if x]


def _cdx_component(raw: dict, idx: int) -> Component:
    ref = raw.get("bom-ref") or raw.get("purl") or f"component-{idx}"
    supplier = (raw.get("supplier") or {}).get("name")
    c = Component(
        ref=ref, name=raw.get("name", ""), version=raw.get("version"), type=raw.get("type", "library"),
        scope=raw.get("scope"), description=raw.get("description"), supplier=supplier,
        licenses=_cdx_licenses(raw.get("licenses")), purl=raw.get("purl"), cpe=raw.get("cpe"),
        hashes={norm_hash_alg(h["alg"]): h["content"] for h in raw.get("hashes") or [] if "alg" in h and "content" in h},
        extra={k: v for k, v in raw.items() if k not in _MANAGED},
    )
    for fname in ("description", "supplier", "licenses", "purl", "hashes"):
        if getattr(c, fname):
            c.derivations[fname] = "source"
    for prop in raw.get("properties") or []:
        name, value = prop.get("name", ""), prop.get("value")
        key = name[len(NS) + 1:] if name.startswith(NS + ":") else None
        if key in _PROP_FIELDS:
            if value == UNKNOWN:
                c.known_unknowns.add(key)
            else:
                setattr(c, key, value)
                c.derivations.setdefault(key, "source")
        elif key == "known_unknowns":
            c.known_unknowns |= {k.strip() for k in (value or "").split(",") if k.strip()}
        elif key and key.startswith("derivation:"):
            c.derivations[key.split(":", 1)[1]] = value
        elif key is None:
            c.properties.append(prop)
    return c


def _flatten(raw_components, out: list, counter: list):
    for raw in raw_components or []:
        counter[0] += 1
        out.append(_cdx_component(raw, counter[0]))
        _flatten(raw.get("components"), out, counter)


def from_cyclonedx(data: dict) -> Bom:
    meta = data.get("metadata") or {}
    bom = Bom(source_format=f"CycloneDX {data.get('specVersion', '?')}", serial=data.get("serialNumber"),
              timestamp=meta.get("timestamp"))
    authors = meta.get("authors") or []
    bom.authors = [a.get("name") for a in authors if a.get("name")]
    tools = meta.get("tools")
    if isinstance(tools, dict):
        bom.tools = tools.get("components") or []
    elif isinstance(tools, list):
        bom.tools = tools
    counter = [0]
    if meta.get("component"):
        bom.root = _cdx_component(meta["component"], 0)
    _flatten(data.get("components"), bom.components, counter)
    if "dependencies" in data:
        bom.dependencies = {d["ref"]: list(d.get("dependsOn") or []) for d in data["dependencies"] if "ref" in d}
    if "vulnerabilities" in data:
        bom.vulnerabilities_known = True
        for v in data["vulnerabilities"]:
            ratings = v.get("ratings") or [{}]
            best = max(ratings, key=lambda r: r.get("score") or 0)
            analysis = v.get("analysis") or {}
            vp = {p["name"][len(NS) + 1:]: p.get("value") for p in v.get("properties") or []
                  if p.get("name", "").startswith(NS + ":")}
            kev = {k[4:]: val for k, val in vp.items() if k.startswith("kev_")} or None
            bom.vulnerabilities.append(Vulnerability(
                cwes=[int(c) for c in v.get("cwes") or [] if str(c).isdigit()],
                reported_by=[s for s in (vp.get("reported_by") or "").split(",") if s],
                kev=kev, epss=float(vp["epss"]) if vp.get("epss") else None,
                epss_percentile=float(vp["epss_percentile"]) if vp.get("epss_percentile") else None,
                priority=vp.get("priority"),
                id=v.get("id", "UNKNOWN"), source=(v.get("source") or {}).get("name"),
                source_url=(v.get("source") or {}).get("url"),
                severity=best.get("severity"), score=best.get("score"), vector=best.get("vector"),
                method=best.get("method"), description=v.get("description"),
                affects=[a["ref"] for a in v.get("affects") or [] if "ref" in a],
                references=[a.get("url") for a in v.get("advisories") or [] if a.get("url")],
                aliases=[r.get("id") for r in v.get("references") or [] if r.get("id")],
                published=v.get("published"), state=analysis.get("state"),
                justification=analysis.get("justification"), detail=analysis.get("detail"),
                response=list(analysis.get("response") or []),
                extra={k: val for k, val in v.items() if k in ("recommendation", "cwes", "updated")},
            ))
    return bom


# ------------------------------------------------------------------ SPDX
_SPDX_PURPOSE = {
    "APPLICATION": "application", "FRAMEWORK": "framework", "LIBRARY": "library", "CONTAINER": "container",
    "OPERATING-SYSTEM": "operating-system", "DEVICE": "device", "FIRMWARE": "firmware", "FILE": "file",
    "ARCHIVE": "library", "SOURCE": "library", "INSTALL": "application",
}


def _spdx_actor(value: str | None) -> str | None:
    if not value or value.upper() == "NOASSERTION":
        return None
    for prefix in ("Organization:", "Person:", "Tool:"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    return value.split("(")[0].strip() or None


def from_spdx(data: dict) -> Bom:
    info = data.get("creationInfo") or {}
    bom = Bom(source_format=data.get("spdxVersion", "SPDX"), timestamp=info.get("created"),
              serial=data.get("documentNamespace"))
    for creator in info.get("creators") or []:
        if creator.startswith("Tool:"):
            bom.tools.append({"name": _spdx_actor(creator)})
        else:
            if a := _spdx_actor(creator):
                bom.authors.append(a)
    comps: dict[str, Component] = {}
    for i, pkg in enumerate(data.get("packages") or []):
        purl = next((r["referenceLocator"] for r in pkg.get("externalRefs") or []
                     if r.get("referenceType") == "purl"), None)
        cpe = next((r["referenceLocator"] for r in pkg.get("externalRefs") or []
                    if r.get("referenceType", "").startswith("cpe")), None)
        lic = normalize_license(pkg.get("licenseConcluded")) or normalize_license(pkg.get("licenseDeclared"))
        c = Component(
            ref=pkg.get("SPDXID", f"SPDXRef-{i}"), name=pkg.get("name", ""), version=pkg.get("versionInfo"),
            type=_SPDX_PURPOSE.get(pkg.get("primaryPackagePurpose", ""), "library"),
            description=pkg.get("description") or pkg.get("summary"),
            supplier=_spdx_actor(pkg.get("supplier")) or _spdx_actor(pkg.get("originator")),
            licenses=[lic] if lic else [], purl=purl, cpe=cpe,
            hashes={norm_hash_alg(h["algorithm"]): h["checksumValue"] for h in pkg.get("checksums") or []},
            release_date=pkg.get("releaseDate"), eol_date=pkg.get("validUntilDate"),
            comments=pkg.get("comment"),
        )
        if pkg.get("primaryPackagePurpose") == "ARCHIVE":
            c.set("archive", "true", "source:spdx-primaryPackagePurpose")
        for fname in ("description", "supplier", "licenses", "purl", "hashes", "release_date", "eol_date", "comments"):
            if getattr(c, fname):
                c.derivations[fname] = "source"
        comps[c.ref] = c
    deps: dict[str, list[str]] = {}
    root_ids = list(data.get("documentDescribes") or [])
    for rel in data.get("relationships") or []:
        a, t, b = rel.get("spdxElementId"), rel.get("relationshipType"), rel.get("relatedSpdxElement")
        if t == "DESCRIBES" and a == data.get("SPDXID"):
            root_ids.append(b)
        elif t in ("DEPENDS_ON", "CONTAINS", "DYNAMIC_LINK", "STATIC_LINK") and a in comps and b in comps:
            deps.setdefault(a, []).append(b)
        elif t in ("DEPENDENCY_OF", "CONTAINED_BY") and a in comps and b in comps:
            deps.setdefault(b, []).append(a)
    if deps:
        for ref in comps:
            deps.setdefault(ref, [])
        bom.dependencies = deps
    if root_ids and root_ids[0] in comps:
        bom.root = comps.pop(root_ids[0])
    bom.components = list(comps.values())
    return bom

"""CycloneDX 1.6 JSON writer shared by all BOM types."""
from __future__ import annotations

from . import GUIDELINE, TOOL_NAME, __version__
from .config import NS
from .model import Bom, Component, Vulnerability
from .util import UNKNOWN, best_fix, iso_datetime, new_serial, now_iso

SPEC_VERSION = "1.6"

_PROPERTY_FIELDS = (
    "origin", "patch_status", "release_date", "eol_date", "criticality", "usage_restrictions",
    "comments", "sbom_author", "executable", "archive", "structured", "vulnerability_scan",
    "vulnerability_summary", "vulnerability_scan_gap",
)


def prop(name: str, value) -> dict:
    return {"name": f"{NS}:{name}", "value": str(value)}


def skeleton(bom_type: str, *, authors: list[str] | None = None, root: dict | None = None,
             timestamp: str | None = None, serial: str | None = None, extra_props: list[dict] | None = None) -> dict:
    meta: dict = {
        "timestamp": timestamp or now_iso(),
        "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": __version__}]},
    }
    if authors:
        meta["authors"] = [{"name": a} for a in authors]
    if root:
        meta["component"] = root
    meta["properties"] = [prop("guideline", GUIDELINE), prop("bom_type", bom_type)] + (extra_props or [])
    return {
        "bomFormat": "CycloneDX", "specVersion": SPEC_VERSION,
        "serialNumber": serial if (serial or "").startswith("urn:uuid:") else new_serial(),
        "version": 1, "metadata": meta, "components": [],
    }


def license_entries(licenses: list[str]) -> list[dict]:
    out = []
    for lic in licenses:
        if any(op in lic for op in (" AND ", " OR ", " WITH ")):
            out.append({"expression": lic})
        elif lic.startswith("LicenseRef-"):
            out.append({"license": {"name": lic}})
        else:
            out.append({"license": {"id": lic}})
    # CycloneDX allows either one expression or a list of licences, not both
    exprs = [e for e in out if "expression" in e]
    return exprs[:1] if exprs else out


def component(c: Component) -> dict:
    d: dict = {"type": c.type, "bom-ref": c.ref, "name": c.name}
    if c.version:
        d["version"] = c.version
    if c.scope:
        d["scope"] = c.scope
    if c.description:
        d["description"] = c.description
    if c.supplier:
        d["supplier"] = {"name": c.supplier}
    if c.licenses:
        d["licenses"] = license_entries(c.licenses)
    if c.purl:
        d["purl"] = c.purl
    if c.cpe:
        d["cpe"] = c.cpe
    if c.hashes:
        d["hashes"] = [{"alg": a, "content": v} for a, v in c.hashes.items()]
    for k, v in c.extra.items():
        d.setdefault(k, v)
    props = list(c.properties)
    for f in _PROPERTY_FIELDS:
        val = getattr(c, f)
        if val:
            props.append(prop(f, val))
        elif f in c.known_unknowns:
            props.append(prop(f, UNKNOWN))
    for f, how in sorted(c.derivations.items()):
        if how != "source":
            props.append(prop(f"derivation:{f}", how))
    if c.known_unknowns:
        props.append(prop("known_unknowns", ",".join(sorted(c.known_unknowns))))
    if props:
        d["properties"] = props
    return d


def vulnerability(v: Vulnerability, components: dict[str, Component]) -> dict:
    d: dict = {"bom-ref": f"vuln-{v.id}", "id": v.id}
    if v.source:
        d["source"] = {"name": v.source, **({"url": v.source_url} if v.source_url else {})}
    if v.aliases:
        d["references"] = [{"id": a, "source": {"name": "NVD" if a.startswith("CVE-") else "OSV"}} for a in v.aliases]
    rating: dict = {}
    if v.severity:
        rating["severity"] = v.severity
    if v.score is not None:
        rating["score"] = v.score
    if v.vector:
        rating["vector"] = v.vector
    if v.method:
        rating["method"] = v.method
    if rating:
        d["ratings"] = [rating]
    if v.cwes:
        d["cwes"] = v.cwes
    if v.description:
        d["description"] = v.description
    if v.references:
        d["advisories"] = [{"url": u} for u in v.references]
    if v.published:
        d["published"] = iso_datetime(v.published)
    fixes = []
    for ref, fixed in v.fixed_versions.items():
        if fixed and ref in components:
            comp = components[ref]
            target = best_fix(comp.version, fixed)
            if target:
                fixes.append(f"{comp.name} {comp.version or ''}".strip() + f": upgrade to {target}")
    if fixes:
        d["recommendation"] = "; ".join(fixes)
    d.update({k: val for k, val in v.extra.items() if k not in d})
    if v.state or v.justification or v.detail or v.response:
        analysis = {"state": v.state or "in_triage"}
        if v.justification:
            analysis["justification"] = v.justification
        if v.response:
            analysis["response"] = v.response
        if v.detail:
            analysis["detail"] = v.detail
        d["analysis"] = analysis
    d["affects"] = [{"ref": r} for r in v.affects]
    props = []
    if v.priority:
        props.append(prop("priority", v.priority))
    if v.kev:
        props += [prop(f"kev_{k}", val) for k, val in v.kev.items() if val]
    if v.epss is not None:
        props.append(prop("epss", f"{v.epss:.5f}"))
    if v.epss_percentile is not None:
        props.append(prop("epss_percentile", f"{v.epss_percentile:.5f}"))
    if v.reported_by:
        props.append(prop("reported_by", ",".join(v.reported_by)))
    if props:
        d["properties"] = props
    return d


def from_bom(bom: Bom, bom_type: str = "SBOM", extra_props: list[dict] | None = None) -> dict:
    doc = skeleton(bom_type, authors=bom.authors, root=component(bom.root) if bom.root else None,
                   timestamp=bom.timestamp, serial=bom.serial, extra_props=extra_props)
    tools = doc["metadata"]["tools"]["components"]
    seen = {(t["name"], t.get("version")) for t in tools}
    for t in bom.tools:  # keep the generators of the source SBOM; schema requires unique entries
        if t.get("name") and (t["name"], t.get("version")) not in seen:
            seen.add((t["name"], t.get("version")))
            tools.append({"type": "application", **{k: t[k] for k in ("name", "version") if t.get(k)}})
    doc["components"] = [component(c) for c in bom.components]
    if bom.dependencies is not None:
        doc["dependencies"] = [{"ref": r, "dependsOn": d} for r, d in bom.dependencies.items()]
    if bom.vulnerabilities_known or bom.vulnerabilities:
        doc["vulnerabilities"] = [vulnerability(v, bom.by_ref()) for v in bom.vulnerabilities]
    return doc

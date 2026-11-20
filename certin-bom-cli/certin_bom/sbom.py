"""Turn any CycloneDX/SPDX SBOM into a CERT-In Table 5 conformant CycloneDX 1.6 SBOM."""
from __future__ import annotations

import logging
from pathlib import Path

from . import TOOL_NAME
from .config import Config, NS
from .cyclonedx import from_bom, prop
from .fields import CRITICALITY_VALUES, SBOM_PRACTICES
from .ingest import load_bom
from .model import Bom, Component
from .vulns import osv_target
from .util import (UNKNOWN, best_fix, sort_versions, build_purl, is_known_spdx, is_set, license_restrictions, normalize_license, now_iso,
                   parse_purl, read_json, slug, version_lt)

log = logging.getLogger(__name__)

# purl type -> (archive, structured) defaults. Packages from an ecosystem registry
# are distributed as archives with a structured manifest.
_ARCHIVE_TYPES = {"maven", "npm", "pypi", "gem", "nuget", "cargo", "deb", "rpm", "apk", "composer", "hex",
                  "pub", "conda", "cocoapods", "golang", "swift", "hackage", "cran", "alpm", "oci", "docker"}
_EXEC_COMPONENT_TYPES = {"application", "operating-system", "container", "firmware", "device"}
_NONEXEC_COMPONENT_TYPES = {"library", "framework", "data", "file"}
_EXEC_EXT = (".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".sh", ".bat", ".ps1", ".app", ".msi")
_ARCHIVE_EXT = (".zip", ".jar", ".war", ".ear", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".whl", ".nupkg",
                ".deb", ".rpm", ".apk", ".gem", ".crate")
_OPEN_SOURCE_HINT = ("github.com", "gitlab.com", "apache", "eclipse", "python", "mozilla")


# ------------------------------------------------------------------ overrides
def load_overrides(path: str | Path | None) -> dict:
    if not path:
        return {"defaults": {}, "components": {}}
    data = read_json(path)
    return {"defaults": data.get("defaults") or {}, "components": data.get("components") or {}}


def _override_for(c: Component, ov: dict) -> dict:
    keys = [c.purl, (c.purl or "").split("@")[0], c.ref, c.name, f"{c.name}@{c.version}"]
    merged = dict(ov["defaults"])
    for k in keys:
        if k and k in ov["components"]:
            merged.update(ov["components"][k])
    return merged


_OVERRIDABLE = {"description", "supplier", "origin", "patch_status", "release_date", "eol_date", "criticality",
                "usage_restrictions", "comments", "executable", "archive", "structured", "cpe", "purl"}


def apply_overrides(c: Component, ov: dict) -> None:
    for key, value in _override_for(c, ov).items():
        if key in ("license", "licenses"):
            vals = value if isinstance(value, list) else [value]
            c.set("licenses", [normalize_license(v) for v in vals if normalize_license(v)], "override")
        elif key in _OVERRIDABLE:
            if str(value).lower() == UNKNOWN:
                c.known_unknowns.add(key)
            else:  # an explicit override always wins over source data
                c.set(key, str(value), "override")
        else:
            log.warning("override key %r ignored for %s", key, c.name)


# ------------------------------------------------------------------ derivations
def _first_party(c: Component, cfg: Config) -> bool:
    hay = " ".join(filter(None, [c.supplier, c.purl, c.name])).lower()
    pats = [p.lower() for p in cfg.first_party_patterns] + ([cfg.organization.lower()] if cfg.organization else [])
    return any(p and p in hay for p in pats)


def derive(c: Component, cfg: Config) -> None:
    p = parse_purl(c.purl)
    # 21 Unique Identifier
    if c.purl and not p:
        c.comments = ((c.comments + "; ") if c.comments else "") + f"invalid purl in source: {c.purl}"
        c.purl = None
    if not c.purl:
        ns = slug(c.supplier) if c.supplier else (slug(cfg.organization) if cfg.organization else None)
        c.set("purl", build_purl("generic", c.name or c.ref, c.version, ns), "derived:generic-purl")
        p = parse_purl(c.purl)
    # 4 Supplier
    if not c.supplier and p and p.get("namespace"):
        ns = p["namespace"]
        if p["type"] == "golang" and ns.startswith(("github.com/", "gitlab.com/")):
            ns = ns.split("/")[1]
        if p["type"] in ("maven", "npm", "golang", "composer", "github", "gitlab", "nuget", "docker", "oci"):
            c.set("supplier", ns.lstrip("@"), f"derived:purl-namespace({p['type']})")
    # 5 Licence - normalise to SPDX
    if c.licenses:
        c.licenses = [normalize_license(x) or x for x in c.licenses]
    # 6 Origin
    if not c.origin:
        if _first_party(c, cfg):
            c.set("origin", "proprietary (first-party)", "derived:organization-match")
        elif c.licenses and all(is_known_spdx(l) and not l.startswith("LicenseRef-") for l in c.licenses):
            c.set("origin", "open-source", "derived:spdx-licence")
        elif any("proprietary" in l.lower() or "commercial" in l.lower() for l in c.licenses):
            c.set("origin", "third-party (proprietary)", "derived:licence-text")
        elif p and p["type"] in ("github", "gitlab", "bitbucket") or any(h in (c.purl or "") for h in _OPEN_SOURCE_HINT):
            c.set("origin", "open-source", "derived:public-source-host")
    # 13 Usage restrictions
    if not c.usage_restrictions and c.licenses:
        c.set("usage_restrictions", license_restrictions(c.licenses), "derived:licence-analysis")
    # 18-20 Executable / Archive / Structured
    ext = (c.name or "").lower()
    if not c.executable:
        if c.type in _EXEC_COMPONENT_TYPES or ext.endswith(_EXEC_EXT):
            c.set("executable", "true", f"derived:component-type({c.type})")
        elif c.type in _NONEXEC_COMPONENT_TYPES:
            c.set("executable", "false", f"derived:component-type({c.type})")
    if not c.archive:
        if (p and p["type"] in _ARCHIVE_TYPES) or ext.endswith(_ARCHIVE_EXT):
            c.set("archive", "true", f"derived:purl-type({p['type'] if p else 'ext'})")
        elif p and p["type"] in ("github", "gitlab", "bitbucket") or c.type == "file":
            c.set("archive", "false", "derived:source-reference")
    if not c.structured:
        if p and p["type"] not in ("generic",):
            c.set("structured", "true", f"derived:package-manifest({p['type']})")
    # 12 Criticality
    if c.criticality and c.criticality.lower() not in CRITICALITY_VALUES:
        log.warning("%s: criticality %r is not one of %s", c.name, c.criticality, CRITICALITY_VALUES)
    if not c.criticality and cfg.default_criticality:
        c.set("criticality", cfg.default_criticality, "config:default_criticality")
    # 16 Author of SBOM data
    if not c.sbom_author:
        c.set("sbom_author", cfg.author or cfg.organization or TOOL_NAME, "config:author")


def _criticality_heuristic(bom: Bom) -> None:
    if not bom.root or not bom.dependencies:
        return
    direct = set(bom.dependencies.get(bom.root.ref, []))
    for c in bom.components:
        if c.criticality:
            continue
        if c.scope in ("optional", "excluded"):
            c.set("criticality", "low", "derived:scope")
        elif c.ref in direct:
            c.set("criticality", "high", "derived:direct-dependency")
        else:
            c.set("criticality", "medium", "derived:transitive-dependency")


def _patch_status(bom: Bom) -> None:
    by_comp: dict[str, list] = {}
    for v in bom.vulnerabilities:
        for ref in v.affects:
            by_comp.setdefault(ref, []).append(v)
    for c in bom.components + ([bom.root] if bom.root else []):
        vulns = by_comp.get(c.ref, [])
        if c.patch_status and c.derivations.get("patch_status") in ("source", "override"):
            continue
        if vulns:
            open_v = [v for v in vulns if v.state not in ("resolved", "resolved_with_pedigree", "not_affected", "false_positive")]
            fixed = sort_versions({f for v in open_v for f in v.fixed_versions.get(c.ref, [])
                                   if not c.version or version_lt(c.version, f)})
            if not open_v:
                c.set("patch_status", "no action required (all vulnerabilities fixed/not affected per VEX)", "derived:vex")
            elif fixed:
                target = best_fix(c.version, fixed)
                kev = sum(1 for v in open_v if v.kev)
                c.set("patch_status", ("URGENT - actively exploited (CISA KEV); " if kev else "")
                      + f"patch available: upgrade to {target} "
                      f"(fixes {sum(1 for v in open_v if v.fixed_versions.get(c.ref))}/{len(open_v)} open)",
                      "derived:vulnerability-fix-versions")
            elif any(c.ref in v.fixed_versions for v in open_v):  # fix data was looked up (OSV) and is empty
                c.set("patch_status", "no patch available for known vulnerabilities", "derived:vulnerability-fix-versions")
            else:
                c.set("patch_status", f"vulnerable ({len(open_v)} open); fix availability not determined - "
                                      "run with --online or check the advisory", "derived:vulnerability-list")
        elif c.vulnerability_scan:
            c.set("patch_status", "up to date: no known vulnerabilities", "derived:vulnerability-scan")


# field key -> predicate telling whether the component carries it
def field_present(c: Component, key: str, bom: Bom) -> bool:
    attr = {"license": "licenses", "unique_id": "purl"}.get(key, key)
    if key == "dependencies":
        return bom.dependencies is not None and c.ref in bom.dependencies
    if key == "vulnerabilities":
        return bool(c.vulnerability_scan) or any(c.ref in v.affects for v in bom.vulnerabilities)
    if key == "timestamp":
        return bool(bom.timestamp)
    return is_set(getattr(c, attr, None))


def _mark_unknowns(bom: Bom) -> None:
    from .fields import SBOM_FIELDS
    for c in bom.components:
        for f in SBOM_FIELDS:
            if not field_present(c, f.key, bom):
                c.known_unknowns.add(f.key)
            else:
                c.known_unknowns.discard(f.key)
        derived = sorted(k for k, how in c.derivations.items() if how.startswith("derived"))
        if not c.comments:
            notes = []
            if derived:
                notes.append("heuristically derived: " + ", ".join(derived))
            unknowns = sorted(c.known_unknowns - {"comments"})
            if unknowns:
                notes.append("known unknowns: " + ", ".join(unknowns))
            c.set("comments", "; ".join(notes) or "all CERT-In fields sourced from supplier data",
                  "derived:certin-bom-summary")
            c.known_unknowns.discard("comments")


def build_sbom(input_path: str | Path, cfg: Config, overrides_path: str | Path | None = None,
               practices: dict | None = None) -> tuple[dict, Bom]:
    bom = load_bom(input_path)
    log.info("loaded %s with %d components", bom.source_format, len(bom.components))
    bom.timestamp = bom.timestamp or now_iso()
    if cfg.author and cfg.author not in bom.authors:
        bom.authors.insert(0, cfg.author)
    ov = load_overrides(overrides_path)
    for c in bom.components:
        apply_overrides(c, ov)
        if bom.vulnerabilities_known and not c.vulnerability_scan:
            # The source SBOM carried a vulnerabilities section, so its generator scanned this
            # component - but only identifiable components (ecosystem purl or CPE) can be matched.
            if osv_target(c) or c.cpe:
                c.vulnerability_scan = "source-sbom"
                c.derivations["vulnerability_scan"] = "source:vulnerabilities-section"
            elif not any(c.ref in v.affects for v in bom.vulnerabilities):
                c.vulnerability_scan_gap = "no ecosystem purl or CPE - no vulnerability database can match it"
    if cfg.online:
        from .online import enrich_online
        enrich_online(bom, cfg.http_timeout)
    for c in bom.components:
        derive(c, cfg)
    from .vulns import postprocess, scan
    if cfg.online or cfg.osv_db:
        scan(bom, cfg)              # OSV (+ NVD), dedupe, CVSS scoring, KEV, EPSS, priority
    else:
        postprocess(bom, cfg)       # offline: still dedupe, score vectors and prioritise
    if cfg.criticality_heuristic:
        _criticality_heuristic(bom)
    _patch_status(bom)
    _mark_unknowns(bom)
    extra = [prop("source_format", bom.source_format), prop("distribution", "private")]
    for name in SBOM_PRACTICES:  # Table 5 "Practices and Processes"
        value = (practices or {}).get(name)
        extra.append(prop(f"practice:{slug(name).lower()}", value if value else UNKNOWN))
    return from_bom(bom, "SBOM", extra), bom

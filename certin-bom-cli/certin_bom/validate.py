"""Audit any CycloneDX/SPDX BOM against the CERT-In v2.0 minimum elements.

Each field is classified as:
  present   - value supplied by the BOM author / source data
  derived   - value filled heuristically or from config (cert-in:derivation:<field>)
  unknown   - explicitly declared as a known unknown (Table 5 practice "Known Unknowns")
  missing   - absent and not declared
  n/a       - not applicable (e.g. Mode for a hash)
"""
from __future__ import annotations

from . import GUIDELINE
from .config import NS
from .fields import (AIBOM_FIELDS, CBOM_FIELDS, CRITICALITY_VALUES, HBOM_COMPONENT_FIELDS, HBOM_PRODUCT_FIELDS,
                     QBOM_FIELDS, SBOM_FIELDS, SBOM_PRACTICES)
from .util import UNKNOWN, WEAK_HASHES, is_known_spdx, is_set, norm_hash_alg, parse_purl, slug

_ATTR_FOR = {"license": "licenses", "unique_id": "purl"}


# ------------------------------------------------------------------ helpers
def props_of(c: dict) -> dict[str, str]:
    return {p["name"][len(NS) + 1:]: p.get("value") for p in c.get("properties") or []
            if p.get("name", "").startswith(NS + ":")}


def _unknowns(c: dict) -> set[str]:
    return {k.strip() for k in (props_of(c).get("known_unknowns") or "").split(",") if k.strip()}


def _status(c: dict, key: str, value, na: bool = False) -> str:
    if na or key in (props_of(c).get("not_applicable") or "").split(","):
        return "n/a"
    if is_set(value):
        how = props_of(c).get(f"derivation:{_ATTR_FOR.get(key, key)}", "")
        return "derived" if how.startswith(("derived", "config")) else "present"
    if key in _unknowns(c) or (isinstance(value, str) and value.strip().lower() == UNKNOWN):
        return "unknown"
    return "missing"


def _item(c: dict, kind: str, fields, getter) -> dict:
    out = {"ref": c.get("bom-ref"), "name": c.get("name"), "kind": kind, "fields": {}}
    for f in fields:
        value, na = getter(f.key)
        out["fields"][f.key] = {"label": f.label, "status": _status(c, f.key, value, na)}
    return out


def _check(cid: str, ok: bool | None, message: str) -> dict:
    return {"id": cid, "status": "pass" if ok else ("warn" if ok is None else "fail"), "message": message}


# ------------------------------------------------------------------ SBOM
def _sbom_items(doc: dict) -> tuple[list[dict], list[dict]]:
    deps = {d.get("ref") for d in doc.get("dependencies") or []}
    affected = {a.get("ref") for v in doc.get("vulnerabilities") or [] for a in v.get("affects") or []}
    meta = doc.get("metadata") or {}
    doc_author = bool(meta.get("authors") or meta.get("manufacturer") or meta.get("supplier"))
    items, checks = [], []
    weak_only = bad_purl = bad_crit = 0
    for c in _all_components(doc.get("components")):
        p = props_of(c)

        def get(key, c=c, p=p):
            if key == "name":
                return c.get("name"), False
            if key == "version":
                return c.get("version"), False
            if key == "description":
                return c.get("description"), False
            if key == "supplier":
                return ((c.get("supplier") or {}).get("name") or (c.get("manufacturer") or {}).get("name")
                        or c.get("publisher") or (c.get("authors") or [{}])[0].get("name")), False
            if key == "license":
                return c.get("licenses"), False
            if key == "dependencies":
                return (True if c.get("bom-ref") in deps else None), False
            if key == "vulnerabilities":
                return (True if c.get("bom-ref") in affected or is_set(p.get("vulnerability_scan")) else None), False
            if key == "hashes":
                return c.get("hashes"), False
            if key == "sbom_author":
                return p.get("sbom_author") or (True if doc_author else None), False
            if key == "timestamp":
                return meta.get("timestamp"), False
            if key == "unique_id":
                return (c.get("purl") if parse_purl(c.get("purl")) else None) or c.get("cpe") or c.get("swid") \
                    or c.get("omniborId"), False
            return p.get(key), False

        items.append(_item(c, c.get("type", "library"), SBOM_FIELDS, get))
        algs = {norm_hash_alg(h.get("alg", "")) for h in c.get("hashes") or []}
        if algs and algs <= WEAK_HASHES:
            weak_only += 1
        if c.get("purl") and not parse_purl(c["purl"]):
            bad_purl += 1
        if p.get("criticality") and p["criticality"].lower() not in CRITICALITY_VALUES + (UNKNOWN,):
            bad_crit += 1
    licences = [l.get("license", {}).get("id") or l.get("expression") for c in _all_components(doc.get("components"))
                for l in c.get("licenses") or []]
    bad_lic = sorted({l for l in licences if l and not is_known_spdx(l)})
    checks += [
        _check("dependency-graph", "dependencies" in doc, "Dependency graph present (Table 5: Component Dependencies)"),
        _check("vulnerability-data", "vulnerabilities" in doc or None,
               "Vulnerability section present (or vulnerability scan declared per component)"),
        _check("weak-hashes", weak_only == 0 or None, f"{weak_only} component(s) carry only MD5/SHA-1 hashes"),
        _check("purl-syntax", bad_purl == 0, f"{bad_purl} invalid purl(s)"),
        _check("criticality-values", bad_crit == 0 or None, f"{bad_crit} criticality value(s) outside {CRITICALITY_VALUES}"),
        _check("spdx-licences", not bad_lic or None,
               "Licences use SPDX identifiers" if not bad_lic else f"Non-SPDX licence ids: {', '.join(bad_lic[:8])}"),
    ]
    vulns = doc.get("vulnerabilities") or []
    untriaged = sum(1 for v in vulns if not (v.get("analysis") or {}).get("state"))
    if vulns:
        checks.append(_check("vex-status", untriaged == 0 or None,
                             f"{untriaged}/{len(vulns)} vulnerabilities without VEX status (run `certin-bom vex`)"))
    vs = vulnerability_summary(doc)
    if vs["components"]:
        gaps = vs["coverage_gaps"]
        checks.append(_check("vulnerability-coverage", not gaps or None,
                             f"{vs['components_scanned']}/{vs['components']} components checked against a vulnerability "
                             f"source ({vs['coverage_pct']}%)" + (f"; not covered: {', '.join(g['name'] for g in gaps[:6])}"
                                                                  if gaps else "")))
    if vs["open_kev"]:
        checks.append(_check("known-exploited", None,
                             f"{vs['open_kev']} open vulnerabilities are in CISA KEV (actively exploited)"))
    if vs["malicious"]:
        checks.append(_check("malicious-packages", None, f"{vs['malicious']} known malicious package(s) present"))
    mprops = props_of(meta)
    missing_pr = [n for n in SBOM_PRACTICES if not is_set(mprops.get(f"practice:{slug(n).lower()}"))]
    checks.append(_check("practices", not missing_pr or None,
                         "Practices and Processes declared" if not missing_pr
                         else f"Practices not declared: {', '.join(missing_pr)} (use --practices)"))
    return items, checks


_CLOSED = ("resolved", "resolved_with_pedigree", "not_affected", "false_positive")
_SEV_ORDER = ("critical", "high", "medium", "low", "none", "unscored")


def vulnerability_summary(doc: dict) -> dict:
    comps = [c for c in _all_components(doc.get("components")) if c.get("type") != "cryptographic-asset"]
    vulns = doc.get("vulnerabilities") or []
    affected = {a.get("ref") for v in vulns for a in v.get("affects") or []}
    scanned, gaps = 0, []
    for c in comps:
        p = props_of(c)
        if c.get("bom-ref") in affected or is_set(p.get("vulnerability_scan")):
            scanned += 1
        else:
            gaps.append({"name": c.get("name"), "ref": c.get("bom-ref"),
                         "reason": p.get("vulnerability_scan_gap") or "not scanned"})
    open_v = [v for v in vulns if (v.get("analysis") or {}).get("state") not in _CLOSED]
    by_sev = {s: 0 for s in _SEV_ORDER}
    for v in open_v:
        sev = ((v.get("ratings") or [{}])[0].get("severity") or "unscored").lower()
        by_sev[sev if sev in by_sev else "unscored"] += 1
    vp = lambda v: props_of(v)  # noqa: E731
    ranked = sorted(open_v, key=lambda v: (vp(v).get("priority") or "P9", -float(vp(v).get("epss") or 0)))
    names = {c.get("bom-ref"): f"{c.get('name')}@{c.get('version', '')}" for c in comps}
    return {
        "components": len(comps), "components_scanned": scanned,
        "coverage_pct": round(100 * scanned / len(comps), 1) if comps else 0.0, "coverage_gaps": gaps,
        "total": len(vulns), "open": len(open_v), "by_severity": by_sev,
        "open_kev": sum(1 for v in open_v if vp(v).get("kev_date_added")),
        "malicious": sum(1 for v in open_v if str(v.get("id", "")).startswith("MAL-")),
        "sources": sorted({s for v in vulns for s in (vp(v).get("reported_by") or (v.get("source") or {}).get("name", "")).split(",") if s}),
        "top": [{"id": v.get("id"), "priority": vp(v).get("priority"),
                 "severity": (v.get("ratings") or [{}])[0].get("severity"),
                 "score": (v.get("ratings") or [{}])[0].get("score"), "epss": vp(v).get("epss"),
                 "kev": bool(vp(v).get("kev_date_added")),
                 "components": [names.get(a.get("ref"), a.get("ref")) for a in v.get("affects") or []],
                 "fix": v.get("recommendation")} for v in ranked[:15]],
    }


# ------------------------------------------------------------------ CBOM / QBOM
def _cbom_items(components: list[dict]) -> list[dict]:
    items = []
    for c in components:
        cp = c.get("cryptoProperties") or {}
        kind = cp.get("assetType")
        if kind == "related-crypto-material":
            kind = "key"
        if kind not in CBOM_FIELDS:
            continue
        sub = (cp.get("algorithmProperties") or cp.get("relatedCryptoMaterialProperties")
               or cp.get("protocolProperties") or cp.get("certificateProperties") or {})

        def get(key, c=c, cp=cp, sub=sub, kind=kind):
            direct = {
                "name": c.get("name"), "asset_type": cp.get("assetType"), "oid": cp.get("oid"),
                "primitive": sub.get("primitive"), "crypto_functions": sub.get("cryptoFunctions"),
                "classical_security_level": sub.get("classicalSecurityLevel"), "id": sub.get("id"),
                "state": sub.get("state"), "size": sub.get("size"), "creation_date": sub.get("creationDate"),
                "activation_date": sub.get("activationDate"), "version": sub.get("version"),
                "cipher_suites": sub.get("cipherSuites"), "subject_name": sub.get("subjectName"),
                "issuer_name": sub.get("issuerName"), "not_valid_before": sub.get("notValidBefore"),
                "not_valid_after": sub.get("notValidAfter"), "signature_algorithm_ref": sub.get("signatureAlgorithmRef"),
                "subject_public_key_ref": sub.get("subjectPublicKeyRef"), "certificate_format": sub.get("certificateFormat"),
                "certificate_extension": sub.get("certificateExtension"),
            }
            if key == "mode":
                return sub.get("mode"), sub.get("primitive") not in (None, "block-cipher", "unknown") and not sub.get("mode")
            return direct.get(key), False

        items.append(_item(c, kind, CBOM_FIELDS[kind], get))
    return items


def _qbom_items(doc: dict) -> tuple[list[dict], list[dict]]:
    root = (doc.get("metadata") or {}).get("component") or {}
    comps = list(_all_components(doc.get("components")))
    crypto = [c for c in comps if c.get("type") == "cryptographic-asset"]
    p = props_of(root)

    def get(key):
        return {
            "model_name": root.get("name") if root.get("name") != "system-under-assessment" else None,
            "version": root.get("version"),
            "vendor_origin": (root.get("manufacturer") or root.get("supplier") or {}).get("name"),
            "license": root.get("licenses"),
            "cryptographic_asset": crypto,
            "communication_protocol": p.get("communication_protocol"),
            "hardware": [c for c in comps if c.get("type") == "device"] or p.get("hardware"),
            "software_dependencies": [c for c in comps if c.get("type") in ("library", "framework", "firmware")],
            "environmental_impact": p.get("environmental_impact"),
            "vulnerabilities": doc.get("vulnerabilities") or p.get("vulnerability_scan"),
            "attestations": doc.get("signature"),
        }.get(key), False

    items = [_item(root, "quantum system", QBOM_FIELDS, get)] + _cbom_items(crypto)
    checks = [_check("crypto-inventory", bool(crypto), f"{len(crypto)} cryptographic assets inventoried"),
              _check("readiness", None, f"Quantum readiness: {p.get('qbom:quantum_readiness_pct', '?')}% of assets quantum-resistant")]
    return items, checks


# ------------------------------------------------------------------ AIBOM
def _aibom_items(doc: dict) -> list[dict]:
    root = (doc.get("metadata") or {}).get("component") or {}
    comps = list(_all_components(doc.get("components")))
    models = [c for c in [root] + comps if c.get("type") == "machine-learning-model"]
    deps = {d["ref"]: d.get("dependsOn") or [] for d in doc.get("dependencies") or [] if "ref" in d}
    data_refs = {c["bom-ref"] for c in comps if c.get("type") == "data"}
    items = []
    for m in models:
        card = m.get("modelCard") or {}
        params = card.get("modelParameters") or {}
        cons = card.get("considerations") or {}
        p = props_of(m)
        ref = m.get("bom-ref")
        affected = [v for v in doc.get("vulnerabilities") or [] for a in v.get("affects") or []
                    if a.get("ref") == ref or a.get("ref") in deps.get(ref, [])]

        def get(key, m=m, params=params, cons=cons, p=p, ref=ref, affected=affected, card=card):
            env = cons.get("environmentalConsiderations")
            return {
                "model_name": m.get("name"), "model_version": m.get("version"), "model_type": params.get("task"),
                "model_developer": (m.get("supplier") or m.get("manufacturer") or {}).get("name")
                                   or (m.get("authors") or [{}])[0].get("name"),
                "model_licensing": m.get("licenses"),
                "software_dependencies": [d for d in deps.get(ref, []) if d not in data_refs],
                "ml_models_algorithms": params.get("modelArchitecture") or params.get("architectureFamily")
                                        or (params.get("approach") or {}).get("type"),
                "performance_metrics": (card.get("quantitativeAnalysis") or {}).get("performanceMetrics"),
                "data_source": p.get("data_source"), "data_sets": params.get("datasets"),
                "hardware": p.get("hardware"), "security_requirements": p.get("security_requirements"),
                "input": params.get("inputs"), "output": params.get("outputs"), "intended_usage": cons.get("useCases"),
                "out_of_scope_usage": p.get("out_of_scope_usage"),
                "environmental_impact": env or p.get("environmental_impact"),
                "vulnerabilities": affected or p.get("vulnerability_scan"),
                "attestations": doc.get("signature"),
            }.get(key), False

        items.append(_item(m, "machine-learning-model", AIBOM_FIELDS, get))
    return items


# ------------------------------------------------------------------ HBOM
def _hbom_items(doc: dict) -> list[dict]:
    root = (doc.get("metadata") or {}).get("component") or {}
    items = []

    def org(c, which):
        return (c.get(which) or {}).get("name"), (c.get(which) or {}).get("address")

    p = props_of(root)

    def get_root(key):
        man, man_loc = org(root, "manufacturer")
        sup, sup_loc = org(root, "supplier")
        return {"product_name": root.get("name"), "product_version": root.get("version"),
                "product_details": root.get("description"), "warranty_amc": p.get("warranty_amc"),
                "manufacturer_name": man, "manufacturer_location": man_loc,
                "manufacturing_date": p.get("manufacturing_date"), "supplier_information": sup,
                "supplier_location": sup_loc, "model_number": p.get("model_number"),
                "serial_number": p.get("serial_number")}.get(key), False

    if root:
        items.append(_item(root, "product", HBOM_PRODUCT_FIELDS, get_root))
    for c in _all_components(doc.get("components")):
        if c.get("type") != "device":
            continue
        cp = props_of(c)

        def get(key, c=c, cp=cp):
            sup, sup_loc = org(c, "supplier")
            if key == "sub_component":
                return c.get("components") or cp.get("sub_component"), False
            return {"name": c.get("name"), "supplier_information": sup, "supplier_location": sup_loc,
                    "license": c.get("licenses")}.get(key, cp.get(key)), False

        items.append(_item(c, "hardware component", HBOM_COMPONENT_FIELDS, get))
    return items


# ------------------------------------------------------------------ driver
def _all_components(components):
    for c in components or []:
        yield c
        yield from _all_components(c.get("components"))


def detect_type(doc: dict) -> str:
    t = props_of(doc.get("metadata") or {}).get("bom_type")
    if t:
        return t.upper()
    comps = list(_all_components(doc.get("components")))
    root = (doc.get("metadata") or {}).get("component") or {}
    if root.get("type") == "machine-learning-model" or any(c.get("type") == "machine-learning-model" for c in comps):
        return "AIBOM"
    crypto = sum(1 for c in comps if c.get("type") == "cryptographic-asset")
    if crypto and crypto >= len(comps) / 2:
        return "CBOM"
    if root.get("type") == "device" and comps and all(c.get("type") == "device" for c in comps):
        return "HBOM"
    return "SBOM"


def validate(doc: dict, bom_type: str | None = None) -> dict:
    if "spdxVersion" in doc:  # audit SPDX as-is by mapping it to CycloneDX without enrichment
        from .cyclonedx import from_bom
        from .ingest import from_spdx
        doc = from_bom(from_spdx(doc), "SBOM")
    bom_type = (bom_type or detect_type(doc)).upper()
    meta = doc.get("metadata") or {}
    checks = [
        _check("format", doc.get("bomFormat") == "CycloneDX"
               and tuple(int(x) for x in str(doc.get("specVersion", "0.0")).split(".")[:2] if x.isdigit()) >= (1, 4),
               f"Machine-readable format: {doc.get('bomFormat')} {doc.get('specVersion')} (Table 5: Automation Support)"),
        _check("serial-number", bool(doc.get("serialNumber")), "Unique BOM serial number"),
        _check("timestamp", bool(meta.get("timestamp")), "Timestamp of BOM assembly"),
        _check("author", bool(meta.get("authors") or meta.get("manufacturer") or meta.get("supplier")) or None,
               "BOM author/organisation recorded in metadata"),
        _check("signature", bool(doc.get("signature")) or None,
               "Digitally signed (5.3.3.2 / Attestations)" if doc.get("signature") else "Not signed (run `certin-bom sign`)"),
    ]
    if bom_type == "SBOM":
        items, extra = _sbom_items(doc)
        checks += extra
    elif bom_type == "CBOM":
        items = _cbom_items(list(_all_components(doc.get("components"))))
        checks.append(_check("algorithm-list", any(i["kind"] == "algorithm" for i in items), "Algorithm list present"))
    elif bom_type == "QBOM":
        items, extra = _qbom_items(doc)
        checks += extra
    elif bom_type == "AIBOM":
        items = _aibom_items(doc)
        checks.append(_check("model-present", bool(items), f"{len(items)} AI model(s) described"))
    elif bom_type == "HBOM":
        items = _hbom_items(doc)
    else:
        raise ValueError(f"unknown BOM type {bom_type}")

    totals = {"present": 0, "derived": 0, "unknown": 0, "missing": 0, "n/a": 0}
    coverage: dict[str, dict] = {}
    for it in items:
        for key, f in it["fields"].items():
            totals[f["status"]] += 1
            cov = coverage.setdefault(f"{it['kind']}:{key}" if bom_type in ("CBOM", "QBOM", "HBOM") else key,
                                      {"label": f["label"], "kind": it["kind"], **{s: 0 for s in totals}})
            cov[f["status"]] += 1
    applicable = sum(v for k, v in totals.items() if k != "n/a")
    completeness = round(100 * (totals["present"] + totals["derived"]) / applicable, 1) if applicable else 0.0
    conformance = round(100 * (applicable - totals["missing"]) / applicable, 1) if applicable else 0.0
    failed = [c for c in checks if c["status"] == "fail"]
    if not items:
        verdict = "NO ITEMS"
    elif conformance == 100 and not failed:
        verdict = "CONFORMANT" if completeness >= 80 else "CONFORMANT (many known unknowns)"
    else:
        verdict = "NON-CONFORMANT"
    return {
        "guideline": GUIDELINE, "bom_type": bom_type, "serial_number": doc.get("serialNumber"),
        "document_checks": checks, "items": items, "field_coverage": coverage,
        "vulnerabilities": vulnerability_summary(doc) if bom_type in ("SBOM", "AIBOM", "QBOM") else None,
        "summary": {"items": len(items), **totals, "completeness_pct": completeness,
                    "conformance_pct": conformance, "verdict": verdict},
    }

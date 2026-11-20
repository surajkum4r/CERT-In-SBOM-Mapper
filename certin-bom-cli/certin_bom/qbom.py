"""QBOM generator (CERT-In Table 8): quantum device/system elements plus a
quantum-risk assessment of every cryptographic asset (Table 9) from a CBOM.
"""
from __future__ import annotations

import copy

from .config import NS
from .crypto_catalog import ALGORITHMS
from .cyclonedx import license_entries, prop, skeleton
from .util import UNKNOWN, build_purl, is_set, normalize_license, slug

PRIORITY = {
    "broken": "P0 - replace now (classically broken)",
    "hndl": "P1 - harvest-now-decrypt-later exposure: move key exchange to ML-KEM/hybrid",
    "signature": "P2 - migrate signatures/certificates to ML-DSA/SLH-DSA before a CRQC",
    "unknown": "P2 - investigate (algorithm parameters not visible)",
    "weakened": "P3 - increase symmetric key/hash size (Grover)",
    "resistant": "none - quantum-resistant",
}
_RANK = {"broken": 0, "vulnerable": 1, "unknown": 2, "weakened": 3, "resistant": 4}


def _prop(comp: dict, name: str):
    for p in comp.get("properties") or []:
        if p.get("name") == f"{NS}:{name}":
            return p.get("value")
    return None


def _set_prop(comp: dict, name: str, value) -> None:
    props = [p for p in comp.get("properties") or [] if p.get("name") != f"{NS}:{name}"]
    props.append(prop(name, value))
    comp["properties"] = props


def _worst(risks: list[str]) -> str:
    risks = [r for r in risks if r] or [UNKNOWN]
    return min(risks, key=lambda r: _RANK.get(r, 2))


def assess(components: list[dict]) -> dict:
    """Annotate crypto components with quantum risk + migration priority; return summary."""
    by_ref = {c["bom-ref"]: c for c in components}

    def alg_risk(ref: str | None) -> str:
        c = by_ref.get(ref or "")
        return (_prop(c, "quantum_risk") or UNKNOWN) if c else UNKNOWN

    counts: dict[str, int] = {}
    for c in components:
        cp = c.get("cryptoProperties") or {}
        kind = cp.get("assetType")
        if kind == "algorithm":
            risk = _prop(c, "quantum_risk") or ALGORITHMS.get(c["name"], {}).get("quantum", UNKNOWN)
            primitive = (cp.get("algorithmProperties") or {}).get("primitive")
            if risk == "vulnerable":
                bucket = "hndl" if primitive in ("pke", "key-agree", "kem") else "signature"
            else:
                bucket = risk if risk in PRIORITY else "unknown"
        elif kind == "certificate":
            props = cp.get("certificateProperties") or {}
            key = by_ref.get(props.get("subjectPublicKeyRef") or "")
            key_alg = ((key or {}).get("cryptoProperties", {}).get("relatedCryptoMaterialProperties") or {}).get("algorithmRef")
            risk = _worst([alg_risk(props.get("signatureAlgorithmRef")), alg_risk(key_alg)])
            bucket = risk if risk in ("broken", "resistant", "unknown") else "signature"
        elif kind == "related-crypto-material":
            rcm = cp.get("relatedCryptoMaterialProperties") or {}
            risk = alg_risk(rcm.get("algorithmRef")) if rcm.get("algorithmRef") else UNKNOWN
            bucket = risk if risk in ("broken", "resistant", "unknown", "weakened") else "hndl"
        elif kind == "protocol":
            suites = (cp.get("protocolProperties") or {}).get("cipherSuites") or []
            risk = _worst([_prop(c, "quantum_risk") or UNKNOWN] + [alg_risk(a) for s in suites for a in s.get("algorithms", [])])
            # TLS/SSH/IPsec with classical key exchange is the main HNDL exposure
            bucket = "broken" if risk == "broken" else ("resistant" if risk == "resistant" else "hndl")
            risk = "vulnerable" if bucket == "hndl" else risk
        else:
            continue
        _set_prop(c, "quantum_risk", risk)
        _set_prop(c, "migration_priority", PRIORITY[bucket])
        counts[risk] = counts.get(risk, 0) + 1
    total = sum(counts.values())
    ready = counts.get("resistant", 0)
    return {"total_assets": total, "by_risk": counts,
            "quantum_readiness_pct": round(100 * ready / total, 1) if total else 0.0}


def _entity(value) -> tuple[str | None, str | None]:
    if isinstance(value, dict):
        return value.get("name"), value.get("origin") or value.get("location") or value.get("country")
    return (value, None) if value else (None, None)


def build_qbom(cbom: dict, device: dict | None = None, author: str | None = None) -> dict:
    device = device or {}
    components = copy.deepcopy([c for c in cbom.get("components") or [] if c.get("type") == "cryptographic-asset"])
    summary = assess(components)
    unknowns: list[str] = []

    def val(key, v):
        if not is_set(v):
            unknowns.append(key)
            return None
        return v

    name = val("model_name", device.get("model_name")) or "system-under-assessment"
    version = val("version", device.get("version"))
    vendor, origin = _entity(device.get("vendor"))
    root: dict = {"type": "device" if device else "application", "bom-ref": f"qbom/{slug(name)}", "name": name}
    if version:
        root["version"] = version
    if val("vendor_origin", vendor):
        root["manufacturer"] = {"name": vendor, **({"address": {"country": origin}} if origin else {})}
        root["supplier"] = {"name": vendor}
    lic = [normalize_license(x) for x in (device.get("licenses") or []) if normalize_license(x)]
    if val("license", lic):
        root["licenses"] = license_entries(lic)
    props = []
    if origin:
        props.append(prop("vendor_origin", f"{vendor} ({origin})"))
    protocols = list(device.get("communication_protocols") or [])
    protocols += [c["name"] for c in components if c["cryptoProperties"].get("assetType") == "protocol"]
    if val("communication_protocol", protocols):
        props.append(prop("communication_protocol", "; ".join(protocols)))
    env = device.get("environmental_impact")
    if val("environmental_impact", env):
        props.append(prop("environmental_impact", env if isinstance(env, str) else "; ".join(f"{k}={v}" for k, v in env.items())))
    if not components:
        unknowns.append("cryptographic_asset")

    sub: list[dict] = []
    hardware = device.get("hardware") or []
    if val("hardware", hardware):
        for i, h in enumerate(hardware):
            h = h if isinstance(h, dict) else {"name": str(h)}
            hw = {"type": "device", "bom-ref": f"qbom/hw/{i}-{slug(h.get('name', 'hw'))}", "name": h.get("name", f"hardware-{i}")}
            if h.get("description") or h.get("type"):
                hw["description"] = h.get("description") or h.get("type")
            sub.append(hw)
    software = device.get("software_dependencies") or []
    if val("software_dependencies", software):
        for i, s in enumerate(software):
            s = s if isinstance(s, dict) else {"name": str(s)}
            comp = {"type": "library", "bom-ref": f"qbom/sw/{i}-{slug(s.get('name', 'sw'))}", "name": s.get("name", f"software-{i}")}
            if s.get("version"):
                comp["version"] = s["version"]
            comp["purl"] = s.get("purl") or build_purl("generic", comp["name"], s.get("version"))
            sub.append(comp)

    vulns_doc = []
    vulns = device.get("vulnerabilities")
    if isinstance(vulns, list) and vulns:
        for v in vulns:
            vulns_doc.append({"id": v.get("id", "UNKNOWN"), **({"description": v["description"]} if v.get("description") else {}),
                              **({"ratings": [{"severity": v["severity"]}]} if v.get("severity") else {}),
                              "affects": [{"ref": root["bom-ref"]}]})
    elif isinstance(vulns, str) and is_set(vulns):
        props.append(prop("vulnerability_scan", vulns))
    else:
        unknowns.append("vulnerabilities")
    props += [prop("qbom:quantum_readiness_pct", summary["quantum_readiness_pct"]),
              prop("qbom:assets_total", summary["total_assets"])]
    props += [prop(f"qbom:assets_{k}", v) for k, v in sorted(summary["by_risk"].items())]
    if unknowns:
        props.append(prop("known_unknowns", ",".join(unknowns)))
    root["properties"] = props

    doc = skeleton("QBOM", authors=[author] if author else None, root=root)
    doc["components"] = sub + components
    doc["dependencies"] = [{"ref": root["bom-ref"], "dependsOn": [c["bom-ref"] for c in sub + components]}] + \
        [d for d in cbom.get("dependencies") or []]
    if vulns_doc:
        doc["vulnerabilities"] = vulns_doc
    return doc

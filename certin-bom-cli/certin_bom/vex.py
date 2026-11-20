"""VEX (CycloneDX) and CSAF 2.0 VEX-profile generation - CERT-In section 6.

Every vulnerability in the SBOM gets one of the four CERT-In statuses:
Not affected / Affected / Fixed / Under Investigation (default until triaged).
"""
from __future__ import annotations

import copy

from . import TOOL_NAME, __version__
from .cyclonedx import prop, skeleton
from .fields import VEX_STATUS, cdx_state_to_certin
from .util import now_iso, read_json

# triage file "status" -> CycloneDX analysis.state
STATUS_TO_CDX = {"not_affected": "not_affected", "affected": "exploitable", "fixed": "resolved",
                 "under_investigation": "in_triage"}
CDX_JUSTIFICATIONS = {"code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
                      "requires_environment", "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter",
                      "protected_by_mitigating_control"}
# CycloneDX justification -> CSAF flag label
CSAF_FLAG = {"code_not_present": "vulnerable_code_not_present", "code_not_reachable": "vulnerable_code_not_in_execute_path",
             "requires_configuration": "vulnerable_code_cannot_be_controlled_by_adversary",
             "requires_dependency": "component_not_present", "requires_environment": "vulnerable_code_cannot_be_controlled_by_adversary",
             "protected_by_compiler": "inline_mitigations_already_exist", "protected_at_runtime": "inline_mitigations_already_exist",
             "protected_at_perimeter": "inline_mitigations_already_exist",
             "protected_by_mitigating_control": "inline_mitigations_already_exist"}


def load_triage(path: str | None) -> dict:
    """Triage file: {"CVE-2021-44228": {"status": "not_affected", "justification": "code_not_reachable",
    "detail": "...", "response": ["update"], "components": ["pkg:maven/..."]}}"""
    if not path:
        return {}
    data = read_json(path)
    for vid, t in data.items():
        if t.get("status") not in STATUS_TO_CDX:
            raise ValueError(f"{vid}: status must be one of {sorted(STATUS_TO_CDX)}")
        if t.get("justification") and t["justification"] not in CDX_JUSTIFICATIONS:
            raise ValueError(f"{vid}: justification must be one of {sorted(CDX_JUSTIFICATIONS)}")
    return data


def _triage_for(v: dict, triage: dict) -> dict | None:
    ids = [v.get("id")] + [r.get("id") for r in v.get("references") or []]
    return next((triage[i] for i in ids if i in triage), None)


def apply_triage(sbom: dict, triage: dict) -> dict:
    out = copy.deepcopy(sbom)
    for v in out.get("vulnerabilities") or []:
        t = _triage_for(v, triage)
        analysis = v.get("analysis") or {}
        if t:
            analysis = {"state": STATUS_TO_CDX[t["status"]]}
            if t.get("justification"):
                analysis["justification"] = t["justification"]
            if t.get("response"):
                analysis["response"] = t["response"]
            if t.get("detail"):
                analysis["detail"] = t["detail"]
            analysis["lastUpdated"] = now_iso()
        analysis.setdefault("state", "in_triage")
        v["analysis"] = analysis
    return out


def cyclonedx_vex(sbom: dict, triage: dict, author: str | None = None) -> dict:
    """Standalone CycloneDX VEX referencing the SBOM via BOM-Link."""
    src = apply_triage(sbom, triage)
    serial = sbom.get("serialNumber", "urn:uuid:unknown")
    link = f"{serial}/{sbom.get('version', 1)}#"
    doc = skeleton("VEX", authors=[author] if author else None, extra_props=[prop("describes_sbom", serial)])
    doc.pop("components")
    vulns = []
    for v in src.get("vulnerabilities") or []:
        nv = {k: v[k] for k in ("bom-ref", "id", "source", "references", "ratings", "description", "recommendation",
                                "advisories", "published", "analysis") if k in v}
        nv["affects"] = [{"ref": link + a["ref"]} for a in v.get("affects") or []]
        nv["properties"] = [prop("vex_status", VEX_STATUS[cdx_state_to_certin(v["analysis"]["state"])]["label"])]
        vulns.append(nv)
    doc["vulnerabilities"] = vulns
    return doc


def csaf_vex(sbom: dict, triage: dict, publisher: str, namespace: str, tracking_id: str | None = None) -> dict:
    """CSAF 2.0 document using the csaf_vex profile."""
    src = apply_triage(sbom, triage)
    comps = {c["bom-ref"]: c for c in src.get("components") or []}
    root = (src.get("metadata") or {}).get("component") or {}
    if root.get("bom-ref"):
        comps[root["bom-ref"]] = root
    product_ids: dict[str, str] = {}
    branches = []
    for ref, c in comps.items():
        pid = f"CSAFPID-{len(product_ids) + 1:04d}"
        product_ids[ref] = pid
        helper = {"purl": c["purl"]} if c.get("purl") else {}
        name = f"{c.get('name')} {c.get('version', '')}".strip()
        branches.append({"category": "product_version", "name": c.get("version") or "unspecified",
                         "product": {"name": name, "product_id": pid,
                                     **({"product_identification_helper": helper} if helper else {})}})
    now = now_iso()
    vulns = []
    for v in src.get("vulnerabilities") or []:
        status_key = VEX_STATUS[cdx_state_to_certin(v["analysis"]["state"])]["csaf"]
        pids = [product_ids[a["ref"]] for a in v.get("affects") or [] if a["ref"] in product_ids]
        if not pids:
            continue
        entry: dict = {"product_status": {status_key: pids}}
        vid = v.get("id", "")
        cve = vid if vid.startswith("CVE-") else next((r["id"] for r in v.get("references") or []
                                                         if r.get("id", "").startswith("CVE-")), None)
        if cve:
            entry["cve"] = cve
        system = (v.get("source") or {}).get("name") or ("CVE" if vid.startswith("CVE-") else "unspecified")
        entry["ids"] = [{"system_name": system, "text": vid}]
        notes = [{"category": "description", "text": v.get("description") or vid, "title": "Vulnerability description"}]
        entry["notes"] = notes
        a = v["analysis"]
        if status_key == "known_not_affected":
            flag = CSAF_FLAG.get(a.get("justification", ""))
            if flag:
                entry["flags"] = [{"label": flag, "product_ids": pids}]
            entry["threats"] = [{"category": "impact", "details": a.get("detail") or "Not affected per vendor analysis",
                                 "product_ids": pids}]
        elif status_key == "known_affected":
            entry["remediations"] = [{"category": "vendor_fix" if v.get("recommendation") else "none_available",
                                      "details": v.get("recommendation") or a.get("detail") or "Remediation under development",
                                      "product_ids": pids}]
        if v.get("ratings") and v["ratings"][0].get("vector", "").startswith("CVSS:3"):
            r = v["ratings"][0]
            entry["scores"] = [{"products": pids, "cvss_v3": {
                "version": r["vector"].split("/")[0].split(":")[1], "vectorString": r["vector"],
                "baseScore": r.get("score") or 0.0, "baseSeverity": (r.get("severity") or "none").upper()}}]
        vulns.append(entry)
    product_name = root.get("name") or "product"
    return {
        "document": {
            "category": "csaf_vex", "csaf_version": "2.0", "lang": "en",
            "title": f"VEX for {product_name}",
            "publisher": {"category": "vendor", "name": publisher, "namespace": namespace},
            "notes": [{"category": "summary", "title": "Scope",
                       "text": f"Exploitability status of vulnerabilities in the SBOM {sbom.get('serialNumber', '')}"}],
            "tracking": {
                "id": tracking_id or f"VEX-{product_name}-{now[:10]}", "status": "interim",
                "version": "1", "initial_release_date": now, "current_release_date": now,
                "revision_history": [{"date": now, "number": "1", "summary": "Initial VEX"}],
                "generator": {"engine": {"name": TOOL_NAME, "version": __version__}},
            },
        },
        "product_tree": {"branches": [{"category": "vendor", "name": publisher,
                                       "branches": [{"category": "product_name", "name": product_name,
                                                     "branches": branches}]}]},
        "vulnerabilities": vulns,
    }

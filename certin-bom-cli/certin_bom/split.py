"""Public / private SBOM split (CERT-In 5.3.2): vulnerability data stays private."""
from __future__ import annotations

import copy

from .config import NS


def _strip(component: dict, private: set[str]) -> None:
    # drop each private property and its provenance marker (cert-in:derivation:<field>)
    derivations = {f"{NS}:derivation:{name.split(':', 1)[1]}" for name in private if ":" in name}
    props = [p for p in component.get("properties") or [] if p.get("name") not in private | derivations]
    if props:
        component["properties"] = props
    else:
        component.pop("properties", None)
    for child in component.get("components") or []:
        _strip(child, private)


def _set_distribution(doc: dict, value: str) -> None:
    props = [p for p in doc["metadata"].get("properties") or [] if p.get("name") != f"{NS}:distribution"]
    props.append({"name": f"{NS}:distribution", "value": value})
    doc["metadata"]["properties"] = props


def split(doc: dict, private_properties: list[str]) -> tuple[dict, dict]:
    private_doc = copy.deepcopy(doc)
    private_doc.pop("signature", None)
    _set_distribution(private_doc, "private")
    public_doc = copy.deepcopy(private_doc)
    public_doc.pop("vulnerabilities", None)
    private = set(private_properties)
    for c in public_doc.get("components") or []:
        _strip(c, private)
    if public_doc["metadata"].get("component"):
        _strip(public_doc["metadata"]["component"], private)
    _set_distribution(public_doc, "public")
    return public_doc, private_doc

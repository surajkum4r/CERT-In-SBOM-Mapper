"""HBOM generator (CERT-In Table 11) -> CycloneDX 1.6 device components (recursive)."""
from __future__ import annotations

from .cyclonedx import license_entries, prop, skeleton
from .util import is_set, normalize_license, slug

_PRODUCT_PROPS = ("warranty_amc", "manufacturing_date", "model_number", "serial_number")
_COMPONENT_PROPS = ("model_number", "serial_number", "technical_specification", "technology_node",
                    "compliance", "power_supply", "test_result", "manufacturing_date")


def _text(v) -> str:
    if isinstance(v, list):
        return "; ".join(map(str, v))
    if isinstance(v, dict):
        return "; ".join(f"{k}={x}" for k, x in v.items())
    return str(v)


def _org(entity, unknowns: list, name_key: str, loc_key: str) -> dict | None:
    entity = entity if isinstance(entity, dict) else ({"name": entity} if entity else {})
    if not is_set(entity.get("name")):
        unknowns.append(name_key)
    loc = entity.get("location")
    if not is_set(loc):
        unknowns.append(loc_key)
    if not is_set(entity.get("name")):
        return None
    out: dict = {"name": entity["name"]}
    if is_set(loc):
        if isinstance(loc, dict):
            out["address"] = {k2: loc[k1] for k1, k2 in (("country", "country"), ("region", "region"), ("city", "locality"),
                                                          ("postal_code", "postalCode"), ("street", "streetAddress")) if loc.get(k1)}
        else:
            out["address"] = {"streetAddress": str(loc)}
    if entity.get("contact"):
        out["contact"] = [{"email": entity["contact"]}] if "@" in str(entity["contact"]) else [{"name": str(entity["contact"])}]
    return out


def _component(spec: dict, path: str, is_product: bool) -> dict:
    unknowns: list[str] = []
    name = spec.get("name")
    if not is_set(name):
        unknowns.append("product_name" if is_product else "name")
        name = "unnamed"
    ref = f"hbom/{path}{slug(name)}"
    c: dict = {"type": "device", "bom-ref": ref, "name": name}
    if is_set(spec.get("version")):
        c["version"] = spec["version"]
    elif is_product:
        unknowns.append("product_version")
    details = spec.get("details") or spec.get("description")
    if is_set(details):
        c["description"] = _text(details)
    elif is_product:
        unknowns.append("product_details")
    if is_product:
        man = _org(spec.get("manufacturer"), unknowns, "manufacturer_name", "manufacturer_location")
        if man:
            c["manufacturer"] = man
    sup = _org(spec.get("supplier"), unknowns, "supplier_information", "supplier_location")
    if sup:
        c["supplier"] = sup
    lic = [normalize_license(x) for x in (spec.get("licenses") or ([spec["license"]] if spec.get("license") else []))]
    lic = [x for x in lic if x]
    if lic:
        c["licenses"] = license_entries(lic)
    elif not is_product:
        unknowns.append("license")
    props = []
    for key in (_PRODUCT_PROPS if is_product else _COMPONENT_PROPS):
        if is_set(spec.get(key)):
            props.append(prop(key, _text(spec[key])))
        elif not (is_product is False and key == "manufacturing_date"):
            if key == "technology_node" and spec.get("is_integrated_circuit") is False:
                props.append(prop("not_applicable", "technology_node"))
                continue
            unknowns.append(key)
    children = spec.get("components") or []
    if children:
        c["components"] = [_component(ch, f"{path}{slug(name)}/", False) for ch in children]
    elif not is_product:
        props.append(prop("sub_component", "none"))
    if unknowns:
        props.append(prop("known_unknowns", ",".join(sorted(set(unknowns)))))
    if props:
        c["properties"] = props
    return c


def build_hbom(spec: dict, author: str | None = None) -> dict:
    product = spec.get("product") or spec
    root = _component(product, "", True)
    doc = skeleton("HBOM", authors=[author] if author else None, root=root)
    doc["components"] = root.pop("components", [])
    deps = []

    def walk(parent_ref: str, children: list[dict]):
        deps.append({"ref": parent_ref, "dependsOn": [ch["bom-ref"] for ch in children]})
        for ch in children:
            walk(ch["bom-ref"], ch.get("components") or [])

    walk(root["bom-ref"], doc["components"])
    doc["dependencies"] = deps
    return doc

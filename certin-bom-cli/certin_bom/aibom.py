"""AIBOM generator (CERT-In Table 10) -> CycloneDX 1.6 machine-learning-model with modelCard."""
from __future__ import annotations

from .cyclonedx import license_entries, prop, skeleton
from .ingest import load_bom
from .util import UNKNOWN, build_purl, is_set, normalize_license, slug

# packages that indicate the ML stack when an application SBOM is linked
ML_PACKAGES = {
    "torch", "pytorch", "tensorflow", "tensorflow-cpu", "keras", "jax", "jaxlib", "transformers", "tokenizers",
    "scikit-learn", "sklearn", "xgboost", "lightgbm", "catboost", "onnx", "onnxruntime", "onnxruntime-gpu",
    "safetensors", "accelerate", "peft", "diffusers", "sentence-transformers", "langchain", "llama-index",
    "vllm", "openai", "anthropic", "mlflow", "numpy", "pandas", "scipy", "opencv-python", "spacy", "nltk",
    "huggingface-hub", "datasets", "triton", "bitsandbytes", "deepspeed", "paddlepaddle", "mxnet",
}


def _text(v) -> str:
    if isinstance(v, list):
        return "; ".join(map(str, v))
    if isinstance(v, dict):
        return "; ".join(f"{k}={x}" for k, x in v.items())
    return str(v)


def build_aibom(spec: dict, sbom_path: str | None = None, author: str | None = None) -> dict:
    m = spec.get("model") or spec
    unknowns: list[str] = []

    def val(key, v):
        if not is_set(v):
            unknowns.append(key)
            return None
        return v

    name = val("model_name", m.get("name")) or "unnamed-model"
    ref = f"aibom/model/{slug(name)}"
    model: dict = {"type": "machine-learning-model", "bom-ref": ref, "name": name}
    if val("model_version", m.get("version")):
        model["version"] = m["version"]
    model["purl"] = m.get("purl") or build_purl("generic", name, m.get("version"),
                                                slug(m["developer"]) if isinstance(m.get("developer"), str) else None)
    if m.get("description"):
        model["description"] = m["description"]
    dev = m.get("developer")
    if val("model_developer", dev):
        dev_name = dev.get("name") if isinstance(dev, dict) else dev
        model["supplier"] = {"name": dev_name}
        model["manufacturer"] = {"name": dev_name}
    lic = [normalize_license(x) for x in (m.get("licenses") or []) if normalize_license(x)]
    if val("model_licensing", lic):
        model["licenses"] = license_entries(lic)

    params: dict = {}
    if val("model_type", m.get("type")):
        params["task"] = m["type"]
    alg = m.get("algorithms") or {}
    if val("ml_models_algorithms", alg):
        if isinstance(alg, str):
            alg = {"model_architecture": alg}
        if alg.get("approach"):
            params["approach"] = {"type": alg["approach"]}
        if alg.get("architecture_family"):
            params["architectureFamily"] = alg["architecture_family"]
        if alg.get("model_architecture"):
            params["modelArchitecture"] = alg["model_architecture"]
    if val("input", m.get("inputs")):
        params["inputs"] = [{"format": i} for i in m["inputs"]]
    if val("output", m.get("outputs")):
        params["outputs"] = [{"format": o} for o in m["outputs"]]

    components: list[dict] = []
    datasets = m.get("datasets") or []
    if val("data_sets", datasets):
        params["datasets"] = []
        for i, d in enumerate(datasets):
            d = d if isinstance(d, dict) else {"name": str(d)}
            dref = f"aibom/dataset/{i}-{slug(d.get('name', 'dataset'))}"
            dc: dict = {"type": "data", "bom-ref": dref, "name": d.get("name", f"dataset-{i}")}
            if d.get("version"):
                dc["version"] = d["version"]
            dlic = normalize_license(d.get("license"))
            if dlic:
                dc["licenses"] = license_entries([dlic])
            dc["data"] = [{"type": "dataset", "name": dc["name"],
                           **({"description": d["description"]} if d.get("description") else {}),
                           **({"classification": d["classification"]} if d.get("classification") else {})}]
            dprops = [prop(k, d[k]) for k in ("format", "source", "limitations", "size", "contains_personal_data") if d.get(k)]
            if dprops:
                dc["properties"] = dprops
            components.append(dc)
            params["datasets"].append({"ref": dref})
    card: dict = {"modelParameters": params} if params else {}

    metrics = m.get("performance_metrics") or []
    if val("performance_metrics", metrics):
        card["quantitativeAnalysis"] = {"performanceMetrics": [
            {"type": x.get("type"), "value": str(x.get("value")),
             **({"slice": x["slice"]} if x.get("slice") else {})} for x in metrics]}
    considerations: dict = {}
    if val("intended_usage", m.get("intended_usage")):
        considerations["useCases"] = m["intended_usage"] if isinstance(m["intended_usage"], list) else [m["intended_usage"]]
    if m.get("limitations"):
        considerations["technicalLimitations"] = m["limitations"]
    env = m.get("environmental_impact")
    if val("environmental_impact", env):
        ec: dict = {}
        if isinstance(env, dict) and env.get("energy_kwh") is not None:
            ec["energyConsumptions"] = [{"activity": env.get("activity", "training"), "energyProviders": [],
                                         "activityEnergyCost": {"value": float(env["energy_kwh"]), "unit": "kWh"},
                                         **({"co2CostEquivalent": {"value": float(env["co2e_kg"]) / 1000, "unit": "tCO2eq"}}
                                            if env.get("co2e_kg") is not None else {})}]
        ec["properties"] = [{"name": "cert-in:environmental_impact", "value": _text(env)}]
        considerations["environmentalConsiderations"] = ec
    if considerations:
        card["considerations"] = considerations
    if card:
        model["modelCard"] = card

    props = []
    sources = m.get("data_sources")
    if val("data_source", sources):
        props.append(prop("data_source", _text(sources)))
    if val("hardware", m.get("hardware")):
        props.append(prop("hardware", _text(m["hardware"])))
    if val("security_requirements", m.get("security_requirements")):
        props.append(prop("security_requirements", _text(m["security_requirements"])))
    if val("out_of_scope_usage", m.get("out_of_scope_usage")):
        props.append(prop("out_of_scope_usage", _text(m["out_of_scope_usage"])))

    # Software dependencies: explicit list plus ML packages found in a linked SBOM
    deps_refs: list[str] = []
    for i, s in enumerate(m.get("software_dependencies") or []):
        s = s if isinstance(s, dict) else {"name": str(s)}
        sref = s.get("purl") or f"aibom/sw/{i}-{slug(s.get('name', 'sw'))}"
        comp = {"type": s.get("type", "library"), "bom-ref": sref, "name": s.get("name", f"software-{i}")}
        if s.get("version"):
            comp["version"] = s["version"]
        comp["purl"] = s.get("purl") or build_purl("generic", comp["name"], s.get("version"))
        components.append(comp)
        deps_refs.append(sref)
    if sbom_path:
        linked = load_bom(sbom_path)
        for c in linked.components:
            if c.name.lower() in ML_PACKAGES and c.ref not in deps_refs:
                comp = {"type": "library", "bom-ref": c.ref, "name": c.name}
                if c.version:
                    comp["version"] = c.version
                if c.purl:
                    comp["purl"] = c.purl
                components.append(comp)
                deps_refs.append(c.ref)
        props.append(prop("linked_sbom", str(sbom_path)))
    if not deps_refs:
        unknowns.append("software_dependencies")

    vulns = m.get("vulnerabilities")
    vuln_doc = []
    if isinstance(vulns, list) and vulns:
        vuln_doc = [{"id": v.get("id", "UNKNOWN"), **({"description": v["description"]} if v.get("description") else {}),
                     **({"ratings": [{"severity": v["severity"]}]} if v.get("severity") else {}),
                     "affects": [{"ref": v.get("affects", ref)}]} for v in vulns]
    elif isinstance(vulns, str) and is_set(vulns):
        props.append(prop("vulnerability_scan", vulns))
    else:
        unknowns.append("vulnerabilities")
    if unknowns:
        props.append(prop("known_unknowns", ",".join(unknowns)))
    model["properties"] = props

    doc = skeleton("AIBOM", authors=[author] if author else None, root=model)
    doc["components"] = components
    doc["dependencies"] = [{"ref": ref, "dependsOn": deps_refs + [d["ref"] for d in params.get("datasets", [])]}]
    if vuln_doc:
        doc["vulnerabilities"] = vuln_doc
    return doc

// CERT-In Table 5 conformance check: for every component, is each of the 21 data fields
// present, declared as not available ("NA"), or missing altogether?
//
//   present  - a real value
//   na       - explicitly recorded as not available (NA / Unknown): a declared "known unknown"
//   missing  - absent: nothing tells the reader whether it was checked
//
// conformance  = share of fields that are present or declared (nothing silently missing)
// completeness = share of fields with real values

import { isValidPurl } from "./purl";
import { CRITICALITY_BASIS_PROPERTY, LOOKUP_STATUS_PROPERTY, isDerivedCriticality, parseKnownUnknowns }
  from "../services/certInDocumentService";

const NA_VALUES = new Set(["na", "n/a", "unknown", "noassertion", "not available"]);

export const TABLE5_FIELDS = [
  { key: "name", label: "Component Name" },
  { key: "version", label: "Component Version" },
  { key: "description", label: "Component Description" },
  { key: "supplier", label: "Component Supplier" },
  { key: "license", label: "Component License" },
  { key: "origin", label: "Component Origin" },
  { key: "dependencies", label: "Component Dependencies" },
  { key: "vulnerabilities", label: "Vulnerabilities" },
  { key: "patch", label: "Patch Status" },
  { key: "release", label: "Release Date" },
  { key: "eol", label: "End-of-Life (EOL) Date" },
  { key: "criticality", label: "Criticality" },
  { key: "usage", label: "Usage Restrictions" },
  { key: "hashes", label: "Checksums or Hashes" },
  { key: "comments", label: "Comments or Notes" },
  { key: "author", label: "Author of SBOM Data" },
  { key: "timestamp", label: "Timestamp" },
  { key: "executable", label: "Executable Property" },
  { key: "archive", label: "Archive Property" },
  { key: "structured", label: "Structured Property" },
  { key: "uid", label: "Unique Identifier" },
];

export const getProp = (component, name) => (component?.properties || []).find((p) => p.name === name)?.value;

function classify(value) {
  if (value === undefined || value === null) return "missing";
  if (Array.isArray(value)) return value.length ? "present" : "missing";
  const s = String(value).trim();
  if (!s) return "missing";
  if (NA_VALUES.has(s.toLowerCase())) return "na";
  return "present";
}

export function componentConformance(component, sbom, context = {}) {
  const deps = context.dependencyRefs || new Set((sbom?.dependencies || []).map((d) => d.ref));
  const affected = context.affectedRefs || new Set((sbom?.vulnerabilities || []).flatMap((v) => (v.affects || []).map((a) => a.ref)));
  const ref = component["bom-ref"];
  const patch = getProp(component, "Patch Status");
  const docAuthor = (sbom?.metadata?.authors || []).length || sbom?.metadata?.manufacturer || sbom?.metadata?.manufacture;
  const uid = getProp(component, "Unique Identifier");

  const values = {
    name: component.name,
    version: component.version,
    description: component.description,
    supplier: getProp(component, "Component Supplier") ?? component.supplier?.name,
    license: component.licenses,
    origin: getProp(component, "Component Origin"),
    // the dependency graph lists the component (an empty dependsOn still records "no dependencies");
    // a component absent from the graph has unknown dependencies, which counts as missing
    dependencies: ref && deps.has(ref) ? "yes" : undefined,
    // checked if a vulnerability references it, or a vulnerability lookup produced a patch status
    vulnerabilities: ref && affected.has(ref) ? "yes" : patch === undefined ? undefined : classify(patch) === "present" ? "yes" : "NA",
    patch,
    release: getProp(component, "Release Date"),
    eol: getProp(component, "End-of-Life Date"),
    criticality: getProp(component, "Criticality"),
    usage: getProp(component, "Usage Restrictions"),
    hashes: component.hashes,
    comments: getProp(component, "Comments or Notes"),
    author: getProp(component, "Author of SBOM Data") ?? (docAuthor ? "yes" : undefined),
    timestamp: sbom?.metadata?.timestamp,
    executable: getProp(component, "Executable Property"),
    archive: getProp(component, "Archive Property"),
    structured: getProp(component, "Structured Property"),
    uid: isValidPurl(component.purl) ? component.purl : uid === undefined ? undefined : isValidPurl(uid) ? uid : classify(uid) === "na" ? "NA" : undefined,
  };
  // If the automatic lookup failed, an NA was never actually collected: count it as missing.
  const lookupFailed = String(getProp(component, LOOKUP_STATUS_PROPERTY) || "").startsWith("failed");
  const fields = {};
  for (const f of TABLE5_FIELDS) {
    const status = classify(values[f.key]);
    fields[f.key] = status === "na" && lookupFailed ? "missing" : status;
  }
  return fields;
}

export function sbomConformance(sbom) {
  const components = sbom?.components || [];
  const context = {
    dependencyRefs: new Set((sbom?.dependencies || []).map((d) => d.ref)),
    affectedRefs: new Set((sbom?.vulnerabilities || []).flatMap((v) => (v.affects || []).map((a) => a.ref))),
  };
  const perField = Object.fromEntries(TABLE5_FIELDS.map((f) => [f.key, { ...f, present: 0, na: 0, missing: 0 }]));
  const perComponent = components.map((c) => {
    const fields = componentConformance(c, sbom, context);
    for (const [k, status] of Object.entries(fields)) perField[k][status] += 1;
    return {
      ref: c["bom-ref"],
      name: `${c.name || "unnamed"}${c.version ? "@" + c.version : ""}`,
      lookupStatus: getProp(c, LOOKUP_STATUS_PROPERTY) || null,
      // Criticality derived from vulnerability severity still needs a reviewer (field 12 = importance)
      criticalityNeedsReview: fields.criticality === "present" && isDerivedCriticality(getProp(c, CRITICALITY_BASIS_PROPERTY)),
      reasons: parseKnownUnknowns(c),
      missing: TABLE5_FIELDS.filter((f) => fields[f.key] === "missing").map((f) => f.label),
      na: TABLE5_FIELDS.filter((f) => fields[f.key] === "na").map((f) => f.label),
    };
  });
  const total = components.length * TABLE5_FIELDS.length;
  const present = Object.values(perField).reduce((s, f) => s + f.present, 0);
  const missing = Object.values(perField).reduce((s, f) => s + f.missing, 0);
  const pct = (n) => (total ? Math.round((1000 * n) / total) / 10 : 0);
  return {
    components: components.length,
    fields: Object.values(perField),
    perComponent,
    conformancePct: pct(total - missing),
    completenessPct: pct(present),
    verdict: !components.length ? "No components" : missing === 0 ? "Conformant" : "Not conformant",
    criticalityToReview: perComponent.filter((c) => c.criticalityNeedsReview).length,
  };
}

// Components that no vulnerability source could check (no ecosystem purl, lookup failed, ...):
// "0 vulnerabilities" for these means "unknown", not "clean".
export function uncheckedComponents(sbom) {
  const affected = new Set((sbom?.vulnerabilities || []).flatMap((v) => (v.affects || []).map((a) => a.ref)));
  return (sbom?.components || [])
    .filter((c) => !affected.has(c["bom-ref"]))
    .map((c) => {
      const lookup = String(getProp(c, LOOKUP_STATUS_PROPERTY) || "");
      const reasons = parseKnownUnknowns(c);
      const patch = getProp(c, "Patch Status");
      if (lookup.startsWith("failed")) return { c, reason: `lookup ${lookup}` };
      if (patch === undefined || patch === "NA") return { c, reason: reasons["Patch Status"] || "not checked against a vulnerability database" };
      return null;
    })
    .filter(Boolean)
    .map(({ c, reason }) => ({ ref: c["bom-ref"], name: `${c.name || "unnamed"}${c.version ? "@" + c.version : ""}`, reason }));
}

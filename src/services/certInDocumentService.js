// Document-level CERT-In requirements (Technical Guidelines v2.0, 09.07.2025):
//   - Table 5 field 16 "Author of SBOM Data" and field 17 "Timestamp"
//   - Table 5 "Practices and Processes" declaration
//   - 5.3.2 public / private SBOM
//   - Section 6 VEX statuses and CSAF advisory

export const GUIDELINE = "CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM, Version 2.0 (09.07.2025)";
export const AUTHOR_PROPERTY = "Author of SBOM Data";

export const PRACTICES = [
  { key: "frequency", label: "Frequency", hint: "e.g. regenerated on every release and every CI build" },
  { key: "depth", label: "Depth", hint: "e.g. all direct and transitive dependencies, including OS packages" },
  { key: "known-unknowns", label: "Known Unknowns", hint: "e.g. fields that cannot be determined are recorded as NA" },
  { key: "distribution-and-delivery", label: "Distribution and Delivery", hint: "e.g. public SBOM on the portal; private SBOM + VEX on request" },
  { key: "access-control", label: "Access Control", hint: "e.g. private SBOM restricted to customers under NDA" },
  { key: "accommodation-of-mistakes", label: "Accommodation of Mistakes", hint: "e.g. corrections issued as a new SBOM version" },
];

// The four statuses of section 6(a), mapped to CycloneDX analysis.state and CSAF product_status
export const VEX_STATUSES = [
  { key: "under_investigation", label: "Under Investigation", cdx: "in_triage", csaf: "under_investigation" },
  { key: "not_affected", label: "Not affected", cdx: "not_affected", csaf: "known_not_affected" },
  { key: "affected", label: "Affected", cdx: "exploitable", csaf: "known_affected" },
  { key: "fixed", label: "Fixed", cdx: "resolved", csaf: "fixed" },
];
export const VEX_JUSTIFICATIONS = [
  { cdx: "code_not_present", label: "Vulnerable code not present", csaf: "vulnerable_code_not_present" },
  { cdx: "code_not_reachable", label: "Vulnerable code not reachable", csaf: "vulnerable_code_not_in_execute_path" },
  { cdx: "requires_configuration", label: "Requires a configuration that is not used", csaf: "vulnerable_code_cannot_be_controlled_by_adversary" },
  { cdx: "requires_dependency", label: "Requires a dependency that is not present", csaf: "component_not_present" },
  { cdx: "requires_environment", label: "Requires an environment that is not used", csaf: "vulnerable_code_cannot_be_controlled_by_adversary" },
  { cdx: "protected_by_compiler", label: "Protected by compiler", csaf: "inline_mitigations_already_exist" },
  { cdx: "protected_at_runtime", label: "Protected at runtime", csaf: "inline_mitigations_already_exist" },
  { cdx: "protected_at_perimeter", label: "Protected at perimeter", csaf: "inline_mitigations_already_exist" },
  { cdx: "protected_by_mitigating_control", label: "Protected by mitigating control", csaf: "inline_mitigations_already_exist" },
];
// Information that reveals vulnerability status; removed from the public SBOM (5.3.2)
export const PRIVATE_PROPERTIES = ["Patch Status", "Comments or Notes"];

const clone = (x) => JSON.parse(JSON.stringify(x));
const nowIso = () => new Date().toISOString().replace(/\.\d{3}Z$/, "Z");

export function statusOf(vuln) {
  const state = vuln?.analysis?.state;
  if (state === "not_affected" || state === "false_positive") return VEX_STATUSES[1];
  if (state === "exploitable") return VEX_STATUSES[2];
  if (state === "resolved" || state === "resolved_with_pedigree") return VEX_STATUSES[3];
  return VEX_STATUSES[0];
}

// ------------------------------------------------------------------ Author of SBOM Data (field 16)
export function sbomAuthor(sbom) {
  const meta = sbom?.metadata || {};
  const names = [
    ...(meta.authors || []).map((a) => a?.name),
    meta.manufacturer?.name, // CycloneDX 1.6
    meta.manufacture?.name, // CycloneDX 1.4/1.5
    meta.supplier?.name,
  ].filter(Boolean);
  if (names.length) return Array.from(new Set(names)).join(", ");
  return "";
}

export function sbomTools(sbom) {
  const tools = sbom?.metadata?.tools;
  const list = Array.isArray(tools) ? tools : [...(tools?.components || []), ...(tools?.services || [])];
  return list.map((t) => [t.vendor || t.group, t.name, t.version].filter(Boolean).join(" ")).filter(Boolean);
}

const setProp = (props, name, value) => {
  const out = (props || []).filter((p) => p.name !== name);
  out.push({ name, value: String(value) });
  return out;
};
const getProp = (props, name) => (props || []).find((p) => p.name === name)?.value;
const isEmpty = (v) => v === undefined || v === null || v === "" || v === "NA";

// Native CycloneDX fields (description, licenses, hashes) filled from registries where missing,
// plus the per-component Author of SBOM Data.
export function applyComponentFields(component, fields, author) {
  const c = { ...component };
  if (fields?.description && !c.description) c.description = fields.description;
  if (fields?.licenses?.length && !(Array.isArray(c.licenses) && c.licenses.length)) c.licenses = fields.licenses;
  if (fields?.hashes?.length && !(Array.isArray(c.hashes) && c.hashes.length)) {
    c.hashes = fields.hashes;
    if (fields.hashSource) c.properties = setProp(c.properties, "cert-in:hash_source", fields.hashSource);
  }
  if (author && isEmpty(getProp(c.properties, AUTHOR_PROPERTY))) c.properties = setProp(c.properties, AUTHOR_PROPERTY, author);
  return c;
}

// ------------------------------------------------------------------ export (fields 16-17, practices, 5.3.2)
export function prepareForExport(sbom, { author, practices = {}, distribution = "private", now = nowIso() } = {}) {
  const out = clone(sbom);
  out.metadata = out.metadata || {};
  const original = out.metadata.timestamp;
  // Timestamp = when this SBOM data was assembled (this export); keep the generator's time too
  out.metadata.timestamp = now;
  let mprops = out.metadata.properties || [];
  if (original && original !== now) mprops = setProp(mprops, "cert-in:source_timestamp", original);
  if (author) {
    const authors = out.metadata.authors || [];
    if (!authors.some((a) => a?.name === author)) out.metadata.authors = [{ name: author }, ...authors];
  }
  mprops = setProp(mprops, "cert-in:guideline", GUIDELINE);
  mprops = setProp(mprops, "cert-in:distribution", distribution);
  for (const p of PRACTICES) {
    const value = String(practices[p.key] || "").trim();
    mprops = value ? setProp(mprops, `cert-in:practice:${p.key}`, value) : mprops.filter((x) => x.name !== `cert-in:practice:${p.key}`);
  }
  out.metadata.properties = mprops;
  const effectiveAuthor = author || sbomAuthor(out);
  out.components = (out.components || []).map((c) =>
    effectiveAuthor && isEmpty(getProp(c.properties, AUTHOR_PROPERTY))
      ? { ...c, properties: setProp(c.properties, AUTHOR_PROPERTY, effectiveAuthor) } : c);
  if (distribution === "public") return toPublic(out);
  return out;
}

// 5.3.2: the public SBOM carries no vulnerability information
export function toPublic(sbom) {
  const out = clone(sbom);
  delete out.vulnerabilities;
  delete out.signature;
  const strip = (c) => {
    const props = (c.properties || []).filter((p) => !PRIVATE_PROPERTIES.includes(p.name));
    const next = { ...c, properties: props };
    if (Array.isArray(c.components)) next.components = c.components.map(strip);
    return next;
  };
  out.components = (out.components || []).map(strip);
  out.metadata = out.metadata || {};
  out.metadata.properties = setProp(out.metadata.properties, "cert-in:distribution", "public");
  return out;
}

// ------------------------------------------------------------------ VEX (section 6)
export function setVulnerabilityAnalysis(vulnerabilities, index, { status, justification, detail, response }) {
  return vulnerabilities.map((v, i) => {
    if (i !== index) return v;
    const spec = VEX_STATUSES.find((s) => s.key === status) || VEX_STATUSES[0];
    const analysis = { state: spec.cdx };
    if (spec.key === "not_affected" && justification) analysis.justification = justification;
    if (response?.length) analysis.response = response;
    if (detail) analysis.detail = detail;
    analysis.lastUpdated = nowIso();
    return { ...v, analysis };
  });
}

function withDefaultState(v) {
  return v.analysis?.state ? v : { ...v, analysis: { ...(v.analysis || {}), state: "in_triage" } };
}

// Standalone CycloneDX VEX referencing the SBOM through BOM-Link (urn:cdx:serial/version#bom-ref)
export function cyclonedxVex(sbom, { author, now = nowIso() } = {}) {
  const serial = sbom?.serialNumber || "urn:uuid:unknown";
  const link = `${serial.replace(/^urn:uuid:/, "urn:cdx:")}/${sbom?.version || 1}#`;
  return {
    bomFormat: "CycloneDX",
    specVersion: sbom?.specVersion || "1.5",
    serialNumber: `urn:uuid:${uuid()}`,
    version: 1,
    metadata: {
      timestamp: now,
      ...(author ? { authors: [{ name: author }] } : {}),
      properties: [{ name: "cert-in:guideline", value: GUIDELINE }, { name: "cert-in:describes_sbom", value: serial }],
    },
    vulnerabilities: (sbom?.vulnerabilities || []).map((raw) => {
      const v = withDefaultState(raw);
      const keep = ["bom-ref", "id", "source", "references", "ratings", "cwes", "description", "recommendation", "advisories",
        "published", "analysis"];
      const out = Object.fromEntries(keep.filter((k) => v[k] !== undefined).map((k) => [k, v[k]]));
      out.affects = (v.affects || []).map((a) => ({ ref: link + a.ref }));
      out.properties = [{ name: "cert-in:vex_status", value: statusOf(v).label }];
      return out;
    }),
  };
}

// CSAF 2.0 document, csaf_vex profile
export function csafVex(sbom, { publisher = "Unknown publisher", namespace = "https://example.invalid", now = nowIso() } = {}) {
  const comps = new Map();
  const root = sbom?.metadata?.component;
  if (root?.["bom-ref"]) comps.set(root["bom-ref"], root);
  for (const c of sbom?.components || []) if (c["bom-ref"]) comps.set(c["bom-ref"], c);
  const productIds = new Map();
  const branches = [];
  for (const [ref, c] of comps) {
    const pid = `CSAFPID-${String(productIds.size + 1).padStart(4, "0")}`;
    productIds.set(ref, pid);
    branches.push({
      category: "product_version", name: c.version || "unspecified",
      product: { name: `${c.name || ref} ${c.version || ""}`.trim(), product_id: pid,
        ...(c.purl ? { product_identification_helper: { purl: c.purl } } : {}) },
    });
  }
  const productName = root?.name || "product";
  const vulnerabilities = [];
  for (const raw of sbom?.vulnerabilities || []) {
    const v = withDefaultState(raw);
    const pids = (v.affects || []).map((a) => productIds.get(a.ref)).filter(Boolean);
    if (!pids.length) continue;
    const status = statusOf(v);
    const entry = { product_status: { [status.csaf]: pids } };
    const cve = String(v.id).startsWith("CVE-") ? v.id : (v.references || []).map((r) => r.id).find((id) => String(id).startsWith("CVE-"));
    if (cve) entry.cve = cve;
    entry.ids = [{ system_name: v.source?.name || (String(v.id).startsWith("CVE-") ? "CVE" : "unspecified"), text: String(v.id) }];
    entry.notes = [{ category: "description", title: "Vulnerability description", text: v.description || String(v.id) }];
    if (v.cwes?.length) entry.cwe = { id: `CWE-${v.cwes[0]}`, name: `CWE-${v.cwes[0]}` };
    if (status.key === "not_affected") {
      const flag = VEX_JUSTIFICATIONS.find((j) => j.cdx === v.analysis.justification)?.csaf;
      if (flag) entry.flags = [{ label: flag, product_ids: pids }];
      entry.threats = [{ category: "impact", details: v.analysis.detail || "Not affected per vendor analysis", product_ids: pids }];
    } else if (status.key === "affected") {
      entry.remediations = [{ category: v.recommendation ? "vendor_fix" : "none_available",
        details: v.recommendation || v.analysis.detail || "Remediation under development", product_ids: pids }];
    }
    const r = (v.ratings || [])[0];
    if (r?.vector && String(r.vector).startsWith("CVSS:3") && typeof r.score === "number") {
      entry.scores = [{ products: pids, cvss_v3: { version: String(r.vector).split("/")[0].split(":")[1], vectorString: r.vector,
        baseScore: r.score, baseSeverity: String(r.severity || "none").toUpperCase() } }];
    }
    vulnerabilities.push(entry);
  }
  return {
    document: {
      category: "csaf_vex", csaf_version: "2.0", lang: "en", title: `VEX for ${productName}`,
      publisher: { category: "vendor", name: publisher, namespace },
      notes: [{ category: "summary", title: "Scope", text: `Exploitability status of vulnerabilities in SBOM ${sbom?.serialNumber || ""}`.trim() }],
      tracking: {
        id: `VEX-${String(productName).replace(/[^A-Za-z0-9.-]+/g, "-")}-${now.slice(0, 10)}`, status: "interim", version: "1",
        initial_release_date: now, current_release_date: now,
        revision_history: [{ date: now, number: "1", summary: "Initial VEX" }],
        generator: { engine: { name: "CERT-In SBOM Mapper" } },
      },
    },
    product_tree: { branches: [{ category: "vendor", name: publisher,
      branches: [{ category: "product_name", name: productName, branches }] }] },
    vulnerabilities,
  };
}

function uuid() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (ch) => {
    const r = (Math.random() * 16) | 0;
    return (ch === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });
}

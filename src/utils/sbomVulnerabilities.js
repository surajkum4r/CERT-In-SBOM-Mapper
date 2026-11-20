// Builds the CycloneDX vulnerabilities[] array (CERT-In Table 5, field 8) from the
// per-component OSV findings, merged with whatever the uploaded SBOM already contained.

import { bestFix } from "./version";

// CycloneDX needs a bom-ref on every component that a vulnerability "affects".
export function ensureBomRefs(components) {
  const used = new Set(components.map((c) => c["bom-ref"]).filter(Boolean));
  return components.map((c) => {
    if (c["bom-ref"]) return c;
    const base = c.purl || `${c.name || "component"}@${c.version || ""}`;
    let ref = base;
    for (let n = 2; used.has(ref); n++) ref = `${base}#${n}`;
    used.add(ref);
    return { ...c, "bom-ref": ref };
  });
}

function isoDate(value) {
  if (!value) return null;
  const v = String(value).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return `${v}T00:00:00Z`;
  return /T/.test(v) && !/(Z|[+-]\d{2}:?\d{2})$/.test(v) ? `${v}Z` : v;
}

const sourceName = (id) => (id.startsWith("CVE-") ? "NVD" : id.startsWith("GHSA-") ? "GitHub" : "OSV");

export function toCycloneDx(rec, component) {
  const ref = component["bom-ref"];
  const entry = {
    "bom-ref": `osv-${rec.id}`,
    id: rec.id,
    source: { name: sourceName(rec.id), url: rec.id.startsWith("CVE-")
      ? `https://nvd.nist.gov/vuln/detail/${rec.id}` : `https://osv.dev/vulnerability/${rec.id}` },
  };
  if (rec.aliases?.length) entry.references = rec.aliases.map((a) => ({ id: a, source: { name: sourceName(a) } }));
  const rating = {};
  if (typeof rec.score === "number") rating.score = rec.score;
  if (rec.severity) rating.severity = rec.severity;
  if (rec.method) rating.method = rec.method;
  if (rec.vector) rating.vector = rec.vector;
  if (Object.keys(rating).length) entry.ratings = [rating];
  if (rec.cwes?.length) entry.cwes = rec.cwes;
  if (rec.description) entry.description = rec.description;
  if (rec.published) entry.published = isoDate(rec.published);
  if (rec.references?.length) entry.advisories = rec.references.map((url) => ({ url }));
  const fix = bestFix(component.version, rec.fixed || []);
  if (fix) entry.recommendation = `${component.name} ${component.version || ""}`.trim() + `: upgrade to ${fix}`;
  entry.affects = [{ ref }];
  const props = [];
  if (rec.priority) props.push({ name: "cert-in:priority", value: rec.priority });
  if (rec.kev) {
    props.push({ name: "cert-in:kev_date_added", value: String(rec.kev.dateAdded) });
    if (rec.kev.ransomware) props.push({ name: "cert-in:kev_ransomware", value: String(rec.kev.ransomware) });
  }
  if (typeof rec.epss === "number") props.push({ name: "cert-in:epss", value: rec.epss.toFixed(5) });
  if (props.length) entry.properties = props;
  return entry;
}

// existing: the SBOM's original vulnerabilities[]; results[i]._vulnerabilities belong to components[i]
export function mergeVulnerabilities(existing, components, results) {
  const out = (existing || []).map((v) => ({ ...v, affects: [...(v.affects || [])] }));
  const index = new Map();
  const register = (v) => {
    for (const ident of [v.id, ...(v.references || []).map((r) => r.id)]) if (ident) index.set(ident, v);
  };
  out.forEach(register);
  components.forEach((component, i) => {
    const ref = component["bom-ref"];
    for (const rec of results[i]?._vulnerabilities || []) {
      const match = [rec.id, ...(rec.aliases || [])].map((id) => index.get(id)).find(Boolean);
      if (match) {
        if (!match.affects.some((a) => a.ref === ref)) match.affects.push({ ref });
        continue;
      }
      const entry = toCycloneDx(rec, component);
      out.push(entry);
      register(entry);
    }
  });
  return out;
}

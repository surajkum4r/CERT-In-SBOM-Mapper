// Licence analysis for "Usage Restrictions" and "Component Origin" (CERT-In Table 5, fields 6 and 13).

const COPYLEFT_STRONG = ["AGPL", "SSPL", "OSL", "EUPL"];
const COPYLEFT = ["GPL", "CC-BY-SA"];
const COPYLEFT_WEAK = ["LGPL", "MPL", "EPL", "CDDL", "CPL", "MS-RL"];
const RESTRICTED_USE = ["CC-BY-NC", "BUSL", "ELASTIC", "COMMONS-CLAUSE", "LLAMA"];
const PERMISSIVE = ["MIT", "APACHE", "BSD", "ISC", "ZLIB", "UNLICENSE", "0BSD", "PSF", "PYTHON", "BSL-1.0",
  "CC0", "WTFPL", "X11", "POSTGRESQL", "UPL", "NCSA", "OPENSSL", "BLUEOAK", "ARTISTIC"];
const PROPRIETARY = ["PROPRIETARY", "COMMERCIAL", "EULA", "ALL RIGHTS RESERVED"];

const norm = (license) => String(license || "").toUpperCase().replace(/LICENSE/g, "").trim();
const hasAny = (text, list) => list.some((k) => text.includes(k));

export function licenseText(license) {
  if (!license) return null;
  if (Array.isArray(license)) return license.map(licenseText).filter(Boolean).join(" AND ") || null;
  if (typeof license === "object") {
    return license.expression || license.license?.id || license.license?.name || license.id || license.name || license.type || null;
  }
  return String(license);
}

// Licences declared in a CycloneDX component ("licenses": [{license: {id}}, {expression}])
export function componentLicense(component) {
  const entries = Array.isArray(component?.licenses) ? component.licenses : [];
  return entries.map(licenseText).filter(Boolean).join(" AND ") || null;
}

export function usageRestrictions(license) {
  const text = norm(licenseText(license));
  if (!text || text === "NOASSERTION" || text === "UNKNOWN") return "NA";
  const notes = [];
  // check weak/strong families before plain "GPL" (LGPL and AGPL contain "GPL")
  if (hasAny(text, RESTRICTED_USE)) notes.push("Restricted use (non-commercial / source-available terms)");
  if (hasAny(text, COPYLEFT_STRONG)) notes.push("Strong copyleft - network use may trigger source disclosure");
  else if (hasAny(text, COPYLEFT_WEAK)) notes.push("Weak copyleft - modifications to this component must be shared");
  else if (/(^|[^LA])GPL/.test(text) || hasAny(text, COPYLEFT)) notes.push("Copyleft - derivative works must be released under the same licence");
  if (hasAny(text, PROPRIETARY)) notes.push("Proprietary licence - check contract/EULA terms");
  if (!notes.length && hasAny(text, PERMISSIVE)) notes.push("Permissive licence - attribution required");
  if (!notes.length) notes.push("Unrecognised licence - manual legal review required");
  return `${notes.join("; ")}; export control not assessed`;
}

export function isOpenSourceLicense(license) {
  const text = norm(licenseText(license));
  if (!text || hasAny(text, PROPRIETARY) || hasAny(text, RESTRICTED_USE)) return false;
  return hasAny(text, PERMISSIVE) || hasAny(text, COPYLEFT_STRONG) || hasAny(text, COPYLEFT_WEAK)
    || /GPL/.test(text) || hasAny(text, COPYLEFT);
}

export function isProprietaryLicense(license) {
  return hasAny(norm(licenseText(license)), PROPRIETARY);
}

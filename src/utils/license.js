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

// Common SPDX licence identifiers (https://spdx.org/licenses/). The CycloneDX schema only accepts
// listed SPDX ids in license.id; anything else must go in license.name.
const SPDX_IDS = ["0BSD", "AFL-3.0", "AGPL-1.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "Apache-1.1", "Apache-2.0",
  "APSL-2.0", "Artistic-2.0", "BlueOak-1.0.0", "BSD-1-Clause", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear",
  "BSD-4-Clause", "BSL-1.0", "BUSL-1.1", "CC-BY-3.0", "CC-BY-4.0", "CC-BY-SA-4.0", "CC-BY-NC-4.0", "CC0-1.0",
  "CDDL-1.0", "CDDL-1.1", "CPL-1.0", "ECL-2.0", "EPL-1.0", "EPL-2.0", "EUPL-1.1", "EUPL-1.2", "GPL-2.0-only",
  "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "HPND", "ISC", "LGPL-2.0-only", "LGPL-2.1-only",
  "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", "MIT", "MIT-0", "MPL-1.1", "MPL-2.0", "MS-PL", "MS-RL",
  "NCSA", "ODbL-1.0", "OFL-1.1", "OpenSSL", "OSL-3.0", "PostgreSQL", "PSF-2.0", "Python-2.0", "Ruby", "SSPL-1.0",
  "Unicode-DFS-2016", "Unicode-3.0", "Unlicense", "UPL-1.0", "Vim", "W3C", "WTFPL", "X11", "Zlib", "ZPL-2.1"];
const SPDX_LOWER = new Map(SPDX_IDS.map((id) => [id.toLowerCase(), id]));
const ALIASES = {
  "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0", "apache 2": "Apache-2.0", "apache license 2.0": "Apache-2.0",
  "apache license, version 2.0": "Apache-2.0", "apache software license": "Apache-2.0", "mit license": "MIT",
  "the mit license": "MIT", "bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause", "new bsd license": "BSD-3-Clause",
  "bsd-3": "BSD-3-Clause", "simplified bsd": "BSD-2-Clause", "isc license": "ISC", "gplv2": "GPL-2.0-only",
  "gpl-2.0": "GPL-2.0-only", "gplv3": "GPL-3.0-only", "gpl-3.0": "GPL-3.0-only", "lgpl-2.1": "LGPL-2.1-only",
  "lgpl-3.0": "LGPL-3.0-only", "agpl-3.0": "AGPL-3.0-only", "mpl 2.0": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0",
  "psf": "PSF-2.0", "python software foundation license": "PSF-2.0", "zlib license": "Zlib",
};

export function toSpdxId(text) {
  if (!text) return null;
  const t = String(text).trim();
  return SPDX_LOWER.get(t.toLowerCase()) || ALIASES[t.toLowerCase()] || null;
}

// CycloneDX "licenses" array for a licence string from a registry.
export function toCycloneDxLicenses(text) {
  if (!text) return null;
  const t = String(text).trim();
  if (!t || /^(noassertion|none|unknown|see license|other)$/i.test(t)) return null;
  if (/\s(AND|OR|WITH)\s/.test(t)) {
    const parts = t.replace(/[()]/g, " ").split(/\s+(?:AND|OR|WITH)\s+/).map((p) => p.trim()).filter(Boolean);
    if (parts.every((p) => toSpdxId(p) === p || p.startsWith("LicenseRef-"))) return [{ expression: t }];
    return [{ license: { name: t } }];
  }
  const id = toSpdxId(t);
  return id ? [{ license: { id } }] : [{ license: { name: t.slice(0, 200) } }];
}

// Package URL (purl) helpers - https://github.com/package-url/purl-spec
//
// CERT-In Guidelines v2.0 (Table 5, field 21) describe the Unique Identifier as
// "pkg:supplier/OrganizationName/ComponentName@Version?qualifiers&subpath".
// That is the purl *shape* (type/namespace/name@version); the identifier itself must
// remain a valid purl so scanners (Dependency-Track, Grype, OSV) can match it.

const PURL_RE = /^pkg:([A-Za-z][A-Za-z0-9.+-]*)\/([^?#]+?)(?:\?([^#]*))?(?:#(.*))?$/;

export function parsePurl(purl) {
  if (!purl || typeof purl !== "string") return null;
  const m = purl.trim().match(PURL_RE);
  if (!m) return null;
  let rest = m[2];
  let version = null;
  // The version follows the last "@". A leading "@" (unencoded npm scope, e.g. "@angular/core")
  // is not a version separator, so only "@" at position > 0 counts.
  const at = rest.lastIndexOf("@");
  if (at > 0) {
    version = safeDecode(rest.slice(at + 1));
    rest = rest.slice(0, at);
  }
  const parts = rest.split("/").filter(Boolean).map(safeDecode);
  if (parts.length === 0) return null;
  const qualifiers = {};
  if (m[3]) {
    for (const pair of m[3].split("&")) {
      const [k, v = ""] = pair.split("=");
      if (k) qualifiers[k.toLowerCase()] = safeDecode(v);
    }
  }
  return {
    type: m[1].toLowerCase(),
    namespace: parts.length > 1 ? parts.slice(0, -1).join("/") : null,
    name: parts[parts.length - 1],
    version,
    qualifiers,
    subpath: m[4] || null,
  };
}

export function isValidPurl(purl) {
  return parsePurl(purl) !== null;
}

export function buildPurl(type, name, version, namespace) {
  const enc = (s) => encodeURIComponent(s);
  const segs = namespace ? String(namespace).split("/").map((s) => (s.startsWith("@") ? "%40" + enc(s.slice(1)) : enc(s))) : [];
  segs.push(enc(name));
  return `pkg:${String(type).toLowerCase()}/${segs.join("/")}${version ? "@" + enc(version) : ""}`;
}

export function slug(text) {
  return String(text || "").replace(/[^A-Za-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "") || "unnamed";
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

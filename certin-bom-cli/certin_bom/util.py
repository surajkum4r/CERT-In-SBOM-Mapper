from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote

UNKNOWN = "unknown"  # value for an explicitly declared "known unknown"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def iso_datetime(value: str) -> str:
    """Make a timestamp RFC 3339 compliant (NVD omits the timezone; some feeds give a bare date)."""
    v = value.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        return v + "T00:00:00Z"
    if "T" in v and not re.search(r"(Z|[+-]\d{2}:?\d{2})$", v):
        return v + "Z"
    return v


def new_serial() -> str:
    return f"urn:uuid:{uuid.uuid4()}"


def read_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, data: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9.\-]+", "-", text).strip("-") or "unnamed"


def is_set(value) -> bool:
    """True when a field carries a real value (not missing, not a declared unknown)."""
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip() != "" and value.strip().lower() not in (UNKNOWN, "noassertion")
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) > 0
    return True


# ---------------------------------------------------------------- purl
_PURL_RE = re.compile(r"^pkg:(?P<type>[A-Za-z][A-Za-z0-9.+\-]*)/(?P<rest>[^?#]+?)(?:\?(?P<q>[^#]*))?(?:#(?P<sub>.*))?$")


def parse_purl(purl: str | None) -> dict | None:
    if not purl:
        return None
    m = _PURL_RE.match(purl.strip())
    if not m:
        return None
    rest = m.group("rest")
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version)
    parts = [unquote(p) for p in rest.split("/") if p]
    if not parts:
        return None
    return {
        "type": m.group("type").lower(),
        "namespace": "/".join(parts[:-1]) or None,
        "name": parts[-1],
        "version": version,
        "qualifiers": m.group("q"),
        "subpath": m.group("sub"),
    }


def build_purl(ptype: str, name: str, version: str | None = None, namespace: str | None = None) -> str:
    segs = [quote(s, safe="") for s in (namespace.split("/") if namespace else [])]
    segs.append(quote(name, safe=""))
    out = f"pkg:{ptype.lower()}/" + "/".join(segs)
    if version:
        out += "@" + quote(version, safe="")
    return out


# ---------------------------------------------------------------- versions
def _vkey(v: str):
    v = v.strip().lstrip("vV")
    main, _, pre = v.partition("-")
    nums = []
    for part in re.split(r"[.+_]", main):
        m = re.match(r"(\d+)(.*)", part)
        if m:
            nums.append((int(m.group(1)), m.group(2)))
        else:
            nums.append((-1, part))
    # a pre-release sorts before the release
    return nums, (0 if pre else 1, pre)


def version_lt(a: str, b: str) -> bool:
    try:
        ka, kb = _vkey(a), _vkey(b)
        la, lb = ka[0], kb[0]
        n = max(len(la), len(lb))
        la = la + [(0, "")] * (n - len(la))
        lb = lb + [(0, "")] * (n - len(lb))
        return (la, ka[1]) < (lb, kb[1])
    except Exception:  # noqa: BLE001 - unparseable versions are never "less than"
        return False


def sort_versions(versions) -> list[str]:
    from functools import cmp_to_key
    return sorted(set(versions), key=cmp_to_key(lambda a, b: -1 if version_lt(a, b) else (1 if version_lt(b, a) else 0)))


def best_fix(current: str | None, fixed: list[str]) -> str:
    """Highest fix on the same release line (major.minor, then major); else the lowest newer release.

    Advisories list fix versions for every maintained branch, so the global maximum
    would wrongly suggest a major upgrade (e.g. Django 4.2.7 -> 6.x).
    """
    fixed = sort_versions(f for f in fixed if not current or version_lt(current, f)) or sort_versions(fixed)
    if not fixed:
        return ""
    if not current:
        return fixed[-1]
    parts = current.lstrip("vV").split(".")
    for depth in (2, 1):
        prefix = ".".join(parts[:depth]) + "."
        same_line = [f for f in fixed if f.lstrip("vV").startswith(prefix)]
        if same_line:
            return same_line[-1]
    return fixed[0]


# ---------------------------------------------------------------- hashes
_HASH_ALIASES = {
    "MD5": "MD5", "SHA1": "SHA-1", "SHA-1": "SHA-1", "SHA224": "SHA-224",
    "SHA256": "SHA-256", "SHA-256": "SHA-256", "SHA384": "SHA-384", "SHA-384": "SHA-384",
    "SHA512": "SHA-512", "SHA-512": "SHA-512", "SHA3-256": "SHA3-256", "SHA3_256": "SHA3-256",
    "SHA3-384": "SHA3-384", "SHA3-512": "SHA3-512", "BLAKE2B-256": "BLAKE2b-256",
    "BLAKE2B-512": "BLAKE2b-512", "BLAKE3": "BLAKE3",
}
WEAK_HASHES = {"MD5", "SHA-1"}


def norm_hash_alg(alg: str) -> str:
    return _HASH_ALIASES.get(alg.upper().replace(" ", ""), alg.upper())


# ---------------------------------------------------------------- licences
# Common SPDX identifiers (subset of https://spdx.org/licenses/). Unrecognised
# licences become LicenseRef-<slug> as CERT-In section 3.x(c)/(d) recommends.
SPDX_IDS = {
    "0BSD", "AFL-3.0", "AGPL-1.0", "AGPL-3.0-only", "AGPL-3.0-or-later", "Apache-1.1", "Apache-2.0",
    "APSL-2.0", "Artistic-2.0", "BlueOak-1.0.0", "BSD-1-Clause", "BSD-2-Clause", "BSD-3-Clause",
    "BSD-3-Clause-Clear", "BSD-4-Clause", "BSL-1.0", "BUSL-1.1", "CC-BY-3.0", "CC-BY-4.0",
    "CC-BY-SA-4.0", "CC-BY-NC-4.0", "CC0-1.0", "CDDL-1.0", "CDDL-1.1", "CPL-1.0", "ECL-2.0",
    "EPL-1.0", "EPL-2.0", "EUPL-1.1", "EUPL-1.2", "GPL-1.0-only", "GPL-2.0-only", "GPL-2.0-or-later",
    "GPL-3.0-only", "GPL-3.0-or-later", "HPND", "ISC", "LGPL-2.0-only", "LGPL-2.1-only",
    "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", "MIT", "MIT-0", "MPL-1.1", "MPL-2.0",
    "MS-PL", "MS-RL", "NCSA", "ODbL-1.0", "OFL-1.1", "OpenSSL", "OSL-3.0", "PostgreSQL", "PSF-2.0",
    "Python-2.0", "Ruby", "SSPL-1.0", "Unicode-DFS-2016", "Unicode-3.0", "Unlicense", "UPL-1.0",
    "Vim", "W3C", "WTFPL", "X11", "Zlib", "ZPL-2.1", "LLVM-exception", "Classpath-exception-2.0",
    "OpenRAIL", "OpenRAIL-M", "CreativeML-OpenRAIL-M", "Llama-3.1", "NOASSERTION",
}
_SPDX_LOWER = {i.lower(): i for i in SPDX_IDS}
_LICENSE_ALIASES = {
    "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0", "apache2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0", "the apache software license, version 2.0": "Apache-2.0",
    "mit license": "MIT", "the mit license": "MIT", "expat": "MIT",
    "bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause", "new bsd license": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause", "3-clause bsd": "BSD-3-Clause", "simplified bsd": "BSD-2-Clause",
    "bsd-2": "BSD-2-Clause", "isc license": "ISC",
    "gpl": "GPL-2.0-or-later", "gplv2": "GPL-2.0-only", "gpl-2.0": "GPL-2.0-only", "gpl v2": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only", "gpl-3.0": "GPL-3.0-only", "gpl v3": "GPL-3.0-only",
    "lgpl": "LGPL-2.1-or-later", "lgplv2.1": "LGPL-2.1-only", "lgpl-2.1": "LGPL-2.1-only",
    "lgplv3": "LGPL-3.0-only", "lgpl-3.0": "LGPL-3.0-only", "agplv3": "AGPL-3.0-only", "agpl-3.0": "AGPL-3.0-only",
    "mpl 2.0": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0", "mpl-2": "MPL-2.0",
    "epl 2.0": "EPL-2.0", "eclipse public license 2.0": "EPL-2.0", "psf": "PSF-2.0",
    "python software foundation license": "PSF-2.0", "zlib license": "Zlib", "unlicense": "Unlicense",
    "public domain": "LicenseRef-public-domain", "cc0": "CC0-1.0", "postgresql license": "PostgreSQL",
}
COPYLEFT_PREFIXES = ("GPL-", "AGPL-", "LGPL-", "MPL-", "EPL-", "EUPL-", "CDDL-", "OSL-", "SSPL-", "CC-BY-SA", "MS-RL", "CPL-")
NONCOMMERCIAL_OR_SOURCE_AVAILABLE = ("CC-BY-NC", "BUSL-", "SSPL-", "Llama-")
_OPERATORS = re.compile(r"\s+(AND|OR|WITH)\s+")


def normalize_license(raw: str | None) -> str | None:
    """Return an SPDX id/expression, a LicenseRef-*, or None."""
    if raw is None:
        return None
    text = raw.strip().strip("()")
    if not text or text.upper() in ("NOASSERTION", "NONE", "UNKNOWN"):
        return None
    if _OPERATORS.search(text):  # already an expression: normalise each operand
        parts = _OPERATORS.split(text)
        return " ".join(p if p in ("AND", "OR", "WITH") else (normalize_license(p) or p) for p in parts)
    if text.startswith("LicenseRef-") or text.startswith("DocumentRef-"):
        return text
    low = text.lower()
    if low in _SPDX_LOWER:
        return _SPDX_LOWER[low]
    if low in _LICENSE_ALIASES:
        return _LICENSE_ALIASES[low]
    legacy = {"gpl-2.0+": "GPL-2.0-or-later", "gpl-3.0+": "GPL-3.0-or-later", "lgpl-2.1+": "LGPL-2.1-or-later"}
    if low in legacy:
        return legacy[low]
    return f"LicenseRef-{slug(text)[:60]}"


def is_known_spdx(lic: str) -> bool:
    ids = [p for p in _OPERATORS.split(lic.strip("()")) if p not in ("AND", "OR", "WITH")]
    return all(i.strip("() ") in SPDX_IDS or i.strip("() ").startswith("LicenseRef-") for i in ids)


def license_restrictions(licenses: list[str]) -> str | None:
    if not licenses:
        return None
    joined = " ".join(licenses)
    notes = []
    if any(p in joined for p in NONCOMMERCIAL_OR_SOURCE_AVAILABLE):
        notes.append("licence restricts commercial/field-of-use")
    if any(p in joined for p in COPYLEFT_PREFIXES):
        notes.append("copyleft obligations (source disclosure/attribution)")
    if "LicenseRef-" in joined:
        notes.append("non-SPDX licence - manual legal review required")
    if not notes:
        notes.append("permissive licence; attribution required")
    return "; ".join(notes) + "; export control not assessed"

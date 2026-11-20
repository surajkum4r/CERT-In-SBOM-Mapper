"""Optional metadata enrichment (opt-in via --online).

Sends package names/versions to pypi.org, registry.npmjs.org, repo1.maven.org,
crates.io, rubygems.org, api.deps.dev (description, supplier, licence, release date,
hashes) and endoflife.date (EOL dates). Vulnerability sources live in vulns.py.
"""
from __future__ import annotations

import base64
import json
import logging
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET  # noqa: S405 - expat >= 2.4 guards entity expansion
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from . import TOOL_NAME, __version__
from .model import Bom, Component
from .util import normalize_license, parse_purl, version_lt

log = logging.getLogger(__name__)
_UA = f"{TOOL_NAME}/{__version__}"
_cache: dict[str, object] = {}


def http_json(url: str, payload: dict | None = None, timeout: float = 15.0):
    """GET (or POST when payload is given) JSON. Returns None on 404/network errors."""
    key = url + (json.dumps(payload, sort_keys=True) if payload else "")
    if key in _cache:
        return _cache[key]
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, headers={"User-Agent": _UA, "Accept": "application/json",
                                                         **({"Content-Type": "application/json"} if data else {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoints
            result = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code != 404:
            log.warning("%s -> HTTP %s", url, e.code)
        result = None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        log.warning("%s -> %s", url, e)
        result = None
    _cache[key] = result
    return result


# ------------------------------------------------------------------ registries
def _fill(c: Component, field_name: str, value, how: str) -> None:
    if value and not getattr(c, field_name):
        c.set(field_name, value, how)


def pypi_enrich(c: Component, p: dict, timeout: float) -> None:
    doc = http_json(f"https://pypi.org/pypi/{quote(p['name'])}/{quote(p['version'])}/json", timeout=timeout)
    if not doc:
        return
    info = doc.get("info") or {}
    _fill(c, "description", info.get("summary"), "online:pypi.org")
    _fill(c, "supplier", info.get("maintainer") or info.get("author")
          or (info.get("author_email") or "").split("<")[0].strip(), "online:pypi.org")
    lic = info.get("license_expression") or (info.get("license") if len(info.get("license") or "") < 80 else None)
    if not lic:
        lic = next((cl.split("::")[-1].strip() for cl in info.get("classifiers") or [] if cl.startswith("License ::")), None)
    if lic and not c.licenses:
        c.set("licenses", [normalize_license(lic)], "online:pypi.org")
    urls = doc.get("urls") or []
    pick = next((u for u in urls if u.get("packagetype") == "sdist"), urls[0] if urls else None)
    if pick:
        _fill(c, "release_date", (pick.get("upload_time_iso_8601") or "")[:10], "online:pypi.org")
        if not c.hashes and (pick.get("digests") or {}).get("sha256"):
            c.set("hashes", {"SHA-256": pick["digests"]["sha256"]}, f"online:pypi.org ({pick.get('filename')})")


def npm_enrich(c: Component, p: dict, timeout: float) -> None:
    name = f"{p['namespace']}/{p['name']}" if p.get("namespace") else p["name"]
    doc = http_json(f"https://registry.npmjs.org/{quote(name, safe='@')}", timeout=timeout)
    if not doc:
        return
    ver = (doc.get("versions") or {}).get(p["version"]) or {}
    _fill(c, "description", ver.get("description"), "online:npmjs")
    author = ver.get("author")
    _fill(c, "supplier", author.get("name") if isinstance(author, dict) else author, "online:npmjs")
    lic = ver.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    if lic and not c.licenses:
        c.set("licenses", [normalize_license(lic)], "online:npmjs")
    _fill(c, "release_date", ((doc.get("time") or {}).get(p["version"]) or "")[:10], "online:npmjs")
    integrity = (ver.get("dist") or {}).get("integrity", "")
    if not c.hashes and integrity.startswith("sha512-"):
        c.set("hashes", {"SHA-512": base64.b64decode(integrity[7:]).hex()}, "online:npmjs (tarball)")


# Package names whose endoflife.date product slug differs from the package name.
# Anything else is matched against the live endoflife.date product list.
EOL_ALIASES = {
    "spring-core": "spring-framework", "spring-webmvc": "spring-framework", "spring-boot-starter": "spring-boot",
    "tomcat-catalina": "tomcat", "tomcat-embed-core": "tomcat", "log4j-core": "log4j", "log4j-api": "log4j",
    "@angular/core": "angular", "laravel/framework": "laravel", "symfony/symfony": "symfony",
    "symfony/http-kernel": "symfony", "node": "nodejs", "struts2-core": "apache-struts",
    "hibernate-core": "hibernate", "next": "nextjs", "@nestjs/core": "nestjs", "jakarta.jakartaee-api": "jakarta-ee",
    "rails": "rails", "railties": "rails", "activerecord": "rails", "openjdk": "openjdk-builds-from-oracle",
    "kotlin-stdlib": "kotlin", "scala-library": "scala", "typo3/cms-core": "typo3", "drupal/core": "drupal",
    "wordpress": "wordpress", "jquery": "jquery", "bootstrap": "bootstrap", "vue": "vue", "react": "react",
    "react-native": "react-native", "electron": "electron", "elasticsearch": "elasticsearch",
    "org.elasticsearch:elasticsearch": "elasticsearch", "postgresql": "postgresql", "openssl": "openssl",
    "libssl3": "openssl", "libssl1.1": "openssl", "python3": "python", "nginx": "nginx", "redis": "redis",
}


def _eol_products(timeout: float) -> set[str]:
    data = http_json("https://endoflife.date/api/all.json", timeout=timeout)
    return set(data) if isinstance(data, list) else set()


def eol_enrich(c: Component, p: dict | None, timeout: float) -> None:
    name = (f"{p['namespace']}/{p['name']}" if p and p.get("namespace") and p["type"] in ("npm", "composer")
            else (p["name"] if p else c.name)).lower()
    version = (p or {}).get("version") or c.version
    if not version:
        return
    products = _eol_products(timeout)
    product = EOL_ALIASES.get(name) or EOL_ALIASES.get(c.name.lower()) or (name if name in products else None)
    if not product:
        return
    cycles = http_json(f"https://endoflife.date/api/{product}.json", timeout=timeout)
    if not isinstance(cycles, list):
        return
    ver = version.lstrip("v").split("+")[0]
    match = None
    for cyc in sorted(cycles, key=lambda x: len(str(x.get("cycle", ""))), reverse=True):
        cy = str(cyc.get("cycle", ""))
        if ver == cy or ver.startswith(cy + "."):
            match = cyc
            break
    if not match:
        return
    eol = match.get("eol")
    value = eol if isinstance(eol, str) else ("ended (date not published)" if eol else "not announced")
    _fill(c, "eol_date", value, f"online:endoflife.date/{product}")
    if not c.release_date and match.get("releaseDate") and match.get("latest") == ver:
        c.set("release_date", match["releaseDate"], f"online:endoflife.date/{product}")
    latest = match.get("latest")
    if latest and version_lt(ver, str(latest)):
        c.comments = ((c.comments + "; ") if c.comments else "") + f"newer patch release in cycle: {latest}"


def http_text(url: str, timeout: float = 15.0) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoints
            return resp.read(2_000_000).decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError):
        return None


def maven_enrich(c: Component, p: dict, timeout: float) -> None:
    """Description, supplier, licence and artefact hash from Maven Central."""
    if not p.get("namespace"):
        return
    base = (f"https://repo1.maven.org/maven2/{p['namespace'].replace('.', '/')}/{quote(p['name'])}/"
            f"{quote(p['version'])}/{quote(p['name'])}-{quote(p['version'])}")
    pom = http_text(base + ".pom", timeout)
    if pom:
        try:
            root = ET.fromstring(pom)
        except ET.ParseError:
            root = None
        if root is not None:
            ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {"m": ""}
            find = (lambda path: root.findtext(path, namespaces=ns)) if ns["m"] else \
                (lambda path: root.findtext(path.replace("m:", "")))
            _fill(c, "description", " ".join((find("m:description") or "").split())[:300], "online:maven-central")
            _fill(c, "supplier", find("m:organization/m:name") or find("m:developers/m:developer/m:organization")
                  or find("m:developers/m:developer/m:name"), "online:maven-central")
            lic = find("m:licenses/m:license/m:name")
            if lic and not c.licenses:
                c.set("licenses", [normalize_license(lic)], "online:maven-central")
    if not c.hashes or set(c.hashes) <= {"MD5", "SHA-1"}:
        for ext, alg in ((".jar.sha512", "SHA-512"), (".jar.sha256", "SHA-256")):
            digest = (http_text(base + ext, timeout) or "").split()
            if digest and re.fullmatch(r"[0-9a-fA-F]{64,128}", digest[0]):
                c.hashes[alg] = digest[0].lower()
                c.derivations["hashes"] = "online:maven-central"
                break


def crates_enrich(c: Component, p: dict, timeout: float) -> None:
    doc = http_json(f"https://crates.io/api/v1/crates/{quote(p['name'])}/{quote(p['version'])}", timeout=timeout)
    ver = (doc or {}).get("version") or {}
    if not ver:
        return
    _fill(c, "release_date", (ver.get("created_at") or "")[:10], "online:crates.io")
    if ver.get("license") and not c.licenses:
        c.set("licenses", [normalize_license(ver["license"])], "online:crates.io")
    if ver.get("checksum") and not c.hashes:
        c.set("hashes", {"SHA-256": ver["checksum"]}, "online:crates.io")
    _fill(c, "supplier", (ver.get("published_by") or {}).get("name"), "online:crates.io")
    crate = (http_json(f"https://crates.io/api/v1/crates/{quote(p['name'])}", timeout=timeout) or {}).get("crate") or {}
    _fill(c, "description", crate.get("description"), "online:crates.io")


def rubygems_enrich(c: Component, p: dict, timeout: float) -> None:
    doc = http_json(f"https://rubygems.org/api/v2/rubygems/{quote(p['name'])}/versions/{quote(p['version'])}.json",
                    timeout=timeout)
    if not doc:
        return
    _fill(c, "description", doc.get("info"), "online:rubygems.org")
    _fill(c, "supplier", doc.get("authors"), "online:rubygems.org")
    _fill(c, "release_date", (doc.get("version_created_at") or doc.get("created_at") or "")[:10], "online:rubygems.org")
    if doc.get("licenses") and not c.licenses:
        c.set("licenses", [normalize_license(x) for x in doc["licenses"] if normalize_license(x)], "online:rubygems.org")
    if doc.get("sha") and not c.hashes:
        c.set("hashes", {"SHA-256": doc["sha"]}, "online:rubygems.org")


_DEPS_DEV = {"maven": "MAVEN", "golang": "GO", "cargo": "CARGO", "nuget": "NUGET", "npm": "NPM", "pypi": "PYPI"}


def deps_dev_enrich(c: Component, p: dict, timeout: float) -> None:
    """Release date and licences from deps.dev (covers Maven/Go/Cargo/NuGet too)."""
    system = _DEPS_DEV.get(p["type"])
    if not system:
        return
    sep = ":" if p["type"] == "maven" else "/"
    name = f"{p['namespace']}{sep}{p['name']}" if p.get("namespace") else p["name"]
    doc = http_json(f"https://api.deps.dev/v3/systems/{system}/packages/{quote(name, safe='')}"
                    f"/versions/{quote(p['version'], safe='')}", timeout=timeout)
    if not doc:
        return
    _fill(c, "release_date", (doc.get("publishedAt") or "")[:10], "online:deps.dev")
    lics = [normalize_license(x) for x in doc.get("licenses") or [] if x and x != "non-standard"]
    if lics and not c.licenses:
        c.set("licenses", [x for x in lics if x], "online:deps.dev")


_REGISTRY = {"pypi": pypi_enrich, "npm": npm_enrich, "maven": maven_enrich, "cargo": crates_enrich,
             "gem": rubygems_enrich}


def _enrich_one(c: Component, timeout: float) -> None:
    p = parse_purl(c.purl)
    try:
        if p and p.get("version"):
            if p["type"] in _REGISTRY:
                _REGISTRY[p["type"]](c, p, timeout)
            if not c.release_date or not c.licenses:
                deps_dev_enrich(c, p, timeout)
        eol_enrich(c, p, timeout)  # also works by name for components without a purl
    except Exception as e:  # noqa: BLE001 - enrichment must never abort generation
        log.warning("enrichment failed for %s: %s", c.purl or c.name, e)


def enrich_online(bom: Bom, timeout: float) -> None:
    """Metadata only; vulnerability sources are handled by vulns.scan()."""
    _eol_products(timeout)  # warm the cache once before fanning out
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda c: _enrich_one(c, timeout), bom.components))

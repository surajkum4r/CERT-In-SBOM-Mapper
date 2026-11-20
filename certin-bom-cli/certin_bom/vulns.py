"""Vulnerability coverage: multiple sources, de-duplication, scoring and prioritisation.

Sources
  * OSV (api.osv.dev or an offline OSV database built with `certin-bom vulndb update`)
    - language ecosystems via purl, OS packages (Debian/Ubuntu/Alpine) via ecosystem + source package
    - includes GitHub Security Advisories, PyPA, RustSec, Go, malicious-package (MAL-) reports
  * NVD CVE API 2.0 by CPE - for components with no package-ecosystem identity (C/C++, appliances)
  * CISA Known Exploited Vulnerabilities catalogue (KEV)
  * FIRST EPSS exploit-prediction scores
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import os
import re
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path
from urllib.parse import parse_qsl, quote

from . import TOOL_NAME, __version__
from .cvss import base_score, severity as cvss_severity
from .model import Bom, Component, Vulnerability
from .online import http_json
from .util import parse_purl, version_lt

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_CSV_URLS = ("https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
                 "https://epss.cyentia.com/epss_scores-current.csv.gz")
OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"
NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPES = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

# purl type -> OSV ecosystem (language ecosystems)
PURL_TO_OSV = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go", "cargo": "crates.io",
               "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist", "hex": "Hex", "pub": "Pub",
               "swift": "SwiftURL", "cran": "CRAN", "hackage": "Hackage", "conan": "ConanCenter",
               "bitnami": "Bitnami"}
DEBIAN_CODENAMES = {"stretch": "9", "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
SEV_RANK = {None: 0, "unknown": 0, "none": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
CLOSED_STATES = ("resolved", "resolved_with_pedigree", "not_affected", "false_positive")


def _today() -> str:
    return date.today().isoformat()


def _norm_name(ecosystem: str, name: str) -> str:
    name = name.lower()
    return re.sub(r"[-_.]+", "-", name) if ecosystem == "PyPI" else name


# ------------------------------------------------------------------ query building
def osv_target(c: Component) -> dict | None:
    """Return {"ecosystem", "name", "version", "query"} for a component, or None if OSV cannot cover it."""
    p = parse_purl(c.purl)
    if not p or not p.get("version"):
        return None
    q = dict(parse_qsl(p.get("qualifiers") or ""))
    ns = (p.get("namespace") or "").lower()
    if p["type"] in ("deb", "apk"):
        src = (q.get("upstream") or p["name"]).split("@")[0].split(" ")[0]
        distro = (q.get("distro") or "").lower()
        eco = None
        if p["type"] == "deb" and ns == "debian":
            m = re.search(r"(\d+)", distro)
            rel = m.group(1) if m else next((v for k, v in DEBIAN_CODENAMES.items() if k in distro), None)
            eco = f"Debian:{rel}" if rel else "Debian"
        elif p["type"] == "deb" and ns == "ubuntu":
            m = re.search(r"(\d{2})\.(\d{2})", distro)
            if m:
                lts = int(m.group(1)) % 2 == 0 and m.group(2) == "04"
                eco = f"Ubuntu:{m.group(1)}.{m.group(2)}" + (":LTS" if lts else "")
        elif p["type"] == "apk" and ns == "alpine":
            m = re.search(r"(\d+)\.(\d+)", distro)
            eco = f"Alpine:v{m.group(1)}.{m.group(2)}" if m else None
        if not eco:
            return None
        return {"ecosystem": eco, "name": src, "version": p["version"],
                "query": {"package": {"name": src, "ecosystem": eco}, "version": p["version"]}}
    eco = PURL_TO_OSV.get(p["type"])
    if not eco:
        return None
    if p["type"] == "maven":
        name = f"{p['namespace']}:{p['name']}" if p.get("namespace") else p["name"]
    elif p.get("namespace") and p["type"] in ("npm", "golang", "composer", "swift"):
        name = f"{p['namespace']}/{p['name']}"
    else:
        name = p["name"]
    # qualifiers (?type=jar, ?arch=...) make OSV reject or miss the purl, so send name + ecosystem
    return {"ecosystem": eco, "name": name, "version": p["version"],
            "query": {"package": {"name": name, "ecosystem": eco}, "version": p["version"]}}


# ------------------------------------------------------------------ OSV record -> Vulnerability
def _osv_severity(v: dict) -> tuple[str | None, str | None, str | None]:
    sev = (v.get("database_specific") or {}).get("severity")
    sev = sev.lower() if isinstance(sev, str) else None
    sev = "medium" if sev == "moderate" else sev
    vector = method = None
    for s in v.get("severity") or []:  # prefer v3 (scorable), else v4
        if s.get("type") == "CVSS_V3":
            vector, method = s.get("score"), "CVSSv31" if "3.1" in (s.get("score") or "") else "CVSSv3"
            break
        if s.get("type") == "CVSS_V4" and not vector:
            vector, method = s.get("score"), "CVSSv4"
    return sev, vector, method


def _cwes(values) -> list[int]:
    out = []
    for v in values or []:
        m = re.match(r"CWE-(\d+)", str(v))
        if m:
            out.append(int(m.group(1)))
    return sorted(set(out))


def _affected_entries(detail: dict, target: dict) -> list[dict]:
    want = _norm_name(target["ecosystem"], target["name"])
    eco_base = target["ecosystem"].split(":")[0]
    out = []
    for aff in detail.get("affected") or []:
        pkg = aff.get("package") or {}
        if _norm_name(target["ecosystem"], pkg.get("name", "")) != want:
            continue
        aeco = pkg.get("ecosystem", "")
        if aeco != target["ecosystem"] and aeco.split(":")[0] != eco_base:
            continue
        if ":" in target["ecosystem"] and ":" in aeco and aeco != target["ecosystem"]:
            continue  # a different distro release
        out.append(aff)
    return out


def _fixed_for(detail: dict, target: dict) -> list[str]:
    fixed = []
    for aff in _affected_entries(detail, target):
        for rng in aff.get("ranges") or []:
            if rng.get("type") != "GIT":
                fixed += [e["fixed"] for e in rng.get("events") or [] if "fixed" in e]
    return sorted(set(fixed))


def osv_to_vuln(detail: dict, source: str = "OSV") -> Vulnerability:
    sev, vector, method = _osv_severity(detail)
    vid = detail["id"]
    # "upstream" (OSV schema 1.6) carries the CVE for distro records such as DEBIAN-CVE-*/UBUNTU-CVE-*
    aliases = list(dict.fromkeys(a for a in (detail.get("aliases") or []) + (detail.get("upstream") or []) if a != vid))
    return Vulnerability(
        id=vid, source=source, source_url=f"https://osv.dev/vulnerability/{vid}",
        aliases=aliases, severity=sev, vector=vector, method=method,
        description=detail.get("summary") or (detail.get("details") or "")[:500] or None,
        references=[r["url"] for r in detail.get("references") or [] if r.get("url")][:10],
        published=detail.get("published"), cwes=_cwes((detail.get("database_specific") or {}).get("cwe_ids")),
        reported_by=[source],
    )


def _attach(bom: Bom, index: dict[str, Vulnerability], comp: Component, detail: dict, target: dict, source: str) -> bool:
    if detail.get("withdrawn"):
        return False
    vid = detail["id"]
    vuln = index.get(vid)
    new = vuln is None
    if new:
        vuln = osv_to_vuln(detail, source)
        index[vid] = vuln
        bom.vulnerabilities.append(vuln)
    if comp.ref not in vuln.affects:
        vuln.affects.append(comp.ref)
    vuln.fixed_versions[comp.ref] = _fixed_for(detail, target)
    if vid.startswith("MAL-"):
        vuln.severity = "critical"
        vuln.description = "MALICIOUS PACKAGE: " + (vuln.description or "reported in the OSV malicious packages feed")
    return new


def _mark_scanned(c: Component, source: str) -> None:
    prev = [s for s in (c.vulnerability_scan or "").split(",") if s and not s.startswith(source.split(":")[0])
            and s != "source-sbom"]
    c.vulnerability_scan = ",".join(prev + [f"{source}:{_today()}"])
    c.derivations["vulnerability_scan"] = f"online:{source}" if "offline" not in source else source
    c.vulnerability_scan_gap = None
    c.known_unknowns.discard("vulnerabilities")


# ------------------------------------------------------------------ OSV online
def osv_online(bom: Bom, timeout: float) -> int:
    targets = [(c, t) for c in bom.components if (t := osv_target(c))]
    index = {v.id: v for v in bom.vulnerabilities}
    found = 0
    for start in range(0, len(targets), 500):
        chunk = targets[start:start + 500]
        res = http_json("https://api.osv.dev/v1/querybatch", {"queries": [t["query"] for _, t in chunk]}, timeout)
        if res is None:
            log.warning("OSV batch query failed for %d components", len(chunk))
            continue
        hits_per: list[list[str]] = []
        for (c, t), result in zip(chunk, res.get("results") or []):
            ids = [h["id"] for h in result.get("vulns") or []]
            token = result.get("next_page_token")
            while token:  # paginated (packages with very many advisories)
                page = http_json("https://api.osv.dev/v1/query", {**t["query"], "page_token": token}, timeout) or {}
                ids += [v["id"] for v in page.get("vulns") or []]
                token = page.get("next_page_token")
            hits_per.append(ids)
        all_ids = sorted({i for ids in hits_per for i in ids} - set(index))
        with ThreadPoolExecutor(max_workers=8) as pool:
            details = dict(zip(all_ids, pool.map(
                lambda i: http_json(f"https://api.osv.dev/v1/vulns/{quote(i)}", timeout=timeout), all_ids)))
        for (c, t), ids in zip(chunk, hits_per):
            _mark_scanned(c, "osv.dev")
            for vid in ids:
                detail = details.get(vid) or http_json(f"https://api.osv.dev/v1/vulns/{quote(vid)}", timeout=timeout)
                if detail:
                    found += _attach(bom, index, c, detail, t, "OSV")
    return found


# ------------------------------------------------------------------ OSV offline
def _in_range(version: str, aff: dict) -> bool:
    if version in (aff.get("versions") or []):
        return True
    ge = lambda v, lo: lo in ("0", "") or not version_lt(v, lo)  # noqa: E731
    for rng in aff.get("ranges") or []:
        if rng.get("type") == "GIT":
            continue
        intro = None
        for e in rng.get("events") or []:
            if "introduced" in e:
                intro = e["introduced"]
            elif "fixed" in e and intro is not None:
                if ge(version, intro) and version_lt(version, e["fixed"]):
                    return True
                intro = None
            elif "last_affected" in e and intro is not None:
                if ge(version, intro) and not version_lt(e["last_affected"], version):
                    return True
                intro = None
        if intro is not None and ge(version, intro):
            return True
    return False


class OfflineDB:
    """Reads indexes produced by `certin-bom vulndb update`."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self._idx: dict[str, dict] = {}
        meta = self.root / "metadata.json"
        self.meta = json.loads(meta.read_text()) if meta.exists() else {}

    def index(self, ecosystem: str) -> dict | None:
        base = ecosystem.split(":")[0]
        if base not in self._idx:
            path = self.root / f"osv-{base.replace('/', '_')}.json.gz"
            self._idx[base] = json.loads(gzip.decompress(path.read_bytes())) if path.exists() else None
        return self._idx[base]

    def kev(self) -> dict | None:
        p = self.root / "kev.json"
        return json.loads(p.read_text()) if p.exists() else None

    def epss(self) -> dict[str, tuple[float, float]]:
        p = self.root / "epss.json.gz"
        return {k: tuple(v) for k, v in json.loads(gzip.decompress(p.read_bytes())).items()} if p.exists() else {}


def osv_offline(bom: Bom, db: OfflineDB) -> int:
    index = {v.id: v for v in bom.vulnerabilities}
    found, missing_eco = 0, set()
    built = db.meta.get("built", "unknown-date")
    for c in bom.components:
        t = osv_target(c)
        if not t:
            continue
        idx = db.index(t["ecosystem"])
        if idx is None:
            missing_eco.add(t["ecosystem"].split(":")[0])
            continue
        for rec in idx.get(_norm_name(t["ecosystem"], t["name"]), []):
            if any(_in_range(t["version"], a) for a in _affected_entries(rec, t)):
                found += _attach(bom, index, c, rec, t, "OSV (offline)")
        _mark_scanned(c, f"osv-offline({built})")
    for eco in sorted(missing_eco):
        log.warning("offline DB has no %s index - run `certin-bom vulndb update --ecosystem %s`", eco, eco)
    return found


def _slim(rec: dict) -> dict:
    keep = {k: rec[k] for k in ("id", "aliases", "upstream", "summary", "severity", "published", "withdrawn") if k in rec}
    ds = rec.get("database_specific") or {}
    keep["database_specific"] = {k: ds[k] for k in ("severity", "cwe_ids") if k in ds}
    keep["references"] = [{"url": r["url"]} for r in (rec.get("references") or [])[:5] if r.get("url")]
    keep["affected"] = [{"package": a.get("package", {}), "ranges": a.get("ranges", []),
                         "versions": a.get("versions", [])} for a in rec.get("affected") or []]
    return keep


def _download(url: str, timeout: float = 120.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": f"{TOOL_NAME}/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https endpoints
        return resp.read()


def update_offline_db(root: str | Path, ecosystems: list[str], with_kev: bool = True, with_epss: bool = True) -> dict:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    stats: dict = {"built": _today(), "ecosystems": {}}
    for eco in ecosystems:
        log.warning("downloading OSV %s ...", eco)
        data = _download(f"{OSV_BUCKET}/{quote(eco)}/all.zip")
        idx: dict[str, list] = {}
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                rec = json.loads(zf.read(name))
                if rec.get("withdrawn"):
                    continue
                slim = _slim(rec)
                for a in slim["affected"]:
                    pkg = a["package"]
                    key = _norm_name(pkg.get("ecosystem", eco).split(":")[0], pkg.get("name", ""))
                    if key and (not idx.get(key) or idx[key][-1]["id"] != slim["id"]):
                        idx.setdefault(key, []).append(slim)
        (root / f"osv-{eco.replace('/', '_')}.json.gz").write_bytes(gzip.compress(json.dumps(idx).encode()))
        stats["ecosystems"][eco] = {"packages": len(idx), "advisories": len({r["id"] for v in idx.values() for r in v})}
    if with_kev:
        (root / "kev.json").write_bytes(_download(KEV_URL))
        stats["kev"] = len(json.loads((root / "kev.json").read_text()).get("vulnerabilities", []))
    if with_epss:
        for url in EPSS_CSV_URLS:
            try:
                raw = gzip.decompress(_download(url)).decode()
                break
            except Exception as e:  # noqa: BLE001
                log.warning("EPSS download from %s failed: %s", url, e)
        else:
            raw = ""
        scores = {r["cve"]: (float(r["epss"]), float(r["percentile"]))
                  for r in csv.DictReader(line for line in io.StringIO(raw) if not line.startswith("#")) if r.get("cve")}
        (root / "epss.json.gz").write_bytes(gzip.compress(json.dumps(scores).encode()))
        stats["epss"] = len(scores)
    prev = json.loads((root / "metadata.json").read_text()) if (root / "metadata.json").exists() else {}
    prev.setdefault("ecosystems", {}).update(stats.pop("ecosystems"))
    prev.update(stats)
    (root / "metadata.json").write_text(json.dumps(prev, indent=2))
    return prev


# ------------------------------------------------------------------ NVD (CPE-identified components)
class _Nvd:
    def __init__(self, api_key: str | None, timeout: float):
        self.key, self.timeout = api_key, timeout
        self.delay = 0.7 if api_key else 6.5  # NVD: 50 vs 5 requests per rolling 30 s
        self._last = 0.0

    def get(self, base: str, params: str):
        wait = self._last + self.delay - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        url = f"{base}?{params}"
        if not self.key:
            return http_json(url, timeout=self.timeout)
        req = urllib.request.Request(url, headers={"apiKey": self.key, "User-Agent": f"{TOOL_NAME}/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                return json.loads(resp.read())
        except Exception as e:  # noqa: BLE001
            log.warning("NVD %s -> %s", url, e)
            return None


def _cpe_product(cpe: str) -> str | None:
    parts = cpe.split(":")
    return parts[4].lower() if len(parts) > 5 else None


def _nvd_version_matches(cve: dict, product: str | None, version: str) -> bool:
    """Confirm the version falls inside a *vulnerable* cpeMatch for the product.

    NVD's cpeName search also returns CVEs where the product appears only as a
    platform or in an unrelated version range; those are false positives.
    Returns True when the CVE cannot be verified (no product-specific match data).
    """
    entries = [m for conf in cve.get("configurations") or [] for node in conf.get("nodes") or []
               for m in node.get("cpeMatch") or [] if _cpe_product(m.get("criteria", "")) == product]
    vulnerable = [m for m in entries if m.get("vulnerable")]
    if not entries:
        return True
    for m in vulnerable:
        exact = m["criteria"].split(":")[5]
        if exact not in ("*", "-"):
            if exact == version:
                return True
            continue
        lo_in, lo_ex = m.get("versionStartIncluding"), m.get("versionStartExcluding")
        hi_in, hi_ex = m.get("versionEndIncluding"), m.get("versionEndExcluding")
        if lo_in and version_lt(version, lo_in):
            continue
        if lo_ex and not version_lt(lo_ex, version):
            continue
        if hi_ex and not version_lt(version, hi_ex):
            continue
        if hi_in and version_lt(hi_in, version):
            continue
        return True
    return False


def _nvd_fixed(cve: dict, product: str | None) -> list[str]:
    out = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") and m.get("versionEndExcluding") and (
                        not product or _cpe_product(m.get("criteria", "")) == product):
                    out.append(m["versionEndExcluding"])
    return sorted(set(out))


def nvd_to_vuln(cve: dict) -> Vulnerability:
    metrics = cve.get("metrics") or {}
    score = vector = sev = method = None
    for key, meth in (("cvssMetricV31", "CVSSv31"), ("cvssMetricV30", "CVSSv3"), ("cvssMetricV40", "CVSSv4"),
                      ("cvssMetricV2", "CVSSv2")):
        if metrics.get(key):
            m = next((x for x in metrics[key] if x.get("type") == "Primary"), metrics[key][0])
            d = m.get("cvssData") or {}
            score, vector, method = d.get("baseScore"), d.get("vectorString"), meth
            sev = (d.get("baseSeverity") or m.get("baseSeverity") or "").lower() or None
            break
    desc = next((d["value"] for d in cve.get("descriptions") or [] if d.get("lang") == "en"), None)
    cwes = _cwes(d.get("value") for w in cve.get("weaknesses") or [] for d in w.get("description") or [])
    return Vulnerability(id=cve["id"], source="NVD", source_url=f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                         severity=sev, score=score, vector=vector, method=method, description=desc,
                         references=[r["url"] for r in (cve.get("references") or [])[:10] if r.get("url")],
                         published=cve.get("published"), cwes=cwes, reported_by=["NVD"])


def nvd_scan(bom: Bom, api_key: str | None, timeout: float, guess_cpe: bool = True) -> int:
    nvd = _Nvd(api_key, timeout)
    index = {v.id: v for v in bom.vulnerabilities}
    for v in list(bom.vulnerabilities):
        for a in v.aliases:
            index.setdefault(a, v)
    found = 0
    for c in bom.components:
        if osv_target(c) or not c.version:
            continue  # covered by OSV, or nothing to match on
        cpe = c.cpe
        if not cpe and guess_cpe:
            name = re.sub(r"[^a-z0-9_\-.]", "_", c.name.lower())
            res = nvd.get(NVD_CPES, f"cpeMatchString=cpe:2.3:*:*:{quote(name)}:{quote(c.version)}&resultsPerPage=20") or {}
            names = sorted({p["cpe"]["cpeName"] for p in res.get("products") or [] if not p["cpe"].get("deprecated")})
            vendors = {n.split(":")[3] for n in names}
            if len(vendors) == 1 and names:
                cpe = names[0]
                c.set("cpe", cpe, "derived:nvd-cpe-dictionary")
            elif len(vendors) > 1:
                c.vulnerability_scan_gap = f"ambiguous CPE vendor for {c.name}: {', '.join(sorted(vendors)[:5])} - set cpe via overrides"
                continue
        if not cpe:
            c.vulnerability_scan_gap = c.vulnerability_scan_gap or "no ecosystem purl or CPE - add a CPE via overrides"
            continue
        start, total, ok = 0, 1, True
        while start < total:
            res = nvd.get(NVD_CVES, f"cpeName={quote(cpe, safe=':*')}&startIndex={start}&resultsPerPage=2000")
            if res is None:
                ok = False
                break
            total = res.get("totalResults", 0)
            items = res.get("vulnerabilities") or []
            for item in items:
                cve = item["cve"]
                if cve.get("vulnStatus") == "Rejected":
                    continue
                cpe_ver = cpe.split(":")[5] if len(cpe.split(":")) > 5 else c.version
                if not _nvd_version_matches(cve, _cpe_product(cpe), cpe_ver):
                    log.debug("NVD %s dropped for %s %s: version outside vulnerable ranges", cve["id"], c.name, cpe_ver)
                    continue
                vuln = index.get(cve["id"])
                if vuln is None:
                    vuln = nvd_to_vuln(cve)
                    index[vuln.id] = vuln
                    bom.vulnerabilities.append(vuln)
                    found += 1
                if c.ref not in vuln.affects:
                    vuln.affects.append(c.ref)
                vuln.fixed_versions[c.ref] = _nvd_fixed(cve, _cpe_product(cpe))
            if not items:
                break
            start += len(items)
        if ok:
            _mark_scanned(c, "nvd")
    return found


def nvd_backfill(bom: Bom, api_key: str | None, timeout: float, limit: int | None = None) -> int:
    """Fetch CVSS/CWE from NVD for CVE-linked records that arrived without a score (e.g. distro advisories)."""
    nvd = _Nvd(api_key, timeout)
    todo = [v for v in bom.vulnerabilities if v.score is None and not (v.vector or "").startswith("CVSS:3")
            and _cve_of(v) and "NVD" not in v.reported_by]
    if limit is None:
        limit = len(todo) if api_key else 40
    if len(todo) > limit:
        log.warning("NVD backfill limited to %d of %d unscored CVEs (set NVD_API_KEY to lift the limit)", limit, len(todo))
    n = 0
    for v in todo[:limit]:
        res = nvd.get(NVD_CVES, f"cveId={_cve_of(v)}") or {}
        items = res.get("vulnerabilities") or []
        if not items:
            continue
        ref = nvd_to_vuln(items[0]["cve"])
        v.score, v.vector, v.method = ref.score, ref.vector, ref.method
        v.severity = v.severity or ref.severity
        v.cwes = sorted(set(v.cwes) | set(ref.cwes))
        v.description = v.description or ref.description
        v.reported_by = sorted(set(v.reported_by) | {"NVD"})
        n += 1
    return n


# ------------------------------------------------------------------ de-duplication & scoring
def _cve_of(v: Vulnerability) -> str | None:
    return v.id if v.id.startswith("CVE-") else next((a for a in v.aliases if a.startswith("CVE-")), None)


def merge_duplicates(bom: Bom) -> int:
    """Merge records that describe the same flaw (GHSA/PYSEC/CVE aliases). Returns records removed.

    Bundled advisories (DSA/USN/RHSA... listing several CVEs) are never used as merge
    links - that would collapse distinct CVEs into one. They are folded into the
    per-CVE records afterwards when every CVE they list is already tracked.
    """
    original = len(bom.vulnerabilities)
    bundles = [v for v in bom.vulnerabilities if len({a for a in [v.id] + v.aliases if a.startswith("CVE-")}) > 1]
    bundle_ids = {id(v) for v in bundles}
    bom.vulnerabilities = [v for v in bom.vulnerabilities if id(v) not in bundle_ids]
    parent = list(range(len(bom.vulnerabilities)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    seen: dict[str, int] = {}
    for i, v in enumerate(bom.vulnerabilities):
        for ident in [v.id] + v.aliases:
            if ident in seen:
                parent[find(i)] = find(seen[ident])
            else:
                seen[ident] = i
    groups: dict[int, list[Vulnerability]] = {}
    for i, v in enumerate(bom.vulnerabilities):
        groups.setdefault(find(i), []).append(v)
    merged = []
    for members in groups.values():
        if len(members) == 1:
            v = members[0]
            cves = [a for a in v.aliases if a.startswith("CVE-")]
            if not v.id.startswith("CVE-") and len(cves) == 1:  # use the CVE as the primary identifier
                v.aliases = [v.id] + [a for a in v.aliases if a != cves[0]]
                v.id = cves[0]
            merged.append(v)
            continue
        # canonical id: CVE > GHSA > first; keep source-SBOM triage (analysis) if any
        ids = [m.id for m in members]
        canon = next((i for i in ids if i.startswith("CVE-")), None) or \
            next((a for m in members for a in m.aliases if a.startswith("CVE-")), None) or \
            next((i for i in ids if i.startswith("GHSA-")), ids[0])
        base = next((m for m in members if m.state), None) or next((m for m in members if m.id == canon), members[0])
        out = Vulnerability(**{**base.__dict__, "id": canon})
        out.aliases = sorted({x for m in members for x in [m.id] + m.aliases} - {canon})
        out.affects = list(dict.fromkeys(r for m in members for r in m.affects))
        out.fixed_versions = {}
        for m in members:
            for ref, fx in m.fixed_versions.items():
                out.fixed_versions[ref] = sorted(set(out.fixed_versions.get(ref, [])) | set(fx))
        out.references = list(dict.fromkeys(u for m in members for u in m.references))[:15]
        out.cwes = sorted({c for m in members for c in m.cwes})
        out.reported_by = sorted({s for m in members for s in (m.reported_by or [m.source or "source"])})
        best = max(members, key=lambda m: (m.score or 0, SEV_RANK.get(m.severity, 0)))
        out.score, out.severity = best.score, best.severity or out.severity
        v3 = next((m for m in members if (m.vector or "").startswith("CVSS:3")), None)
        if v3:
            out.vector, out.method = v3.vector, v3.method
        out.description = next((m.description for m in members if m.description and m.source == "NVD"), None) \
            or next((m.description for m in members if m.description), None)
        out.source = "NVD" if canon.startswith("CVE-") and any(m.source == "NVD" for m in members) else base.source
        out.source_url = f"https://nvd.nist.gov/vuln/detail/{canon}" if canon.startswith("CVE-") else base.source_url
        merged.append(out)
    # fold bundles whose every CVE is already a record affecting the same components
    by_cve: dict[str, list[Vulnerability]] = {}
    for v in merged:
        for ident in [v.id] + v.aliases:
            if ident.startswith("CVE-"):
                by_cve.setdefault(ident, []).append(v)
    for b in bundles:
        cves = sorted({a for a in [b.id] + b.aliases if a.startswith("CVE-")})
        covered = all(any(set(b.affects) <= set(t.affects) for t in by_cve.get(c, [])) for c in cves)
        if covered:
            for c in cves:
                for t in by_cve[c]:
                    if b.id not in t.aliases:
                        t.aliases.append(b.id)
                    for ref, fx in b.fixed_versions.items():
                        t.fixed_versions[ref] = sorted(set(t.fixed_versions.get(ref, [])) | set(fx))
        else:
            merged.append(b)
    bom.vulnerabilities = merged
    return original - len(merged)


def score_all(bom: Bom) -> None:
    for v in bom.vulnerabilities:
        if v.score is None and v.vector:
            v.score = base_score(v.vector)
        if not v.severity and v.score is not None:
            v.severity = cvss_severity(v.score)


# ------------------------------------------------------------------ exploitation intelligence
def apply_kev(bom: Bom, kev_doc: dict | None) -> int:
    if not kev_doc:
        return 0
    kev = {k["cveID"]: k for k in kev_doc.get("vulnerabilities") or []}
    n = 0
    for v in bom.vulnerabilities:
        rec = kev.get(_cve_of(v) or "")
        if rec:
            v.kev = {"date_added": rec.get("dateAdded"), "due_date": rec.get("dueDate"),
                     "ransomware": rec.get("knownRansomwareCampaignUse"), "action": rec.get("requiredAction")}
            n += 1
    return n


def apply_epss(bom: Bom, scores: dict[str, tuple[float, float]] | None = None, timeout: float = 15.0) -> int:
    cves = sorted({c for v in bom.vulnerabilities if (c := _cve_of(v))})
    if scores is None:  # online API, 100 CVEs per request
        scores = {}
        for i in range(0, len(cves), 100):
            res = http_json(f"{EPSS_API}?cve={','.join(cves[i:i + 100])}&limit=100", timeout=timeout) or {}
            for row in res.get("data") or []:
                scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    n = 0
    for v in bom.vulnerabilities:
        s = scores.get(_cve_of(v) or "")
        if s:
            v.epss, v.epss_percentile = s
            n += 1
    return n


def prioritise(bom: Bom) -> None:
    """Per-vulnerability priority and per-component summary."""
    for v in bom.vulnerabilities:
        if v.state in CLOSED_STATES:
            v.priority = f"none (VEX: {v.state})"
        elif v.kev:
            v.priority = "P0 - known exploited (CISA KEV" + (", ransomware" if v.kev.get("ransomware") == "Known" else "") + ")"
        elif (v.epss or 0) >= 0.1 or v.severity == "critical" or v.id.startswith("MAL-"):
            v.priority = "P1 - critical severity or high exploit probability (EPSS >= 10%)"
        elif v.severity == "high":
            v.priority = "P2 - high severity"
        else:
            v.priority = "P3 - medium/low/unscored"
    by_comp: dict[str, list[Vulnerability]] = {}
    for v in bom.vulnerabilities:
        for r in v.affects:
            by_comp.setdefault(r, []).append(v)
    for c in bom.components:
        vs = [v for v in by_comp.get(c.ref, []) if v.state not in CLOSED_STATES]
        if not vs:
            if c.vulnerability_scan:
                c.vulnerability_summary = "0 open"
            continue
        sev: dict[str, int] = {}
        for v in vs:
            sev[v.severity or "unscored"] = sev.get(v.severity or "unscored", 0) + 1
        parts = [f"{len(vs)} open", ", ".join(f"{k}:{n}" for k, n in sorted(sev.items(), key=lambda x: -SEV_RANK.get(x[0], 0)))]
        kev = sum(1 for v in vs if v.kev)
        if kev:
            parts.append(f"{kev} in CISA KEV")
        epss = max((v.epss or 0) for v in vs)
        if epss:
            parts.append(f"max EPSS {epss:.2f}")
        if any(v.id.startswith("MAL-") for v in vs):
            parts.append("MALICIOUS PACKAGE")
        c.vulnerability_summary = "; ".join(parts)
        c.derivations["vulnerability_summary"] = "derived:vulnerability-aggregation"


# ------------------------------------------------------------------ driver
def scan(bom: Bom, cfg) -> None:
    db = OfflineDB(cfg.osv_db) if cfg.osv_db else None
    if db:
        log.info("OSV offline: %d new", osv_offline(bom, db))
    elif cfg.online:
        log.info("OSV online: %d new", osv_online(bom, cfg.http_timeout))
    if cfg.nvd and cfg.online:
        key = cfg.nvd_api_key or os.environ.get("NVD_API_KEY")
        log.info("NVD: %d new", nvd_scan(bom, key, cfg.http_timeout, cfg.nvd_guess_cpe))
        merge_duplicates(bom)
        log.info("NVD backfill: %d scored", nvd_backfill(bom, key, cfg.http_timeout))
    if db or cfg.online:
        bom.vulnerabilities_known = True
        for c in bom.components:
            if not c.vulnerability_scan and not c.vulnerability_scan_gap:
                c.vulnerability_scan_gap = "no ecosystem purl/CPE known to the vulnerability sources" + \
                    ("" if cfg.nvd else " (try --nvd)")
    postprocess(bom, cfg, db)


def postprocess(bom: Bom, cfg=None, db: OfflineDB | None = None) -> None:
    removed = merge_duplicates(bom)
    if removed:
        log.info("merged %d duplicate advisories", removed)
    score_all(bom)
    if db:
        apply_kev(bom, db.kev())
        if db.epss():
            apply_epss(bom, db.epss())
    elif cfg is not None and cfg.online and bom.vulnerabilities:
        if cfg.kev:
            apply_kev(bom, http_json(KEV_URL, timeout=max(cfg.http_timeout, 60)))
        if cfg.epss:
            apply_epss(bom, None, cfg.http_timeout)
    prioritise(bom)

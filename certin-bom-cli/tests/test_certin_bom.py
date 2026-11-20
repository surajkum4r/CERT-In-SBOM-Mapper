import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from certin_bom.aibom import build_aibom
from certin_bom.cbom import CbomBuilder, _suite_algorithms, build_cbom
from certin_bom.config import Config
from certin_bom.fields import AIBOM_FIELDS, HBOM_PRODUCT_FIELDS, SBOM_FIELDS
from certin_bom.hbom import build_hbom
from certin_bom.ingest import load_bom
from certin_bom.qbom import build_qbom
from certin_bom.sbom import build_sbom
from certin_bom.split import split
from certin_bom.util import best_fix, build_purl, normalize_license, parse_purl, read_json, version_lt
from certin_bom.validate import validate
from certin_bom.vex import csaf_vex, cyclonedx_vex

HERE = Path(__file__).parent
FIX = HERE / "fixtures"
TPL = HERE.parent / "certin_bom" / "templates"


def _props(c):
    return {p["name"].split(":", 1)[1]: p["value"] for p in c.get("properties", [])}


class UtilTests(unittest.TestCase):
    def test_purl_roundtrip(self):
        p = parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar")
        self.assertEqual((p["type"], p["namespace"], p["name"], p["version"]),
                         ("maven", "org.apache.logging.log4j", "log4j-core", "2.14.1"))
        self.assertEqual(parse_purl(build_purl("npm", "core", "1.0.0", "@angular"))["namespace"], "@angular")
        self.assertIsNone(parse_purl("not-a-purl"))

    def test_licence_normalisation(self):
        self.assertEqual(normalize_license("Apache License, Version 2.0"), "Apache-2.0")
        self.assertEqual(normalize_license("mit"), "MIT")
        self.assertEqual(normalize_license("GPL-2.0+"), "GPL-2.0-or-later")
        self.assertEqual(normalize_license("MIT OR Apache 2.0"), "MIT OR Apache-2.0")
        self.assertTrue(normalize_license("Some Vendor EULA").startswith("LicenseRef-"))
        self.assertIsNone(normalize_license("NOASSERTION"))

    def test_versions(self):
        self.assertTrue(version_lt("2.14.1", "2.15.0"))
        self.assertTrue(version_lt("1.0.0-rc1", "1.0.0"))
        self.assertFalse(version_lt("4.17.21", "4.17.20"))
        self.assertEqual(best_fix("4.2.7", ["4.2.10", "4.2.30", "5.0.1", "6.1.1"]), "4.2.30")
        self.assertEqual(best_fix("1.0", ["2.0", "3.0"]), "2.0")


class SbomTests(unittest.TestCase):
    def setUp(self):
        self.cfg = Config(author="Test PSIRT", organization="Example Org", criticality_heuristic=True)

    def test_raw_supplier_sbom_is_non_conformant(self):
        result = validate(read_json(FIX / "sample.cdx.json"))
        self.assertEqual(result["summary"]["verdict"], "NON-CONFORMANT")
        self.assertGreater(result["summary"]["missing"], 0)

    def test_enriched_sbom_accounts_for_all_21_fields(self):
        doc, _ = build_sbom(FIX / "sample.cdx.json", self.cfg)
        self.assertEqual(doc["specVersion"], "1.6")
        result = validate(doc)
        self.assertEqual(result["summary"]["conformance_pct"], 100.0, json.dumps(result["summary"]))
        self.assertEqual(len(result["items"][0]["fields"]), 21)
        self.assertEqual(len(SBOM_FIELDS), 21)

    def test_derivations(self):
        doc, _ = build_sbom(FIX / "sample.cdx.json", self.cfg, TPL / "overrides.json")
        comps = {c["name"]: c for c in doc["components"]}
        log4j = _props(comps["log4j-core"])
        self.assertEqual(comps["log4j-core"]["supplier"]["name"], "org.apache.logging.log4j")
        self.assertEqual(log4j["criticality"], "critical")              # override
        self.assertEqual(log4j["origin"], "open-source")
        self.assertIn("vulnerable", log4j["patch_status"])              # offline: fix data unknown
        self.assertEqual(comps["log4j-core"]["licenses"][0]["license"]["id"], "Apache-2.0")
        internal = comps["internal-auth-lib"]
        self.assertTrue(internal["purl"].startswith("pkg:generic/"))    # Unique Identifier generated
        self.assertEqual(_props(internal)["origin"], "proprietary (first-party)")
        self.assertIn("copyleft", _props(comps["readline-wrapper"])["usage_restrictions"])

    def test_cpe_override_closes_coverage_gap(self):
        with tempfile.TemporaryDirectory() as d:
            ov = Path(d) / "ov.json"
            ov.write_text(json.dumps({"components": {"internal-auth-lib": {
                "cpe": "cpe:2.3:a:example:internal-auth-lib:1.3.0:*:*:*:*:*:*:*"}}}))
            doc, bom = build_sbom(FIX / "sample.cdx.json", self.cfg, ov)
        c = next(x for x in bom.components if x.name == "internal-auth-lib")
        self.assertEqual(c.cpe, "cpe:2.3:a:example:internal-auth-lib:1.3.0:*:*:*:*:*:*:*")
        self.assertIsNone(c.vulnerability_scan_gap)  # identifiable now, so not reported as a gap

    def test_criticality_heuristic(self):
        doc, _ = build_sbom(FIX / "sample.cdx.json", self.cfg)
        crit = {c["name"]: _props(c)["criticality"] for c in doc["components"]}
        self.assertEqual(crit["Django"], "high")          # direct
        self.assertEqual(crit["readline-wrapper"], "medium")  # transitive
        self.assertEqual(crit["requests"], "low")         # optional scope

    def test_idempotent(self):
        doc, _ = build_sbom(FIX / "sample.cdx.json", self.cfg)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "once.json"
            p.write_text(json.dumps(doc))
            doc2, _ = build_sbom(p, self.cfg)
        strip = lambda x: sorted((c["name"], json.dumps(c.get("properties"), sort_keys=True)) for c in x["components"])  # noqa: E731
        self.assertEqual(strip(doc), strip(doc2))
        tools = [(t["name"], t.get("version")) for t in doc2["metadata"]["tools"]["components"]]
        self.assertEqual(len(tools), len(set(tools)))  # no duplicate tool entries on re-processing

    def test_spdx_input(self):
        bom = load_bom(FIX / "sample.spdx.json")
        self.assertEqual(bom.root.name, "web-portal")
        self.assertEqual(bom.dependencies["SPDXRef-flask"], ["SPDXRef-jinja"])
        self.assertEqual(bom.components[0].release_date, "2022-08-08T00:00:00Z")
        doc, _ = build_sbom(FIX / "sample.spdx.json", self.cfg)
        self.assertEqual(validate(doc)["summary"]["conformance_pct"], 100.0)

    def test_practices_declared(self):
        doc, _ = build_sbom(FIX / "sample.cdx.json", self.cfg, practices=read_json(TPL / "practices.json"))
        check = next(c for c in validate(doc)["document_checks"] if c["id"] == "practices")
        self.assertEqual(check["status"], "pass")


LOG4J_GHSA = {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "summary": "Log4Shell",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
              "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-502", "CWE-917"]},
              "affected": [{"package": {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"},
                                                                         {"introduced": "2.13.0"}, {"fixed": "2.15.0"}]}]}]}
LODASH_GHSA = {"id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "summary": "lodash command injection",
               "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
               "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
                             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]}
MAL = {"id": "MAL-2026-0001", "summary": "Malicious code in requests (typosquat payload)",
       "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}, "versions": ["2.31.0"]}]}
WITHDRAWN = {"id": "GHSA-gone", "withdrawn": "2026-01-01T00:00:00Z", "affected": []}


def fake_http(url, payload=None, timeout=15.0):
    if url.endswith("querybatch"):
        hits = {"log4j-core": ["GHSA-jfh8-c2jp-5v3q"], "lodash": ["GHSA-35jh-r3h4-6jhm", "GHSA-gone"], "requests": ["MAL-2026-0001"]}
        return {"results": [{"vulns": [{"id": i} for i in hits.get(q["package"]["name"].split(":")[-1], [])]}
                            for q in payload["queries"]]}
    for rec in (LOG4J_GHSA, LODASH_GHSA, MAL, WITHDRAWN):
        if url.endswith("/v1/vulns/" + rec["id"]):
            return rec
    if "known_exploited" in url:
        return {"vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "dueDate": "2021-12-24",
                                     "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply updates"}]}
    if "api.first.org" in url:
        return {"data": [{"cve": "CVE-2021-44228", "epss": "0.94358", "percentile": "0.99961"},
                         {"cve": "CVE-2021-23337", "epss": "0.01200", "percentile": "0.85000"}]}
    if "pypi.org/pypi/django" in url:
        return {"info": {"summary": "Web framework", "author": "DSF", "license": "BSD-3-Clause"},
                "urls": [{"packagetype": "sdist", "upload_time_iso_8601": "2023-11-01T12:00:00Z",
                          "digests": {"sha256": "ab" * 32}, "filename": "Django-4.2.7.tar.gz"}]}
    if url.endswith("endoflife.date/api/all.json"):
        return ["django", "log4j"]
    if url.endswith("endoflife.date/api/django.json"):
        return [{"cycle": "4.2", "eol": "2026-04-30", "latest": "4.2.30", "releaseDate": "2023-04-03"}]
    return None


class OnlineTests(unittest.TestCase):
    def run_online(self, **cfg):
        with mock.patch("certin_bom.online.http_json", side_effect=fake_http), \
                mock.patch("certin_bom.vulns.http_json", side_effect=fake_http), \
                mock.patch("certin_bom.online.http_text", return_value=None):
            doc, _ = build_sbom(FIX / "sample.cdx.json", Config(author="t", online=True, **cfg))
        return doc, {c["name"]: c for c in doc["components"]}, {v["id"]: v for v in doc["vulnerabilities"]}

    def test_metadata_enrichment(self):
        _, comps, _ = self.run_online()
        self.assertEqual(comps["Django"]["description"], "Web framework")
        self.assertEqual(_props(comps["Django"])["release_date"], "2023-11-01")
        self.assertEqual(_props(comps["Django"])["eol_date"], "2026-04-30")  # found via live product list

    def test_aliases_merged_with_source_record(self):
        _, _, vulns = self.run_online()
        # source SBOM had CVE-2021-44228; OSV reported GHSA-jfh8-... with that alias -> one record
        self.assertIn("CVE-2021-44228", vulns)
        self.assertNotIn("GHSA-jfh8-c2jp-5v3q", vulns)
        self.assertIn("GHSA-jfh8-c2jp-5v3q", [r["id"] for r in vulns["CVE-2021-44228"]["references"]])
        self.assertEqual(vulns["CVE-2021-44228"]["cwes"], [502, 917])
        self.assertNotIn("GHSA-gone", vulns)  # withdrawn advisory dropped

    def test_kev_epss_priority(self):
        _, comps, vulns = self.run_online()
        log4j = _props(vulns["CVE-2021-44228"])
        self.assertTrue(log4j["priority"].startswith("P0"))
        self.assertIn("ransomware", log4j["priority"])
        self.assertEqual(log4j["epss"], "0.94358")
        self.assertTrue(_props(comps["log4j-core"])["patch_status"].startswith("URGENT"))
        self.assertIn("1 in CISA KEV", _props(comps["log4j-core"])["vulnerability_summary"])

    def test_cvss_scored_from_vector(self):
        _, _, vulns = self.run_online()
        self.assertEqual(vulns["CVE-2021-23337"]["ratings"][0]["score"], 7.2)

    def test_malicious_package_flagged(self):
        doc, comps, vulns = self.run_online()
        self.assertEqual(vulns["MAL-2026-0001"]["ratings"][0]["severity"], "critical")
        self.assertIn("MALICIOUS", _props(comps["requests"])["vulnerability_summary"])
        check = next(c for c in validate(doc)["document_checks"] if c["id"] == "malicious-packages")
        self.assertEqual(check["status"], "warn")  # security finding, not a CERT-In field gap

    def test_coverage_gaps_reported(self):
        doc, comps, _ = self.run_online()
        self.assertIn("no ecosystem purl", _props(comps["internal-auth-lib"])["vulnerability_scan_gap"])
        vs = validate(doc)["vulnerabilities"]
        self.assertLess(vs["coverage_pct"], 100)
        self.assertIn("internal-auth-lib", [g["name"] for g in vs["coverage_gaps"]])


class VulnSourceTests(unittest.TestCase):
    def test_cvss31(self):
        from certin_bom.cvss import base_score
        self.assertEqual(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8)
        self.assertEqual(base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"), 3.1)
        self.assertEqual(base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)
        self.assertIsNone(base_score("CVSS:4.0/AV:N"))

    def test_os_package_targets(self):
        from certin_bom.model import Component
        from certin_bom.vulns import osv_target
        deb = osv_target(Component(ref="x", name="libc6",
                                   purl="pkg:deb/debian/libc6@2.31-13%2Bdeb11u5?arch=amd64&upstream=glibc&distro=debian-11"))
        self.assertEqual(deb["query"], {"package": {"name": "glibc", "ecosystem": "Debian:11"}, "version": "2.31-13+deb11u5"})
        ub = osv_target(Component(ref="y", name="openssl", purl="pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?distro=ubuntu-22.04"))
        self.assertEqual(ub["ecosystem"], "Ubuntu:22.04:LTS")
        apk = osv_target(Component(ref="z", name="busybox", purl="pkg:apk/alpine/busybox@1.36.1-r2?distro=alpine-3.18.4"))
        self.assertEqual(apk["ecosystem"], "Alpine:v3.18")
        mvn = osv_target(Component(ref="m", name="log4j-core", purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar"))
        self.assertEqual(mvn["query"]["package"], {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven"})
        self.assertIsNone(osv_target(Component(ref="g", name="openssl", purl="pkg:generic/openssl@3.0.1")))

    def test_offline_db(self):
        import gzip
        from certin_bom.vulns import _slim
        with tempfile.TemporaryDirectory() as d:
            idx = {"org.apache.logging.log4j:log4j-core": [_slim(LOG4J_GHSA)], "lodash": [_slim(LODASH_GHSA)]}
            (Path(d) / "osv-Maven.json.gz").write_bytes(gzip.compress(json.dumps({k: v for k, v in idx.items() if ":" in k}).encode()))
            (Path(d) / "osv-npm.json.gz").write_bytes(gzip.compress(json.dumps({"lodash": idx["lodash"]}).encode()))
            (Path(d) / "kev.json").write_text(json.dumps(fake_http("known_exploited")))
            (Path(d) / "epss.json.gz").write_bytes(gzip.compress(json.dumps({"CVE-2021-44228": [0.9, 0.99]}).encode()))
            (Path(d) / "metadata.json").write_text(json.dumps({"built": "2026-11-17"}))
            with mock.patch("certin_bom.vulns.http_json", side_effect=AssertionError("network used offline")):
                doc, _ = build_sbom(FIX / "sample.cdx.json", Config(author="t", osv_db=d))
        vulns = {v["id"]: v for v in doc["vulnerabilities"]}
        self.assertTrue(_props(vulns["CVE-2021-44228"])["priority"].startswith("P0"))
        self.assertIn("lodash", [a["ref"] for a in vulns["CVE-2021-23337"]["affects"]])
        comps = {c["name"]: _props(c) for c in doc["components"]}
        self.assertIn("osv-offline(2026-11-17)", comps["lodash"]["vulnerability_scan"])
        self.assertIn("upgrade to 4.17.21", comps["lodash"]["patch_status"])

    def test_nvd_false_positive_filter(self):
        from certin_bom.vulns import _nvd_version_matches
        cve = {"configurations": [{"nodes": [
            {"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"}]},
            {"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                           "versionStartIncluding": "3.0.0", "versionEndExcluding": "3.0.7"}]}]}]}
        self.assertTrue(_nvd_version_matches(cve, "openssl", "3.0.1"))
        self.assertFalse(_nvd_version_matches(cve, "openssl", "3.0.7"))
        only_111 = {"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"}]}]}]}
        self.assertFalse(_nvd_version_matches(only_111, "openssl", "3.0.1"))   # e.g. CVE-2019-0190
        platform_only = {"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": False, "criteria": "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"}]}]}]}
        self.assertFalse(_nvd_version_matches(platform_only, "openssl", "3.0.1"))

    def test_bundled_advisory_does_not_merge_distinct_cves(self):
        from certin_bom.model import Bom, Vulnerability
        from certin_bom.vulns import merge_duplicates
        bom = Bom(vulnerabilities=[
            Vulnerability(id="DEBIAN-CVE-2023-4911", aliases=["CVE-2023-4911"], affects=["glibc"]),
            Vulnerability(id="DEBIAN-CVE-2023-4806", aliases=["CVE-2023-4806"], affects=["glibc"]),
            Vulnerability(id="DSA-5514-1", aliases=["CVE-2023-4911", "CVE-2023-4806"], affects=["glibc"],
                          fixed_versions={"glibc": ["2.31-13+deb11u7"]}),
            Vulnerability(id="DSA-9999-1", aliases=["CVE-2023-4911", "CVE-2099-0001"], affects=["glibc"]),
        ])
        merge_duplicates(bom)
        ids = sorted(v.id for v in bom.vulnerabilities)
        # the two CVEs stay separate; DSA-5514-1 is folded in (all CVEs tracked); DSA-9999-1 is kept (one CVE untracked)
        self.assertEqual(ids, ["CVE-2023-4806", "CVE-2023-4911", "DSA-9999-1"])
        cve = next(v for v in bom.vulnerabilities if v.id == "CVE-2023-4911")
        self.assertIn("DSA-5514-1", cve.aliases)
        self.assertEqual(cve.fixed_versions["glibc"], ["2.31-13+deb11u7"])

    def test_distro_upstream_cve_used_as_alias(self):
        from certin_bom.vulns import osv_to_vuln
        v = osv_to_vuln({"id": "DEBIAN-CVE-2023-4911", "upstream": ["CVE-2023-4911"]})
        self.assertEqual(v.aliases, ["CVE-2023-4911"])

    def test_range_evaluation(self):
        from certin_bom.vulns import _in_range
        aff = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.5"},
                                                           {"introduced": "2.0"}, {"last_affected": "2.3"}]}]}
        self.assertTrue(_in_range("1.2", aff))
        self.assertFalse(_in_range("1.5", aff))
        self.assertFalse(_in_range("1.9", aff))
        self.assertTrue(_in_range("2.3", aff))
        self.assertFalse(_in_range("2.4", aff))
        self.assertTrue(_in_range("0.9", {"versions": ["0.9"]}))

    def test_nvd_cpe_lookup(self):
        from certin_bom.model import Bom, Component
        from certin_bom.vulns import nvd_scan
        cve = {"id": "CVE-2022-3602", "vulnStatus": "Analyzed",
               "descriptions": [{"lang": "en", "value": "X.509 email address buffer overflow"}],
               "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                   "baseScore": 7.5, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]},
               "weaknesses": [{"description": [{"value": "CWE-120"}]}],
               "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                                                            "versionStartIncluding": "3.0.0", "versionEndExcluding": "3.0.7"}]}]}]}

        def fake(url, payload=None, timeout=15.0):
            if "cpes/2.0" in url:
                return {"products": [{"cpe": {"cpeName": "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*"}}]}
            if "cves/2.0" in url:
                return {"totalResults": 1, "vulnerabilities": [{"cve": cve}]}
            return None

        bom = Bom(components=[Component(ref="ossl", name="openssl", version="3.0.1", purl="pkg:generic/openssl@3.0.1")])
        with mock.patch("certin_bom.vulns.http_json", side_effect=fake), mock.patch("certin_bom.vulns.time.sleep"):
            self.assertEqual(nvd_scan(bom, None, 5), 1)
        c = bom.components[0]
        self.assertEqual(c.cpe, "cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*")
        self.assertTrue(c.vulnerability_scan.startswith("nvd:"))
        v = bom.vulnerabilities[0]
        self.assertEqual((v.score, v.cwes, v.fixed_versions["ossl"]), (7.5, [120], ["3.0.7"]))


class CryptoTests(unittest.TestCase):
    def _tree(self, d):
        (Path(d) / "app.py").write_text(
            "import hashlib\nh = hashlib.md5(x)\nc = AES.new(k, AES.MODE_GCM)\n"
            "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\nalg = 'ML-KEM-768'\n")
        (Path(d) / "node_modules").mkdir()
        (Path(d) / "node_modules" / "skip.js").write_text("md5('x')")

    def test_source_scan(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d)
            doc = build_cbom([d], [])
        names = {c["name"]: c for c in doc["components"]}
        self.assertTrue({"MD5", "AES-GCM", "RSA-2048", "ML-KEM-768"} <= set(names))
        self.assertNotIn("RSA", names)  # generic suppressed by specific match
        self.assertEqual(names["MD5"]["evidence"]["occurrences"], [{"location": "app.py", "line": 2}])
        self.assertEqual(names["RSA-2048"]["cryptoProperties"]["oid"], "1.2.840.113549.1.1.1")
        self.assertEqual(validate(doc)["summary"]["missing"], 0)

    def test_suite_parsing(self):
        self.assertEqual(_suite_algorithms("TLS_AES_256_GCM_SHA384"), ["AES-256-GCM", "SHA-384"])
        self.assertEqual(_suite_algorithms("ECDHE-RSA-AES128-GCM-SHA256"), ["ECDH", "RSA", "AES-128-GCM", "SHA-256"])

    @unittest.skipUnless(__import__("importlib").util.find_spec("cryptography"), "cryptography not installed")
    def test_certificate(self):
        import datetime as dt
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.in")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=365))
                .sign(key, hashes.SHA256()))
        b = CbomBuilder()
        ref = b.certificate(cert, "server.crt", ".crt")
        doc = b.document()
        props = b.components[ref]["cryptoProperties"]["certificateProperties"]
        self.assertEqual(props["signatureAlgorithmRef"], "crypto/algorithm/SHA256withRSA")
        key_comp = b.components[props["subjectPublicKeyRef"]]
        self.assertEqual(key_comp["cryptoProperties"]["relatedCryptoMaterialProperties"]["size"], 2048)
        self.assertEqual(validate(doc)["summary"]["missing"], 0)

    def test_qbom(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d)
            cbom = build_cbom([d], [])
        q = build_qbom(cbom, read_json(TPL / "qbom.json"))
        comps = {c["name"]: _props(c) for c in q["components"] if c["type"] == "cryptographic-asset"}
        self.assertTrue(comps["MD5"]["migration_priority"].startswith("P0"))
        self.assertTrue(comps["RSA-2048"]["migration_priority"].startswith("P1"))
        self.assertEqual(comps["ML-KEM-768"]["quantum_risk"], "resistant")
        r = validate(q)
        self.assertEqual(r["bom_type"], "QBOM")
        missing = [k for k, f in r["items"][0]["fields"].items() if f["status"] == "missing"]
        self.assertEqual(missing, ["attestations"])  # satisfied by `sign`


class AiHwTests(unittest.TestCase):
    def test_aibom_template_complete(self):
        doc = build_aibom(read_json(TPL / "aibom.json"))
        model = doc["metadata"]["component"]
        self.assertEqual(model["type"], "machine-learning-model")
        self.assertEqual(model["modelCard"]["modelParameters"]["task"], "image-classification")
        r = validate(doc)
        self.assertEqual(len(r["items"][0]["fields"]), len(AIBOM_FIELDS))
        missing = [k for k, f in r["items"][0]["fields"].items() if f["status"] == "missing"]
        self.assertEqual(missing, ["attestations"])

    def test_aibom_detects_missing(self):
        r = validate(build_aibom({"model": {"name": "m"}}))
        unknown = [k for k, f in r["items"][0]["fields"].items() if f["status"] == "unknown"]
        self.assertIn("performance_metrics", unknown)
        self.assertIn("out_of_scope_usage", unknown)

    def test_hbom_recursive(self):
        doc = build_hbom(read_json(TPL / "hbom.json"))
        r = validate(doc)
        self.assertEqual(r["bom_type"], "HBOM")
        self.assertEqual(len(r["items"]), 4)  # product + 3 components (one nested)
        self.assertEqual(len(r["items"][0]["fields"]), len(HBOM_PRODUCT_FIELDS))
        self.assertEqual(r["summary"]["missing"], 0)
        psu = next(i for i in r["items"] if i["name"] == "Power module")
        self.assertEqual(psu["fields"]["technology_node"]["status"], "n/a")
        self.assertEqual(psu["fields"]["sub_component"]["status"], "present")


class VexSplitSignTests(unittest.TestCase):
    def setUp(self):
        self.sbom, _ = build_sbom(FIX / "sample.cdx.json", Config(author="t"))
        self.triage = read_json(TPL / "triage.json")

    def test_vex_statuses(self):
        vex = cyclonedx_vex(self.sbom, self.triage)
        status = {v["id"]: _props(v)["vex_status"] for v in vex["vulnerabilities"]}
        self.assertEqual(status, {"CVE-2021-44228": "Fixed", "CVE-2021-23337": "Under Investigation"})
        self.assertTrue(vex["vulnerabilities"][0]["affects"][0]["ref"].startswith(self.sbom["serialNumber"]))
        csaf = csaf_vex(self.sbom, self.triage, "Example Org", "https://example.in")
        self.assertEqual(csaf["document"]["category"], "csaf_vex")
        buckets = [list(v["product_status"])[0] for v in csaf["vulnerabilities"]]
        self.assertEqual(sorted(buckets), ["fixed", "under_investigation"])

    def test_split(self):
        pub, priv = split(self.sbom, Config().private_properties)
        self.assertNotIn("vulnerabilities", pub)
        self.assertIn("vulnerabilities", priv)
        leaked = [p["name"] for c in pub["components"] for p in c.get("properties", [])
                  if "vulnerab" in p["name"] or "patch_status" in p["name"]]
        self.assertEqual(leaked, [])

    def test_timestamps_rfc3339(self):
        from certin_bom.util import iso_datetime
        self.assertEqual(iso_datetime("2022-03-15T17:15:08.513"), "2022-03-15T17:15:08.513Z")
        self.assertEqual(iso_datetime("2022-03-15"), "2022-03-15T00:00:00Z")
        self.assertEqual(iso_datetime("2022-03-15T17:15:08+05:30"), "2022-03-15T17:15:08+05:30")

    @unittest.skipUnless(__import__("importlib").util.find_spec("cryptography"), "cryptography not installed")
    def test_sign_verify_tamper(self):
        from certin_bom.sign import keygen, sign, verify
        with tempfile.TemporaryDirectory() as d:
            priv, pub = keygen(d)
            signed = sign(self.sbom, priv.read_bytes())
            self.assertEqual(verify(signed, pub.read_bytes())[0], True)
            tampered = copy.deepcopy(signed)
            tampered["components"][0]["version"] = "9.9.9"
            self.assertFalse(verify(tampered, pub.read_bytes())[0])
            with self.assertRaises(FileExistsError):
                keygen(d)
        self.assertEqual(next(c for c in validate(signed)["document_checks"] if c["id"] == "signature")["status"], "pass")


if __name__ == "__main__":
    unittest.main()

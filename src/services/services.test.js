import cacheService from "./cacheService";
import PackageRegistryService from "./packageRegistryService";
import PropertyMapperService from "./propertyMapperService";
import VulnerabilityService, { KEV_URL, resetKevCacheForTests } from "./vulnerabilityService";
import { ensureBomRefs, mergeVulnerabilities } from "../utils/sbomVulnerabilities";

const json = (body, ok = true) => Promise.resolve({ ok, status: ok ? 200 : 404, json: () => Promise.resolve(body) });

const LOG4SHELL_GHSA = {
  id: "GHSA-jfh8-c2jp-5v3q", aliases: ["CVE-2021-44228"], summary: "Log4Shell",
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }],
  database_specific: { severity: "CRITICAL", cwe_ids: ["CWE-502"] },
  affected: [{ package: { name: "org.apache.logging.log4j:log4j-core", ecosystem: "Maven" },
    ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.13.0" }, { fixed: "2.15.0" }, { introduced: "2.0" }, { fixed: "2.12.2" }] }] }],
};
const LOG4SHELL_DUP = { ...LOG4SHELL_GHSA, id: "OSV-DUP-44228", database_specific: {} }; // same CVE, other database
const WITHDRAWN = { id: "GHSA-gone", withdrawn: "2026-01-01T00:00:00Z", affected: [] };
const KEV = { vulnerabilities: [{ cveID: "CVE-2021-44228", dateAdded: "2021-12-10", dueDate: "2021-12-24", knownRansomwareCampaignUse: "Known" }] };

let calls;
function mockFetch(routes) {
  calls = [];
  global.fetch = jest.fn((url, opts) => {
    calls.push({ url, body: opts?.body ? JSON.parse(opts.body) : null });
    for (const [match, handler] of routes) if (url.includes(match)) return handler(url, opts);
    return json({}, false);
  });
}

beforeEach(() => {
  cacheService.forceClear();
  resetKevCacheForTests();
});

describe("VulnerabilityService", () => {
  test("queries OSV with the exact version, merges duplicates, drops withdrawn, adds KEV + EPSS", async () => {
    mockFetch([
      ["api.osv.dev/v1/query", () => json({ vulns: [LOG4SHELL_GHSA, LOG4SHELL_DUP, WITHDRAWN] })],
      [KEV_URL, () => json(KEV)],
      ["api.first.org", () => json({ data: [{ cve: "CVE-2021-44228", epss: "0.94358", percentile: "0.99961" }] })],
    ]);
    const svc = new VulnerabilityService();
    const data = await svc.fetchVulnerabilityData({ ecosystem: "maven", group: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1" });
    const osv = calls.find((c) => c.url.includes("osv"));
    expect(osv.body).toEqual({ package: { name: "org.apache.logging.log4j:log4j-core", ecosystem: "Maven" }, version: "2.14.1" });
    expect(data.scanned).toBe(true);
    expect(data.totalVulns).toBe(1); // GHSA + duplicate merged, withdrawn dropped
    const v = data.vulns[0];
    expect(v.id).toBe("CVE-2021-44228");
    expect(v.aliases).toEqual(expect.arrayContaining(["GHSA-jfh8-c2jp-5v3q", "OSV-DUP-44228"]));
    expect(v.score).toBe(10);
    expect(v.kev.ransomware).toBe("Known");
    expect(v.epss).toBeCloseTo(0.94358);
    expect(v.priority).toMatch(/^P0/);
    expect(data.bestFix).toBe("2.15.0"); // 2.12.2 is below 2.14.1
  });

  test("follows OSV pagination", async () => {
    let page = 0;
    mockFetch([
      ["api.osv.dev/v1/query", () => (page++ === 0
        ? json({ vulns: [LOG4SHELL_GHSA], next_page_token: "t1" })
        : json({ vulns: [{ ...LOG4SHELL_GHSA, id: "GHSA-other", aliases: ["CVE-2021-45046"] }] }))],
      [KEV_URL, () => json({ vulnerabilities: [] })],
      ["api.first.org", () => json({ data: [] })],
    ]);
    const data = await new VulnerabilityService().fetchVulnerabilityData({ ecosystem: "maven", group: "org.apache.logging.log4j", name: "log4j-core", version: "2.14.1" });
    expect(data.totalVulns).toBe(2);
    expect(calls.filter((c) => c.url.includes("osv"))[1].body.page_token).toBe("t1");
  });

  test("OS packages are queried by distro release and source package", () => {
    const svc = new VulnerabilityService();
    const reg = new PackageRegistryService();
    const t = (purl) => svc.osvTarget(reg.extractPackageInfo({ purl }));
    expect(t("pkg:deb/debian/libc6@2.31-13%2Bdeb11u5?arch=amd64&upstream=glibc&distro=debian-11"))
      .toEqual({ ecosystem: "Debian:11", name: "glibc", version: "2.31-13+deb11u5" });
    expect(t("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?distro=ubuntu-22.04").ecosystem).toBe("Ubuntu:22.04:LTS");
    expect(t("pkg:apk/alpine/busybox@1.36.1-r2?distro=alpine-3.18.4").ecosystem).toBe("Alpine:v3.18");
    expect(t("pkg:npm/%40angular/core@17.0.1")).toEqual({ ecosystem: "npm", name: "@angular/core", version: "17.0.1" });
    expect(t("pkg:generic/openssl@3.0.1")).toBeNull();
  });

  test("unidentifiable components are reported as not scanned, not as clean", async () => {
    mockFetch([]);
    const data = await new VulnerabilityService().fetchVulnerabilityData({ ecosystem: "unknown", name: "internal-lib", version: "1.0" });
    expect(data.scanned).toBe(false);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  test("network failure is not reported as up to date", async () => {
    global.fetch = jest.fn(() => Promise.reject(new Error("offline")));
    const data = await new VulnerabilityService().fetchVulnerabilityData({ ecosystem: "npm", name: "lodash", version: "4.17.20" });
    expect(data.scanned).toBe(false);
    expect(data.reason).toMatch(/offline/);
  });
});

describe("PackageRegistryService", () => {
  test("npm release date is the component version's date, not package creation", async () => {
    mockFetch([["registry.npmjs.org", () => json({
      time: { created: "2012-04-23T00:00:00Z", "4.17.20": "2020-08-13T16:53:54Z" },
      "dist-tags": { latest: "4.17.21" },
      versions: { "4.17.20": { description: "Lodash modular utilities.", license: "MIT", author: { name: "John-David Dalton" } } },
    })]]);
    const reg = new PackageRegistryService();
    const data = await reg.fetchPackageData(reg.extractPackageInfo({ purl: "pkg:npm/lodash@4.17.20" }));
    expect(data.releaseDate).toBe("13-08-2020");
    expect(data.author).toBe("John-David Dalton");
    expect(data.license).toBe("MIT");
  });

  test("PyPI release date comes from the version's files", async () => {
    mockFetch([["pypi.org", () => json({
      info: { version: "5.1", summary: "Web framework", license: "BSD-3-Clause", author: "DSF" },
      releases: { "4.2.7": [{ packagetype: "sdist", upload_time_iso_8601: "2023-11-01T12:00:00Z" }] },
    })]]);
    const reg = new PackageRegistryService();
    const data = await reg.fetchPackageData(reg.extractPackageInfo({ purl: "pkg:pypi/django@4.2.7" }));
    expect(data.releaseDate).toBe("01-11-2023");
    expect(data.latestVersion).toBe("5.1");
  });
});

describe("LifecycleService", () => {
  const LifecycleService = require("./lifecycleService").default;
  test("matches aliased products and longest cycle; skips distro packages", async () => {
    mockFetch([
      ["all.json", () => json(["log4j", "django", "openssl"])],
      ["api/log4j.json", () => json([{ cycle: "2", eol: false }, { cycle: "1", eol: "2015-08-05" }])],
      ["api/django.json", () => json([{ cycle: "4", eol: "2099-01-01" }, { cycle: "4.2", eol: "2026-04-07" }])],
      ["api/openssl.json", () => json([{ cycle: "3.0", eol: "2026-09-07" }])],
      ["eol-overrides.json", () => json({}, false)],
    ]);
    const svc = new LifecycleService();
    const reg = new PackageRegistryService();
    const eol = (c) => svc.fetchEol(c, reg.extractPackageInfo(c));
    expect(await eol({ name: "log4j-core", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" })).toBe("Not announced");
    expect(await eol({ name: "Django", purl: "pkg:pypi/django@4.2.7" })).toBe("07-04-2026");
    expect(await eol({ name: "openssl", version: "3.0.1", purl: "pkg:generic/openssl@3.0.1" })).toBe("07-09-2026");
    expect(await eol({ name: "openssl", purl: "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?distro=ubuntu-22.04" })).toBeNull();
  });
});

describe("PropertyMapperService", () => {
  const mapper = new PropertyMapperService();
  const vulnData = (over = {}) => ({ scanned: true, hasVulnerabilities: false, totalVulns: 0, vulns: [], fixedVersions: [], ...over });

  test("Unique Identifier stays a valid purl (no pkg:supplier/ prefix)", () => {
    const c = { name: "log4j-core", version: "2.14.1", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar" };
    const props = mapper.buildProperties(c, mapper.pkg.extractPackageInfo(c), null, vulnData(), null, null, []);
    expect(props["Unique Identifier"]).toBe(c.purl);
    const noPurl = { name: "internal-auth", version: "1.3.0", supplier: { name: "Example Org" } };
    expect(mapper.buildProperties(noPurl, mapper.pkg.extractPackageInfo(noPurl), null, vulnData(), null, null, [])["Unique Identifier"])
      .toBe("pkg:generic/Example-Org/internal-auth@1.3.0");
  });

  test("supplier is the entity, executable/archive follow the component", () => {
    const c = { type: "library", name: "log4j-core", version: "2.14.1", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" };
    const p = mapper.buildProperties(c, mapper.pkg.extractPackageInfo(c), { license: "Apache-2.0" }, vulnData(), null, null, []);
    expect(p["Component Supplier"]).toBe("org.apache.logging.log4j");
    expect(p["Executable Property"]).toBe("No");
    expect(p["Archive Property"]).toBe("Yes");
    expect(p["Structured Property"]).toBe("Yes");
    expect(p["Component Origin"]).toBe("Open-source");
    const app = { type: "application", name: "nginx", version: "1.18.0" };
    expect(mapper.buildProperties(app, mapper.pkg.extractPackageInfo(app), null, vulnData(), null, null, [])["Executable Property"]).toBe("Yes");
  });

  test("patch status uses the best fix and flags KEV", () => {
    const info = { ecosystem: "maven", version: "2.14.1" };
    expect(mapper.computePatchStatus(vulnData({ hasVulnerabilities: true, totalVulns: 2, bestFix: "2.17.1", kevCount: 1 }), info, null))
      .toBe("URGENT - actively exploited (CISA KEV); Update available (>= 2.17.1)");
    expect(mapper.computePatchStatus(vulnData({ hasVulnerabilities: true, totalVulns: 3, bestFix: null }), info, null))
      .toBe("No fix available (3 known vulnerabilities)");
    expect(mapper.computePatchStatus(vulnData(), info, { latestVersion: "2.14.1" })).toBe("Up to date");
    expect(mapper.computePatchStatus({ scanned: false }, info, null)).toBe("NA"); // not "Up to date"
  });

  test("criticality: KEV is critical, otherwise highest of SBOM rating and OSV severity", () => {
    const c = { "bom-ref": "x" };
    expect(mapper.determineCriticality(vulnData({ kevCount: 1 }), [], c)).toBe("Critical");
    const sbomVulns = [{ affects: [{ ref: "x" }], ratings: [{ severity: "medium" }] }];
    expect(mapper.determineCriticality(vulnData({ totalVulns: 1, maxSeverity: "high" }), sbomVulns, c)).toBe("High");
    expect(mapper.determineCriticality({ scanned: false }, [], c)).toBe("NA");
  });
});

describe("SBOM vulnerabilities[]", () => {
  test("found vulnerabilities are added once and linked to components; existing ones are kept", () => {
    const comps = ensureBomRefs([{ name: "log4j-core", version: "2.14.1", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" },
      { name: "log4j-api", version: "2.14.1" }]);
    expect(comps[1]["bom-ref"]).toBe("log4j-api@2.14.1");
    const rec = { id: "CVE-2021-44228", aliases: ["GHSA-jfh8-c2jp-5v3q"], severity: "critical", score: 10, method: "CVSSv31",
      vector: "CVSS:3.1/AV:N", fixed: ["2.12.2", "2.15.0"], priority: "P0 - known exploited (CISA KEV)",
      kev: { dateAdded: "2021-12-10", ransomware: "Known" }, epss: 0.94, published: "2021-12-10T00:00:00" };
    const existing = [{ id: "GHSA-jfh8-c2jp-5v3q", affects: [{ ref: "something-else" }] }];
    const out = mergeVulnerabilities(existing, comps, [{ _vulnerabilities: [rec] }, { _vulnerabilities: [rec] }]);
    expect(out).toHaveLength(1); // matched the existing GHSA record via alias
    expect(out[0].affects.map((a) => a.ref)).toEqual(["something-else", comps[0]["bom-ref"], "log4j-api@2.14.1"]);
    const fresh = mergeVulnerabilities([], comps.slice(0, 1), [{ _vulnerabilities: [rec] }])[0];
    expect(fresh.recommendation).toBe("log4j-core 2.14.1: upgrade to 2.15.0");
    expect(fresh.published).toBe("2021-12-10T00:00:00Z");
    expect(fresh.ratings[0]).toEqual({ score: 10, severity: "critical", method: "CVSSv31", vector: "CVSS:3.1/AV:N" });
    expect(fresh.properties.find((p) => p.name === "cert-in:priority").value).toMatch(/^P0/);
  });
});

describe("cacheService checksums", () => {
  test("different SBOMs of the same size no longer share a cached result", () => {
    const a = { components: [{ name: "log4j-core", version: "2.14.1" }, { name: "django", version: "4.2.7" }] };
    const b = { components: [{ name: "left-pad", version: "1.3.0" }, { name: "express", version: "4.18.2" }] };
    expect(cacheService.generateFileChecksum(a)).not.toBe(cacheService.generateFileChecksum(b));
    const ref = (refs) => ({ name: "x", version: "1", externalReferences: refs });
    expect(cacheService.generateComponentChecksum(ref([{ type: "vcs", url: "https://a" }])))
      .not.toBe(cacheService.generateComponentChecksum(ref([{ type: "vcs", url: "https://b" }])));
  });
});

describe("Maven via deps.dev (Maven Central blocks browser requests)", () => {
  const { latestStable } = require("./packageRegistryService");
  test("latest stable skips pre-releases", () => {
    expect(latestStable(["2.14.1", "2.25.4", "3.0.0-beta3", "3.0.0-rc1", "2.25.3"])).toBe("2.25.4");
    expect(latestStable(["5.3.0", "6.0.0-M5", "6.0.0.M1"])).toBe("5.3.0");
  });
  test("latest version, release date and licence come from deps.dev", async () => {
    mockFetch([
      ["/packages/org.apache.logging.log4j%3Alog4j-core/versions/", () => json({ publishedAt: "2021-03-07T01:02:03Z", licenses: ["Apache-2.0"] })],
      ["/packages/org.apache.logging.log4j%3Alog4j-core", () => json({ versions: [{ versionKey: { version: "2.14.1" } },
        { versionKey: { version: "2.25.4" } }, { versionKey: { version: "3.0.0-beta3" }, isDefault: true }] })],
    ]);
    const reg = new PackageRegistryService();
    const data = await reg.fetchPackageData(reg.extractPackageInfo({ purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }));
    expect(data).toMatchObject({ latestVersion: "2.25.4", releaseDate: "07-03-2021", license: "Apache-2.0" });
    expect(calls.some((c) => c.url.includes("search.maven.org"))).toBe(false);
  });
});

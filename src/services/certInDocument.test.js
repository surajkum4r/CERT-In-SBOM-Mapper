import {
  AUTHOR_PROPERTY, applyComponentFields, csafVex, cyclonedxVex, prepareForExport, sbomAuthor, setVulnerabilityAnalysis,
  statusOf, toPublic,
} from "./certInDocumentService";
import { toCycloneDxLicenses, toSpdxId } from "../utils/license";
import cacheService from "./cacheService";
import PackageRegistryService from "./packageRegistryService";

const json = (body) => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
const prop = (c, name) => (c.properties || []).find((p) => p.name === name)?.value;

const SBOM = {
  bomFormat: "CycloneDX", specVersion: "1.5", serialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79", version: 1,
  metadata: { timestamp: "2026-11-10T09:30:00Z", authors: [{ name: "Example Org PSIRT" }],
    component: { "bom-ref": "app", name: "payments-service", version: "4.1.0" } },
  components: [
    { "bom-ref": "log4j", name: "log4j-core", version: "2.14.1", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      properties: [{ name: "Patch Status", value: "Update available (>= 2.17.1)" }, { name: "Comments or Notes", value: "1 known vulnerability" },
        { name: AUTHOR_PROPERTY, value: "NA" }, { name: "Criticality", value: "Critical" }] },
    { "bom-ref": "lodash", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20", properties: [] },
  ],
  vulnerabilities: [
    { "bom-ref": "v1", id: "CVE-2021-44228", source: { name: "NVD" },
      ratings: [{ score: 10, severity: "critical", method: "CVSSv31", vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }],
      description: "Log4Shell", recommendation: "log4j-core 2.14.1: upgrade to 2.15.0", affects: [{ ref: "log4j" }] },
    { "bom-ref": "v2", id: "GHSA-35jh-r3h4-6jhm", references: [{ id: "CVE-2021-23337" }], cwes: [77],
      ratings: [{ severity: "high" }], affects: [{ ref: "lodash" }] },
  ],
};

describe("licences", () => {
  test("only real SPDX ids go into license.id (the CycloneDX schema rejects others)", () => {
    expect(toSpdxId("Apache License, Version 2.0")).toBe("Apache-2.0");
    expect(toCycloneDxLicenses("MIT")).toEqual([{ license: { id: "MIT" } }]);
    expect(toCycloneDxLicenses("mit license")).toEqual([{ license: { id: "MIT" } }]);
    expect(toCycloneDxLicenses("MIT OR Apache-2.0")).toEqual([{ expression: "MIT OR Apache-2.0" }]);
    expect(toCycloneDxLicenses("Some Vendor EULA")).toEqual([{ license: { name: "Some Vendor EULA" } }]);
    expect(toCycloneDxLicenses("UNKNOWN")).toBeNull();
  });
});

describe("hashes from registries", () => {
  beforeEach(() => cacheService.forceClear());
  test("npm: SHA-512 from dist.integrity and SHA-1 from dist.shasum for this version", async () => {
    global.fetch = jest.fn(() => json({
      time: { "4.17.20": "2020-08-13T16:53:54Z" }, "dist-tags": { latest: "4.17.21" },
      versions: { "4.17.20": { license: "MIT", dist: { integrity: "sha512-q83ZaFpN5x5FZlKsnfLlBUCZbe8jc2Ncfc13dTPHGRHeW2PxJIbMgUpVqx4dbZmEIOBINtHlmKiOAXEVFV0S6A==",
        shasum: "b58fd3c8b0db6ec1a6a8ac4c8f9d7a9b0e7a7f5e", tarball: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" } } },
    }));
    const reg = new PackageRegistryService();
    const data = await reg.fetchPackageData(reg.extractPackageInfo({ purl: "pkg:npm/lodash@4.17.20" }));
    expect(data.hashes[0].alg).toBe("SHA-512");
    expect(data.hashes[0].content).toMatch(/^[0-9a-f]{128}$/);
    expect(data.hashes[1]).toEqual({ alg: "SHA-1", content: "b58fd3c8b0db6ec1a6a8ac4c8f9d7a9b0e7a7f5e" });
    expect(data.hashSource).toBe("npm tarball lodash-4.17.20.tgz");
  });
});

describe("component fields", () => {
  test("description, licence and hashes are filled only where missing; author replaces NA", () => {
    const fields = { description: "Lodash", licenses: [{ license: { id: "MIT" } }],
      hashes: [{ alg: "SHA-512", content: "ab" }], hashSource: "npm tarball lodash-4.17.20.tgz" };
    const filled = applyComponentFields({ name: "lodash", properties: [{ name: AUTHOR_PROPERTY, value: "NA" }] }, fields, "Example Org");
    expect(filled.description).toBe("Lodash");
    expect(filled.licenses).toEqual([{ license: { id: "MIT" } }]);
    expect(filled.hashes).toEqual([{ alg: "SHA-512", content: "ab" }]);
    expect(prop(filled, "cert-in:hash_source")).toBe("npm tarball lodash-4.17.20.tgz");
    expect(prop(filled, AUTHOR_PROPERTY)).toBe("Example Org");
    const kept = applyComponentFields({ name: "x", description: "Original", licenses: [{ license: { id: "BSD-3-Clause" } }],
      hashes: [{ alg: "SHA-256", content: "cd" }] }, fields, null);
    expect(kept.description).toBe("Original");
    expect(kept.licenses[0].license.id).toBe("BSD-3-Clause");
    expect(kept.hashes[0].alg).toBe("SHA-256");
  });
});

describe("export document (Author, Timestamp, Practices, distribution)", () => {
  test("author and timestamp come from the document, practices are declared", () => {
    expect(sbomAuthor(SBOM)).toBe("Example Org PSIRT");
    const out = prepareForExport(SBOM, { author: "Example Org PSIRT", practices: { frequency: "Every release", depth: "" },
      now: "2026-11-20T10:00:00Z" });
    expect(out.metadata.timestamp).toBe("2026-11-20T10:00:00Z");
    expect(prop(out.metadata, "cert-in:source_timestamp")).toBe("2026-11-10T09:30:00Z");
    expect(prop(out.metadata, "cert-in:practice:frequency")).toBe("Every release");
    expect(prop(out.metadata, "cert-in:practice:depth")).toBeUndefined();
    expect(prop(out.metadata, "cert-in:distribution")).toBe("private");
    expect(out.metadata.authors).toEqual([{ name: "Example Org PSIRT" }]);
    expect(prop(out.components[0], AUTHOR_PROPERTY)).toBe("Example Org PSIRT");
    expect(prop(out.components[1], AUTHOR_PROPERTY)).toBe("Example Org PSIRT");
    expect(out.vulnerabilities).toHaveLength(2);
    expect(SBOM.metadata.timestamp).toBe("2026-11-10T09:30:00Z"); // input not mutated
  });

  test("public copy carries no vulnerability information", () => {
    const pub = prepareForExport(SBOM, { author: "X", distribution: "public" });
    expect(pub.vulnerabilities).toBeUndefined();
    expect(prop(pub.components[0], "Patch Status")).toBeUndefined();
    expect(prop(pub.components[0], "Comments or Notes")).toBeUndefined();
    expect(prop(pub.components[0], "Criticality")).toBe("Critical");
    expect(prop(pub.metadata, "cert-in:distribution")).toBe("public");
    expect(toPublic(SBOM).signature).toBeUndefined();
  });
});

describe("VEX (section 6)", () => {
  test("statuses map to CycloneDX analysis and default to Under Investigation", () => {
    expect(statusOf(SBOM.vulnerabilities[0]).label).toBe("Under Investigation");
    const v = setVulnerabilityAnalysis(SBOM.vulnerabilities, 1, { status: "not_affected", justification: "code_not_reachable",
      detail: "template() never called with user input" });
    expect(v[1].analysis).toMatchObject({ state: "not_affected", justification: "code_not_reachable" });
    expect(statusOf(v[1]).label).toBe("Not affected");
    expect(v[0]).toBe(SBOM.vulnerabilities[0]); // others untouched
    const fixed = setVulnerabilityAnalysis(v, 0, { status: "fixed", justification: "code_not_reachable" });
    expect(fixed[0].analysis.state).toBe("resolved");
    expect(fixed[0].analysis.justification).toBeUndefined(); // justification only for not_affected
  });

  test("CycloneDX VEX uses BOM-Link references to the SBOM", () => {
    const vex = cyclonedxVex(SBOM, { author: "Example Org", now: "2026-11-20T10:00:00Z" });
    expect(vex.vulnerabilities[0].affects[0].ref).toBe("urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#log4j");
    expect(vex.vulnerabilities[0].analysis.state).toBe("in_triage");
    expect(vex.vulnerabilities[0].properties[0]).toEqual({ name: "cert-in:vex_status", value: "Under Investigation" });
    expect(vex.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/);
    expect(vex.components).toBeUndefined();
  });

  test("CSAF 2.0 VEX profile with product tree and status buckets", () => {
    const vulns = setVulnerabilityAnalysis(setVulnerabilityAnalysis(SBOM.vulnerabilities, 0, { status: "affected" }), 1,
      { status: "not_affected", justification: "code_not_reachable", detail: "unused" });
    const csaf = csafVex({ ...SBOM, vulnerabilities: vulns }, { publisher: "Example Org", namespace: "https://example.in",
      now: "2026-11-20T10:00:00Z" });
    expect(csaf.document.category).toBe("csaf_vex");
    expect(csaf.document.publisher).toEqual({ category: "vendor", name: "Example Org", namespace: "https://example.in" });
    const branches = csaf.product_tree.branches[0].branches[0].branches;
    expect(branches.map((b) => b.product.name)).toEqual(["payments-service 4.1.0", "log4j-core 2.14.1", "lodash 4.17.20"]);
    const [log4shell, lodash] = csaf.vulnerabilities;
    expect(log4shell.product_status).toEqual({ known_affected: ["CSAFPID-0002"] });
    expect(log4shell.remediations[0]).toMatchObject({ category: "vendor_fix", details: "log4j-core 2.14.1: upgrade to 2.15.0" });
    expect(log4shell.scores[0].cvss_v3).toMatchObject({ version: "3.1", baseScore: 10, baseSeverity: "CRITICAL" });
    expect(lodash.cve).toBe("CVE-2021-23337");
    expect(lodash.product_status).toEqual({ known_not_affected: ["CSAFPID-0003"] });
    expect(lodash.flags[0]).toEqual({ label: "vulnerable_code_not_in_execute_path", product_ids: ["CSAFPID-0003"] });
    expect(lodash.cwe).toEqual({ id: "CWE-77", name: "CWE-77" });
  });
});

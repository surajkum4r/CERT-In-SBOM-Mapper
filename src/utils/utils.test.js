import { buildPurl, isValidPurl, parsePurl } from "./purl";
import { bestFix, sortVersions, versionLt } from "./version";
import { cvssBaseScore, severityFromScore } from "./cvss";
import { isOpenSourceLicense, usageRestrictions } from "./license";

describe("purl", () => {
  test("parses maven with qualifiers", () => {
    const p = parsePurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar");
    expect(p).toMatchObject({ type: "maven", namespace: "org.apache.logging.log4j", name: "log4j-core",
      version: "2.14.1", qualifiers: { type: "jar" } });
  });
  test("keeps npm scope (encoded and unencoded)", () => {
    expect(parsePurl("pkg:npm/%40angular/core@17.0.1")).toMatchObject({ namespace: "@angular", name: "core", version: "17.0.1" });
    expect(parsePurl("pkg:npm/@angular/core@17.0.1")).toMatchObject({ namespace: "@angular", name: "core", version: "17.0.1" });
    expect(parsePurl("pkg:npm/@angular/core")).toMatchObject({ namespace: "@angular", name: "core", version: null });
  });
  test("keeps Go module path and deb qualifiers", () => {
    expect(parsePurl("pkg:golang/github.com/gin-gonic/gin@v1.9.1")).toMatchObject({ namespace: "github.com/gin-gonic", name: "gin" });
    const deb = parsePurl("pkg:deb/debian/libc6@2.31-13%2Bdeb11u5?arch=amd64&upstream=glibc&distro=debian-11");
    expect(deb.version).toBe("2.31-13+deb11u5");
    expect(deb.qualifiers).toEqual({ arch: "amd64", upstream: "glibc", distro: "debian-11" });
  });
  test("rejects the old pkg:supplier/<purl> form only when malformed, and builds valid purls", () => {
    expect(isValidPurl("not a purl")).toBe(false);
    expect(buildPurl("npm", "core", "1.0.0", "@angular")).toBe("pkg:npm/%40angular/core@1.0.0");
    expect(buildPurl("generic", "openssl", "3.0.1", "OpenSSL-Project")).toBe("pkg:generic/OpenSSL-Project/openssl@3.0.1");
    expect(isValidPurl(buildPurl("generic", "openssl", "3.0.1"))).toBe(true);
  });
});

describe("version", () => {
  test("compares", () => {
    expect(versionLt("2.14.1", "2.15.0")).toBe(true);
    expect(versionLt("1.0.0-rc1", "1.0.0")).toBe(true);
    expect(versionLt("4.17.21", "4.17.20")).toBe(false);
    expect(sortVersions(["2.17.0", "2.15.0", "2.16.0"])).toEqual(["2.15.0", "2.16.0", "2.17.0"]);
  });
  test("bestFix stays on the release line", () => {
    expect(bestFix("4.2.7", ["4.2.10", "4.2.30", "5.0.1", "6.1.1"])).toBe("4.2.30");
    expect(bestFix("2.9.10", ["2.6.7.4", "2.9.10.3", "2.9.10.4"])).toBe("2.9.10.4");
    expect(bestFix("1.0", ["2.0", "3.0"])).toBe("2.0");
    expect(bestFix("1.0", [])).toBeNull();
  });
});

describe("cvss", () => {
  test("v3.1 base scores match the FIRST calculator", () => {
    expect(cvssBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")).toBe(10);
    expect(cvssBaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvssBaseScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")).toBe(7.8);
    expect(cvssBaseScore("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")).toBe(3.1);
    expect(cvssBaseScore("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")).toBe(7.2);
    expect(cvssBaseScore("CVSS:4.0/AV:N")).toBeNull();
    expect(severityFromScore(7.2)).toBe("high");
  });
});

describe("license", () => {
  test("usage restrictions distinguish licence families", () => {
    expect(usageRestrictions("MIT")).toMatch(/^Permissive/);
    expect(usageRestrictions("LGPL-2.1-only")).toMatch(/^Weak copyleft/);
    expect(usageRestrictions("GPL-3.0-only")).toMatch(/^Copyleft/);
    expect(usageRestrictions("AGPL-3.0-only")).toMatch(/^Strong copyleft/);
    expect(usageRestrictions("CC-BY-NC-4.0")).toMatch(/Restricted use/);
    expect(usageRestrictions(null)).toBe("NA");
    expect(usageRestrictions("Some Vendor Terms")).toMatch(/manual legal review/);
  });
  test("open-source detection", () => {
    expect(isOpenSourceLicense("Apache-2.0")).toBe(true);
    expect(isOpenSourceLicense("Proprietary")).toBe(false);
  });
});

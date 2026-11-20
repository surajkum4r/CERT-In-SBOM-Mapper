// Maps fetched data into the CERT-In properties (Technical Guidelines v2.0, Table 5).

import PackageRegistryService from "./packageRegistryService";
import VulnerabilityService from "./vulnerabilityService";
import GitHubService from "./githubService";
import LifecycleService from "./lifecycleService";
import errorService from "./errorService";
import cacheService from "./cacheService";
import { buildPurl, isValidPurl, slug } from "../utils/purl";
import { versionLt } from "../utils/version";
import { componentLicense, isOpenSourceLicense, isProprietaryLicense, toCycloneDxLicenses, usageRestrictions } from "../utils/license";

// purl types distributed as archives (jar, wheel, tgz, gem, nupkg, crate, deb, rpm, apk, ...)
const ARCHIVE_TYPES = new Set(["maven", "npm", "pypi", "gem", "nuget", "cargo", "deb", "rpm", "apk", "composer", "hex",
  "pub", "conda", "cocoapods", "golang", "swift", "hackage", "cran", "alpm", "oci", "docker"]);
const EXECUTABLE_COMPONENT_TYPES = new Set(["application", "operating-system", "container", "firmware", "device"]);
const NON_EXECUTABLE_COMPONENT_TYPES = new Set(["library", "framework", "data", "file", "machine-learning-model"]);
const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const titleCase = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : s);

class PropertyMapperService {
  constructor() {
    this.pkg = new PackageRegistryService();
    this.vuln = new VulnerabilityService();
    this.gh = new GitHubService();
    this.lifecycle = new LifecycleService();
  }

  async fetchComponentData(component, sbomVulnerabilities = []) {
    try {
      if (cacheService.hasComponentResult(component, sbomVulnerabilities)) {
        return cacheService.getComponentResult(component, sbomVulnerabilities);
      }
      const pkgInfo = this.pkg.extractPackageInfo(component);
      const repoUrl = (component.externalReferences || []).find((r) => r.type === "vcs" || r.type === "repository")?.url || null;
      // each fetch checks the shared cache itself
      const [pkgData, vulnData, ghData, eolDate] = await Promise.all([
        this.pkg.fetchPackageData(pkgInfo),
        this.vuln.fetchVulnerabilityData(pkgInfo),
        this.gh.fetchGitHubData(repoUrl),
        this.lifecycle.fetchEol(component, pkgInfo),
      ]);
      const props = this.buildProperties(component, pkgInfo, pkgData, vulnData, ghData, eolDate, sbomVulnerabilities);
      cacheService.setComponentResult(component, sbomVulnerabilities, props);
      return props;
    } catch (error) {
      errorService.logError(error, "fetchComponentData", { componentName: component.name, componentVersion: component.version });
      // Do not cache failures: a later retry should be able to succeed.
      return {
        "Patch Status": "NA",
        "Release Date": "NA",
        "End-of-Life Date": "NA",
        "Criticality": "NA",
        "Usage Restrictions": "NA",
        "Comments or Notes": "Error occurred while fetching component data",
        "Executable Property": "NA",
        "Archive Property": "NA",
        "Structured Property": "NA",
        "Unique Identifier": isValidPurl(component.purl) ? component.purl : "NA",
        "Component Supplier": "NA",
        "Component Origin": "NA",
        _vulnerabilities: [],
        // NA here means "not collected", not a known unknown (see conformance.js)
        _lookupFailed: String(error?.message || error || "unknown error").slice(0, 200),
      };
    }
  }

  // Why each field that is still NA could not be determined: recorded as CERT-In "known unknowns"
  // (Table 5, Practices and Processes) so a reader can tell "looked, nothing exists" from "not checked".
  explainUnknowns(props, component, pkgInfo, pkgData, vulnData, license) {
    const noEcosystem = !pkgInfo || ["unknown", "generic"].includes(pkgInfo.ecosystem);
    const distro = ["deb", "rpm", "apk", "alpm"].includes(pkgInfo?.ecosystem);
    const reasons = {
      "Patch Status": vulnData?.reason || "vulnerability status could not be determined",
      "Criticality": vulnData?.scanned === false ? `no vulnerability data (${vulnData.reason})` : "no severity information",
      "Release Date": noEcosystem ? "component has no package-registry identity"
        : distro ? "OS package: release date not published by a browser-accessible source"
        : "release date not published by the package registry",
      "End-of-Life Date": distro ? "OS package: supported by the distribution, upstream EOL does not apply"
        : "no end-of-life data published for this product (endoflife.date)",
      "Usage Restrictions": "no licence information in the SBOM or package registry",
      "Component Supplier": "no supplier in the SBOM, package registry or package namespace",
      "Component Origin": license ? "licence does not indicate origin" : "no licence information to determine origin",
      "Executable Property": "cannot be determined from the component type",
      "Archive Property": noEcosystem ? "no package type to determine packaging" : "cannot be determined from the package type",
      "Structured Property": "no package manifest (component has no package ecosystem)",
      "Unique Identifier": "component has no name to build an identifier from",
    };
    const out = {};
    for (const [field, reason] of Object.entries(reasons)) if (props[field] === "NA") out[field] = reason;
    return out;
  }

  buildProperties(component, pkgInfo, pkgData, vulnData, ghData, eolDate, sbomVulnerabilities) {
    const license = componentLicense(component) || pkgData?.license || ghData?.license || null;
    const supplier = this.determineSupplier(component, pkgInfo, pkgData);
    const props = {
      "Patch Status": this.computePatchStatus(vulnData, pkgInfo, pkgData),
      "Release Date": pkgData?.releaseDate || "NA",
      "End-of-Life Date": eolDate || "NA",
      "Criticality": this.determineCriticality(vulnData, sbomVulnerabilities, component),
      "Usage Restrictions": usageRestrictions(license),
      "Comments or Notes": this.buildComments(pkgData, vulnData),
      "Executable Property": this.determineExecutable(component),
      "Archive Property": this.determineArchive(component, pkgInfo),
      "Structured Property": this.determineStructured(pkgInfo),
      "Component Supplier": supplier,
      "Component Origin": this.determineOrigin(component, license, ghData, supplier),
      "Unique Identifier": this.generateUniqueIdentifier(component, pkgInfo, supplier),
      // not CERT-In properties: data written into the SBOM itself by App.js
      _vulnerabilities: vulnData?.vulns || [],
      // native CycloneDX fields (Table 5 fields 3, 5, 14), applied only where the SBOM has none
      _componentFields: {
        description: pkgData?.description || null,
        licenses: componentLicense(component) ? null : toCycloneDxLicenses(pkgData?.license || ghData?.license),
        hashes: Array.isArray(component.hashes) && component.hashes.length ? null : (pkgData?.hashes?.length ? pkgData.hashes : null),
        hashSource: pkgData?.hashSource || null,
      },
    };
    props._knownUnknowns = this.explainUnknowns(props, component, pkgInfo, pkgData, vulnData, license);
    props._criticalityBasis = this.criticalityBasis(props["Criticality"], vulnData, sbomVulnerabilities, component);
    return props;
  }

  // ---------------------------------------------------------------- Patch Status (field 9)
  computePatchStatus(vulnData, pkgInfo, pkgData) {
    const newer = pkgData?.latestVersion && pkgInfo?.version && versionLt(pkgInfo.version, pkgData.latestVersion);
    if (!vulnData?.scanned) {
      // could not be checked against a vulnerability database - do not claim "Up to date"
      return newer ? `Update available (latest ${pkgData.latestVersion})` : "NA";
    }
    if (vulnData.hasVulnerabilities) {
      const urgent = vulnData.kevCount > 0 ? "URGENT - actively exploited (CISA KEV); " : "";
      if (vulnData.bestFix) return `${urgent}Update available (>= ${vulnData.bestFix})`;
      return `${urgent}No fix available (${vulnData.totalVulns} known vulnerabilities)`;
    }
    if (newer) return `Update available (latest ${pkgData.latestVersion})`;
    return "Up to date";
  }

  // ---------------------------------------------------------------- Criticality (field 12)
  determineCriticality(vulnData, sbomVulnerabilities, component) {
    if (vulnData?.kevCount > 0 || vulnData?.malicious) return "Critical";
    const fromSbom = this.determineCriticalityFromSbom(sbomVulnerabilities, component);
    const fromOsv = vulnData?.maxSeverity ? titleCase(vulnData.maxSeverity) : this.determineCriticalityFromScore(vulnData);
    const candidates = [fromSbom, fromOsv].filter((c) => c && SEVERITY_ORDER.includes(c.toLowerCase()));
    if (candidates.length) {
      return candidates.sort((a, b) => SEVERITY_ORDER.indexOf(a.toLowerCase()) - SEVERITY_ORDER.indexOf(b.toLowerCase()))[0];
    }
    if (!vulnData?.scanned) return "NA";
    return this.vuln.determineCriticality(vulnData);
  }

  criticalityBasis(value, vulnData, sbomVulns, component) {
    if (!value || value === "NA") return null;
    if (vulnData?.kevCount > 0) return "an actively exploited vulnerability (CISA KEV)";
    if (vulnData?.malicious) return "a malicious-package report";
    if (this.determineCriticalityFromSbom(sbomVulns, component) || vulnData?.totalVulns > 0) return "the highest vulnerability severity";
    return "having no known vulnerabilities";
  }

  determineCriticalityFromSbom(sbomVulns, component) {
    if (!Array.isArray(sbomVulns) || sbomVulns.length === 0) return null;
    const ref = component["bom-ref"] || component.bomRef || null;
    let best = null;
    for (const v of sbomVulns) {
      if (!Array.isArray(v.affects) || !v.affects.some((a) => a?.ref && ref && a.ref === ref)) continue;
      for (const r of v.ratings || []) {
        const sev = String(r.severity || "").toLowerCase();
        if (SEVERITY_ORDER.includes(sev) && (best === null || SEVERITY_ORDER.indexOf(sev) < SEVERITY_ORDER.indexOf(best))) {
          best = sev;
        }
      }
    }
    return best ? titleCase(best) : null;
  }

  determineCriticalityFromScore(vulnData) {
    const score = Number(vulnData?.maxCvssScore || 0);
    if (score >= 9) return "Critical";
    if (score >= 7) return "High";
    if (score >= 4) return "Medium";
    if (score > 0) return "Low";
    return null;
  }

  // ---------------------------------------------------------------- Supplier / Origin (fields 4, 6)
  // CERT-In: "The entity or organization that supplied the software component".
  determineSupplier(component, pkgInfo, pkgData) {
    const direct = component?.supplier?.name || component?.manufacturer?.name || component?.publisher
      || (Array.isArray(component?.authors) && component.authors[0]?.name) || pkgData?.author;
    if (direct) return direct;
    const ns = pkgInfo?.namespace;
    if (ns) {
      if (pkgInfo.ecosystem === "golang" && /^(github\.com|gitlab\.com)\//.test(ns)) return ns.split("/")[1];
      if (["maven", "npm", "composer", "nuget", "docker", "oci", "github", "gitlab"].includes(pkgInfo.ecosystem)) {
        return ns.replace(/^@/, "");
      }
    }
    return "NA";
  }

  determineOrigin(component, license, ghData, supplier) {
    if (isProprietaryLicense(license)) return "Proprietary";
    if (isOpenSourceLicense(license) || (ghData?.stars || 0) > 0) return "Open-source";
    if (component?.scope === "excluded") return "NA";
    if (supplier && supplier !== "NA" && license) return "Third-party vendor";
    return "NA";
  }

  // ---------------------------------------------------------------- Executable / Archive / Structured (18-20)
  determineExecutable(component) {
    const name = String(component?.name || "").toLowerCase();
    if (EXECUTABLE_COMPONENT_TYPES.has(component?.type) || /\.(exe|dll|so|dylib|bin|elf|sh|bat|ps1|msi)$/.test(name)) return "Yes";
    if (NON_EXECUTABLE_COMPONENT_TYPES.has(component?.type)) return "No";
    return "NA";
  }

  determineArchive(component, pkgInfo) {
    const name = String(component?.name || "").toLowerCase();
    if (ARCHIVE_TYPES.has(pkgInfo?.ecosystem) || /\.(zip|jar|war|ear|tar|tgz|gz|bz2|xz|7z|whl|nupkg|deb|rpm|apk|gem|crate)$/.test(name)) {
      return "Yes";
    }
    if (["github", "gitlab", "bitbucket"].includes(pkgInfo?.ecosystem)) return "No";
    return "NA";
  }

  determineStructured(pkgInfo) {
    // ecosystem packages carry a structured manifest (pom.xml, package.json, METADATA, ...)
    if (pkgInfo?.ecosystem && !["unknown", "generic"].includes(pkgInfo.ecosystem)) return "Yes";
    return "NA";
  }

  // ---------------------------------------------------------------- Unique Identifier (field 21)
  // Always a *valid* purl so scanners can match it. A component without a purl gets
  // pkg:generic/<supplier>/<name>@<version>, matching the CERT-In "pkg:supplier/Org/Component@Version" shape.
  generateUniqueIdentifier(component, pkgInfo, supplier) {
    if (isValidPurl(component?.purl)) return component.purl;
    if (pkgInfo?.ecosystem && pkgInfo.ecosystem !== "unknown" && pkgInfo.name) {
      const ns = pkgInfo.ecosystem === "maven" ? pkgInfo.group : null;
      return buildPurl(pkgInfo.ecosystem, pkgInfo.name, component?.version, ns);
    }
    if (component?.name) {
      const ns = supplier && supplier !== "NA" ? slug(supplier) : null;
      return buildPurl("generic", component.name, component.version, ns);
    }
    return "NA";
  }

  // ---------------------------------------------------------------- Comments (field 15)
  buildComments(pkgData, vulnData) {
    const notes = [];
    if (pkgData?.description) notes.push(`Description: ${pkgData.description}`);
    if (vulnData?.scanned === false) notes.push(`Vulnerabilities not checked: ${vulnData.reason}`);
    if (vulnData?.totalVulns > 0) {
      const bySev = {};
      for (const v of vulnData.vulns) bySev[v.severity || "unscored"] = (bySev[v.severity || "unscored"] || 0) + 1;
      const order = [...SEVERITY_ORDER, "unscored"];
      const breakdown = order.filter((s) => bySev[s]).map((s) => `${s}:${bySev[s]}`).join(", ");
      notes.push(`${vulnData.totalVulns} known vulnerabilities (${breakdown})`);
      if (vulnData.kevCount) notes.push(`${vulnData.kevCount} actively exploited (CISA KEV)`);
      if (vulnData.maxEpss) notes.push(`max EPSS ${vulnData.maxEpss.toFixed(2)}`);
      if (vulnData.malicious) notes.push("MALICIOUS PACKAGE reported in OSV");
      notes.push(`Recommended version: ${vulnData.bestFix || "NA (no fix published)"}`);
    }
    return notes.length ? notes.join("; ") : "NA";
  }
}

export default PropertyMapperService;

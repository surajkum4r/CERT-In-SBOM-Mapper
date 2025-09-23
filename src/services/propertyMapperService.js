// Maps fetched data into CERT-In properties

import PackageRegistryService from "./packageRegistryService";
import VulnerabilityService from "./vulnerabilityService";
import GitHubService from "./githubService";
import LifecycleService from "./lifecycleService";

class PropertyMapperService {
  constructor() {
    this.pkg = new PackageRegistryService();
    this.vuln = new VulnerabilityService();
    this.gh = new GitHubService();
    this.lifecycle = new LifecycleService();
  }

  determineUsageRestrictions(license) {
    if (!license) return "NA";
    const l = String(license).toLowerCase();
    if (l.includes("agpl")) return "AGPL License - Strong copyleft restrictions";
    if (l.includes("gpl")) return "GPL License - Copyleft restrictions apply";
    if (l.includes("mit") || l.includes("apache")) return "Permissive license - Minimal restrictions";
    return "NA";
  }

  determineOrigin(packageData, githubData) {
    if ((githubData?.stars || 0) > 0) return "Open-source";
    if (packageData?.license && /proprietary/i.test(packageData.license)) return "Proprietary";
    return "Open-source";
  }

  determineSupplier(packageData, githubData) {
    if ((githubData?.stars || 0) > 0) return "Open-source";
    if (packageData?.author) return "Vendor";
    return "Third-party";
  }

  buildComments(packageData, vulnData, githubData) {
    const notes = [];
    if (packageData?.description) notes.push(`Description: ${packageData.description}`);
    if (vulnData?.totalVulns > 0) notes.push(`${vulnData.totalVulns} known vulnerabilities`);
    if ((githubData?.stars || 0) > 100) notes.push(`Popular project (${githubData.stars} stars)`);
    return notes.length ? notes.join("; ") : "NA";
  }

  async fetchComponentData(component, sbomVulnerabilities = []) {
    const pkgInfo = this.pkg.extractPackageInfo(component);
    const repoUrl = (component.externalReferences || []).find((r) => r.type === "vcs" || r.type === "repository")?.url || null;

    const [pkgData, vulnData, ghData, eolDate] = await Promise.all([
      pkgInfo?.ecosystem === "npm"
        ? this.pkg.fetchNpmData(pkgInfo.name)
        : pkgInfo?.ecosystem === "pypi"
        ? this.pkg.fetchPyPiData(pkgInfo.name)
        : pkgInfo?.ecosystem === "maven"
        ? this.pkg.fetchMavenData(pkgInfo.group, pkgInfo.name)
        : Promise.resolve(null),
      this.vuln.fetchVulnerabilityData(pkgInfo),
      this.gh.fetchGitHubData(repoUrl),
      this.lifecycle.fetchEol(component, pkgInfo),
    ]);

    if (process.env.REACT_APP_DEBUG_FETCH === "1") {
      // eslint-disable-next-line no-console
      console.log("[MAP:init]", {
        name: component.name,
        version: component.version,
        ecosystem: pkgInfo?.ecosystem,
        maven: pkgInfo?.group ? `${pkgInfo.group}:${pkgInfo.name}` : undefined,
        repoUrl,
      });
    }

    const props = {};
    props["Patch Status"] = this.computePatchStatus(vulnData, pkgInfo, pkgData);
    props["Release Date"] = pkgData?.releaseDate || ghData?.releaseDate || "NA";
    props["End-of-Life Date"] = eolDate || "NA";
    const criticalityFromSbom = this.determineCriticalityFromSbom(sbomVulnerabilities, component);
    const resolvedCriticality =
      criticalityFromSbom ||
      this.determineCriticalityFromOsv(vulnData) ||
      this.vuln.determineCriticality(vulnData);
    props["Criticality"] = resolvedCriticality;
    const license = pkgData?.license || ghData?.license || null;
    props["Usage Restrictions"] = this.determineUsageRestrictions(license);
    props["Comments or Notes"] = this.buildComments(pkgData, vulnData, ghData);
    props["Executable Property"] = pkgInfo?.ecosystem === "npm" ? "Yes" : "No";
    props["Archive Property"] = "No";
    props["Structured Property"] = "Yes";
    props["Unique Identifier"] = component.purl || component.name || "NA";
    props["Component Supplier"] = this.determineSupplier(pkgData, ghData);
    props["Component Origin"] = this.determineOrigin(pkgData, ghData);

    // Provide a recommended vulnerability-free version (or NA if unknown)
    const hasFixed = Array.isArray(vulnData?.fixedVersions) && vulnData.fixedVersions.length > 0;
    const recommendationText = hasFixed
      ? `Recommended version: ${vulnData.fixedVersions[0]}`
      : props["Patch Status"] === "Update available"
      ? "Recommended version: NA"
      : null;
    if (recommendationText) {
      props["Comments or Notes"] = props["Comments or Notes"] === "NA"
        ? recommendationText
        : `${props["Comments or Notes"]}; ${recommendationText}`;
    }

    if (process.env.REACT_APP_DEBUG_FETCH === "1") {
      // eslint-disable-next-line no-console
      console.log("[MAP]", {
        name: component.name,
        version: component.version,
        ecosystem: pkgInfo?.ecosystem,
        maven: pkgInfo?.group ? `${pkgInfo.group}:${pkgInfo.name}` : undefined,
        osvVulns: vulnData?.totalVulns ?? 0,
        osvFixed: Array.isArray(vulnData?.fixedVersions) ? vulnData.fixedVersions : [],
        latest: pkgData?.latestVersion || null,
        patchStatus: props["Patch Status"],
        criticality: props["Criticality"],
      });
    }

    return props;
  }

  determineCriticalityFromSbom(sbomVulns, component) {
    if (!Array.isArray(sbomVulns) || sbomVulns.length === 0) return null;
    const ref = component["bom-ref"] || component.bomRef || null;
    let max = null;
    for (const v of sbomVulns) {
      if (!Array.isArray(v.affects)) continue;
      if (!v.ratings || !Array.isArray(v.ratings) || v.ratings.length === 0) continue;
      const affectsThis = v.affects.some((a) => a?.ref && ref && a.ref === ref);
      if (!affectsThis) continue;
      // pick highest severity string among ratings
      const sev = v.ratings.map((r) => (r.severity || "").toUpperCase());
      const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]; 
      const highest = sev.sort((a, b) => order.indexOf(a) - order.indexOf(b))[0] || null;
      if (!highest) continue;
      if (max === null || order.indexOf(highest) < order.indexOf(max)) {
        max = highest;
      }
    }
    if (!max) return null;
    // Map back to title case expected in UI values
    return max.charAt(0) + max.slice(1).toLowerCase();
  }

  computePatchStatus(vulnData, pkgInfo, pkgData) {
    // If vulnerabilities exist, include fixed version or NA explicitly
    if (vulnData?.hasVulnerabilities) {
      if (Array.isArray(vulnData.fixedVersions) && vulnData.fixedVersions.length > 0) {
        return `Update available (>= ${vulnData.fixedVersions[0]})`;
      }
      return "Update available (>= NA)";
    }
    // No vulnerabilities, but a newer version exists => suggest update (optional version hint)
    if (pkgData?.latestVersion && pkgInfo?.version && pkgData.latestVersion !== pkgInfo.version) {
      return `Update available (latest ${pkgData.latestVersion})`;
    }
    // Otherwise consider up to date
    return "Up to date";
  }

  determineCriticalityFromOsv(vulnData) {
    const score = Number(vulnData?.maxCvssScore || 0);
    if (score >= 9) return "Critical";
    if (score >= 7) return "High";
    if (score >= 4) return "Medium";
    if (score > 0) return "Low";
    return null;
  }
}

export default PropertyMapperService;



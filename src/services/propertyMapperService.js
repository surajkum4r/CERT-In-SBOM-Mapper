// Maps fetched data into CERT-In properties

import PackageRegistryService from "./packageRegistryService";
import VulnerabilityService from "./vulnerabilityService";
import GitHubService from "./githubService";
import LifecycleService from "./lifecycleService";
import errorService from "./errorService";
import cacheService from "./cacheService";

class PropertyMapperService {
  constructor() {
    this.pkg = new PackageRegistryService();
    this.vuln = new VulnerabilityService();
    this.gh = new GitHubService();
    this.lifecycle = new LifecycleService();
  }

  // Check if all required data is cached for fast processing
  isAllDataCached(component, pkgInfo, repoUrl) {
    if (!pkgInfo || pkgInfo.ecosystem === "unknown") return true; // No external data needed
    
    const pkgKey = pkgInfo?.ecosystem === "npm" 
      ? cacheService.generateKey('npm', pkgInfo.name)
      : pkgInfo?.ecosystem === "pypi"
      ? cacheService.generateKey('pypi', pkgInfo.name)
      : pkgInfo?.ecosystem === "maven"
      ? cacheService.generateKey('maven', pkgInfo.group, pkgInfo.name)
      : null;
    
    const vulnKey = cacheService.generateKey('vuln', pkgInfo.ecosystem, pkgInfo.name);
    const ghKey = repoUrl ? cacheService.generateKey('github', repoUrl.split('/').slice(-2).join('/')) : null;
    
    return (!pkgKey || cacheService.has(pkgKey)) &&
           (!vulnKey || cacheService.has(vulnKey)) &&
           (!ghKey || cacheService.has(ghKey));
  }

  // Fast synchronous processing when all data is cached
  buildPropertiesFromCachedData(component, pkgInfo, repoUrl, sbomVulnerabilities) {
    // Get cached data directly
    const pkgData = pkgInfo?.ecosystem === "npm" 
      ? cacheService.get(cacheService.generateKey('npm', pkgInfo.name))
      : pkgInfo?.ecosystem === "pypi"
      ? cacheService.get(cacheService.generateKey('pypi', pkgInfo.name))
      : pkgInfo?.ecosystem === "maven"
      ? cacheService.get(cacheService.generateKey('maven', pkgInfo.group, pkgInfo.name))
      : null;
    
    const vulnData = cacheService.get(cacheService.generateKey('vuln', pkgInfo.ecosystem, pkgInfo.name));
    const ghData = repoUrl ? cacheService.get(cacheService.generateKey('github', repoUrl.split('/').slice(-2).join('/'))) : null;
    const eolDate = this.lifecycle.fetchEol(component, pkgInfo); // This is synchronous

    // Build properties using cached data
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
    props["Component Supplier"] = this.determineSupplier(pkgData, ghData);
    props["Component Origin"] = this.determineOrigin(pkgData, ghData);
    props["Unique Identifier"] = this.generateUniqueIdentifier(component, pkgInfo, props["Component Supplier"]);

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

    return props;
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

  generateUniqueIdentifier(component, pkgInfo, supplier) {
    // If component already has a purl, prepend "supplier" to it
    if (component.purl && this.isValidPurl(component.purl)) {
      // Take existing purl and prepend "supplier"
      // pkg:maven/org.hdrhistogram/HdrHistogram@2.1.12?type=jar
      // becomes: pkg:supplier/maven/org.hdrhistogram/HdrHistogram@2.1.12?type=jar
      return component.purl.replace('pkg:', 'pkg:supplier/');
    }
    
    // Generate new purl following Package URL specification
    if (pkgInfo?.ecosystem && pkgInfo?.name) {
      const organizationName = this.extractOrganizationName(component, pkgInfo, supplier);
      const standardPurl = this.generateStandardPurl(component, pkgInfo, organizationName, supplier);
      // Prepend "supplier" to the generated purl
      return standardPurl.replace('pkg:', 'pkg:supplier/');
    }
    
    // Fallback to component name
    return component.name || "NA";
  }

  extractOrganizationName(component, pkgInfo, supplier) {
    // Try to get organization from various sources in order of preference
    if (pkgInfo?.group) return pkgInfo.group; // For Maven groupId
    if (pkgInfo?.author) return pkgInfo.author;
    if (component.publisher) return component.publisher;
    if (component.author) return component.author;
    if (component.organization) return component.organization;
    
    // For scoped packages (e.g., @angular/core), extract scope
    if (pkgInfo?.name && pkgInfo.name.startsWith('@')) {
      const scope = pkgInfo.name.split('/')[0].substring(1);
      return scope;
    }
    
    // Special handling for different ecosystems
    const ecosystem = pkgInfo?.ecosystem?.toLowerCase();
    if (ecosystem === 'pypi') {
      // PyPI packages typically don't have organization names
      return null;
    }
    if (ecosystem === 'gem') {
      // Ruby gems typically don't have organization names
      return null;
    }
    if (ecosystem === 'cargo') {
      // Rust crates typically don't have organization names
      return null;
    }
    
    // Fallback to supplier or component name
    return supplier || component.name || "unknown";
  }

  generateStandardPurl(component, pkgInfo, organizationName, supplier) {
    const ecosystem = pkgInfo.ecosystem.toLowerCase();
    const name = pkgInfo.name;
    const version = component.version ? `@${component.version}` : '';
    
    // Generate standard purl first, then we'll prepend "supplier"
    let basePurl;
    if (ecosystem === 'maven' && pkgInfo.group) {
      // Maven: pkg:maven/group/name@version
      basePurl = `pkg:${ecosystem}/${pkgInfo.group}/${name}${version}`;
    } else if (ecosystem === 'npm' && name.startsWith('@')) {
      // NPM scoped: pkg:npm/@scope/name@version
      basePurl = `pkg:${ecosystem}/${name}${version}`;
    } else {
      // Other ecosystems: pkg:ecosystem/name@version
      basePurl = `pkg:${ecosystem}/${name}${version}`;
    }
    
    // Add qualifiers and subpath if present
    return this.addQualifiersAndSubpath(basePurl, component);
  }

  addQualifiersAndSubpath(basePurl, component) {
    const qualifiers = [];
    const subpath = component.subpath || '';
    
    // Add common qualifiers based on component properties
    if (component.classifier) qualifiers.push(`classifier=${component.classifier}`);
    if (component.extension) qualifiers.push(`extension=${component.extension}`);
    if (component.type) qualifiers.push(`type=${component.type}`);
    if (component.scope) qualifiers.push(`scope=${component.scope}`);
    
    // Add repository qualifier if available
    if (component.repository) {
      const repo = component.repository.replace(/^https?:\/\//, '').replace(/\/$/, '');
      qualifiers.push(`repository_url=${repo}`);
    }
    
    // Build final PURL
    let finalPurl = basePurl;
    
    if (qualifiers.length > 0) {
      finalPurl += `?${qualifiers.join('&')}`;
    }
    
    if (subpath) {
      finalPurl += `#${subpath}`;
    }
    
    return finalPurl;
  }

  isValidPurl(purl) {
    if (!purl || !purl.startsWith('pkg:')) return false;
    
    try {
      // Basic validation - check if it follows pkg:type/namespace/name@version format
      const withoutPkg = purl.substring(4); // Remove 'pkg:'
      const parts = withoutPkg.split('/');
      
      if (parts.length < 2) return false;
      
      const type = parts[0];
      const namePart = parts[parts.length - 1];
      
      // Check if name part has version
      const hasVersion = namePart.includes('@');
      
      return type && namePart && (hasVersion || !namePart.includes('@'));
    } catch {
      return false;
    }
  }

  parseExistingPurl(purl) {
    if (!this.isValidPurl(purl)) return null;
    
    try {
      const withoutPkg = purl.substring(4);
      const [typeAndNsName, versionPart] = withoutPkg.split('@');
      const parts = typeAndNsName.split('/');
      
      const type = parts[0];
      const version = versionPart ? versionPart.split('?')[0].split('#')[0] : null;
      const name = parts[parts.length - 1];
      const namespace = parts.length > 2 ? parts.slice(1, -1).join('/') : null;
      
      return {
        type,
        namespace,
        name,
        version,
        original: purl
      };
    } catch {
      return null;
    }
  }

  buildComments(packageData, vulnData, githubData) {
    const notes = [];
    if (packageData?.description) notes.push(`Description: ${packageData.description}`);
    if (vulnData?.totalVulns > 0) notes.push(`${vulnData.totalVulns} known vulnerabilities`);
    if ((githubData?.stars || 0) > 100) notes.push(`Popular project (${githubData.stars} stars)`);
    return notes.length ? notes.join("; ") : "NA";
  }

  async fetchComponentData(component, sbomVulnerabilities = []) {
    try {
      // Ultra-fast path: Check if we already have the complete result cached
      if (cacheService.hasComponentResult(component, sbomVulnerabilities)) {
        if (process.env.NODE_ENV === 'development') {
          console.log('[CHECKSUM] Cache HIT for component:', component.name);
        }
        return cacheService.getComponentResult(component, sbomVulnerabilities);
      }
      if (process.env.NODE_ENV === 'development') {
        console.log('[CHECKSUM] Cache MISS for component:', component.name);
      }

      const pkgInfo = this.pkg.extractPackageInfo(component);
      const repoUrl = (component.externalReferences || []).find((r) => r.type === "vcs" || r.type === "repository")?.url || null;

      // Fast path: if all data is cached, process synchronously
      if (this.isAllDataCached(component, pkgInfo, repoUrl)) {
        const result = this.buildPropertiesFromCachedData(component, pkgInfo, repoUrl, sbomVulnerabilities);
        // Cache the complete result for future use
        cacheService.setComponentResult(component, sbomVulnerabilities, result);
        return result;
      }

      // Use Promise.all instead of Promise.allSettled for faster processing with cached data
      const results = await Promise.all([
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

      const [pkgData, vulnData, ghData, eolDate] = results;

      if (process.env.REACT_APP_DEBUG_FETCH === "1" && process.env.NODE_ENV === 'development') {
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
    props["Component Supplier"] = this.determineSupplier(pkgData, ghData);
    props["Component Origin"] = this.determineOrigin(pkgData, ghData);
    props["Unique Identifier"] = this.generateUniqueIdentifier(component, pkgInfo, props["Component Supplier"]);

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

    if (process.env.REACT_APP_DEBUG_FETCH === "1" && process.env.NODE_ENV === 'development') {
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

      // Cache the complete result for future use
      cacheService.setComponentResult(component, sbomVulnerabilities, props);
      return props;
    } catch (error) {
      errorService.logError(error, 'fetchComponentData', { 
        componentName: component.name,
        componentVersion: component.version 
      });
      
      // Return minimal props with error indication
      const errorProps = {
        "Patch Status": "Error fetching data",
        "Release Date": "NA",
        "End-of-Life Date": "NA",
        "Criticality": "Unknown",
        "Usage Restrictions": "NA",
        "Comments or Notes": "Error occurred while fetching component data",
        "Executable Property": "Unknown",
        "Archive Property": "No",
        "Structured Property": "Yes",
        "Unique Identifier": component.purl || component.name || "NA",
        "Component Supplier": "Unknown",
        "Component Origin": "Unknown"
      };
      
      // Cache even error results to avoid repeated failures
      cacheService.setComponentResult(component, sbomVulnerabilities, errorProps);
      return errorProps;
    }
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



// Package registry service: version-specific metadata (release date, description, licence,
// supplier) from npm, PyPI, Maven Central and deps.dev (Maven/Go/Cargo/NuGet/npm/PyPI).

import cacheService from "./cacheService";
import { parsePurl } from "../utils/purl";

const DEPS_DEV_SYSTEM = { maven: "MAVEN", golang: "GO", cargo: "CARGO", nuget: "NUGET", npm: "NPM", pypi: "PYPI" };

class PackageRegistryService {
  // Returns { ecosystem, group, namespace, name, version, qualifiers, purl }.
  //   npm scoped packages keep their scope in `name` ("@angular/core"); Go keeps the module path.
  extractPackageInfo(component) {
    const p = parsePurl(component?.purl);
    if (p) {
      let name = p.name;
      if (p.namespace && (p.type === "npm" || p.type === "golang" || p.type === "composer")) {
        name = `${p.namespace}/${p.name}`;
      }
      return {
        ecosystem: p.type,
        group: p.type === "maven" ? p.namespace : null,
        namespace: p.namespace,
        name,
        version: p.version || component.version || null,
        qualifiers: p.qualifiers,
        purl: component.purl,
      };
    }
    const name = component?.name || "";
    const version = component?.version || null;
    if (component?.group && name) {
      return { ecosystem: "maven", group: component.group, namespace: component.group, name, version, qualifiers: {} };
    }
    return { ecosystem: "unknown", group: null, namespace: null, name, version, qualifiers: {} };
  }

  cacheKey(pkgInfo) {
    if (!pkgInfo || pkgInfo.ecosystem === "unknown") return null;
    return cacheService.generateKey("pkg2", pkgInfo.ecosystem, pkgInfo.group || "", pkgInfo.name, pkgInfo.version || "");
  }

  async fetchPackageData(pkgInfo) {
    const key = this.cacheKey(pkgInfo);
    if (!key) return null;
    if (cacheService.has(key)) return cacheService.get(key);
    let result = null;
    try {
      if (pkgInfo.ecosystem === "npm") result = await this.fetchNpmData(pkgInfo.name, pkgInfo.version);
      else if (pkgInfo.ecosystem === "pypi") result = await this.fetchPyPiData(pkgInfo.name, pkgInfo.version);
      else if (pkgInfo.ecosystem === "maven") result = await this.fetchMavenData(pkgInfo.group, pkgInfo.name, pkgInfo.version);
      // deps.dev fills gaps (and is the only source for Go/Cargo/NuGet here)
      if (!result?.releaseDate || !result?.license) {
        const dd = await this.fetchDepsDev(pkgInfo);
        if (dd) {
          result = {
            ...(result || {}),
            releaseDate: result?.releaseDate || dd.releaseDate,
            license: result?.license || dd.license,
            latestVersion: result?.latestVersion || null,
          };
        }
      }
    } catch {
      result = null;
    }
    if (result) cacheService.set(key, result);
    return result;
  }

  async fetchNpmData(packageName, version) {
    const res = await fetch(`https://registry.npmjs.org/${packageName.replace("/", "%2F")}`);
    if (!res.ok) return null;
    const data = await res.json();
    const ver = (version && data?.versions?.[version]) || {};
    const author = ver.author || data.author;
    return {
      // release date of *this* version (time.created is when the package was first published)
      releaseDate: this.formatDate(version ? data?.time?.[version] : null),
      latestVersion: data?.["dist-tags"]?.latest || null,
      description: ver.description || data?.description || null,
      homepage: ver.homepage || data?.homepage || null,
      repository: (ver.repository || data?.repository)?.url || null,
      license: this.licenseString(ver.license || data?.license),
      author: typeof author === "string" ? author.split("<")[0].trim() : author?.name || null,
    };
  }

  async fetchPyPiData(packageName, version) {
    const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(packageName)}/json`);
    if (!res.ok) return null;
    const data = await res.json();
    const info = data?.info || {};
    const files = (version && data?.releases?.[version]) || [];
    const sdist = files.find((f) => f.packagetype === "sdist") || files[0];
    const classifierLicense = (info.classifiers || []).find((c) => c.startsWith("License ::"))?.split("::").pop()?.trim();
    const license = info.license_expression || (info.license && info.license.length < 80 ? info.license : null) || classifierLicense || null;
    return {
      releaseDate: this.formatDate(sdist?.upload_time_iso_8601 || sdist?.upload_time),
      latestVersion: info.version || null,
      description: info.summary || null,
      homepage: info.home_page || info.project_urls?.Homepage || null,
      repository: info.project_urls?.Source || info.project_urls?.Repository || null,
      license,
      author: info.maintainer || info.author || (info.author_email || "").split("<")[0].trim() || null,
    };
  }

  async fetchMavenData(group, artifact, version) {
    // latest version from Maven Central search; version-specific date/licence come from deps.dev
    let latestVersion = null;
    try {
      const q = encodeURIComponent(`g:"${group}" AND a:"${artifact}"`);
      const res = await fetch(`https://search.maven.org/solrsearch/select?q=${q}&rows=1&wt=json`);
      if (res.ok) latestVersion = (await res.json())?.response?.docs?.[0]?.latestVersion || null;
    } catch {
      // optional
    }
    const dd = await this.fetchDepsDev({ ecosystem: "maven", group, name: artifact, version });
    return {
      releaseDate: dd?.releaseDate || null,
      latestVersion,
      description: null,
      homepage: null,
      repository: null,
      license: dd?.license || null,
      author: null,
    };
  }

  async fetchDepsDev(pkgInfo) {
    const system = DEPS_DEV_SYSTEM[pkgInfo?.ecosystem];
    if (!system || !pkgInfo.version) return null;
    const name = pkgInfo.ecosystem === "maven" ? `${pkgInfo.group}:${pkgInfo.name}` : pkgInfo.name;
    try {
      const res = await fetch(`https://api.deps.dev/v3/systems/${system}/packages/${encodeURIComponent(name)}` +
        `/versions/${encodeURIComponent(pkgInfo.version)}`);
      if (!res.ok) return null;
      const data = await res.json();
      const lic = (data.licenses || []).filter((l) => l && l !== "non-standard");
      return { releaseDate: this.formatDate(data.publishedAt), license: lic.length ? lic.join(" AND ") : null };
    } catch {
      return null;
    }
  }

  licenseString(lic) {
    if (!lic) return null;
    if (typeof lic === "string") return lic;
    if (Array.isArray(lic)) return lic.map((l) => l.type || l).join(" OR ");
    return lic.type || null;
  }

  formatDate(dateString) {
    if (!dateString) return null;
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return null;
    // DD-MM-YYYY (the app's display convention), in UTC so the date does not shift by timezone
    const dd = String(d.getUTCDate()).padStart(2, "0");
    const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
    return `${dd}-${mm}-${d.getUTCFullYear()}`;
  }
}

export default PackageRegistryService;

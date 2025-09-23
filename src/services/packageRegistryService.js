// Lightweight package registry service for fetching package metadata

class PackageRegistryService {
  constructor() {
    this.cache = new Map();
  }

  parsePurl(purl) {
    if (!purl) return null;
    try {
      // Generic: pkg:type/namespaceOrGroup/name@version?...
      const full = purl.replace(/^pkg:/, "");
      const [typeAndNsName, versionPart] = full.split("@");
      const [type, rest] = typeAndNsName.split("/");
      const version = versionPart ? versionPart.split("?")[0] : null;

      if (type === "maven") {
        // pkg:maven/group/name@version
        const [group, nameAndRest] = rest.split("/");
        const name = (nameAndRest || "").split("?")[0];
        if (group && name) {
          return {
            ecosystem: "maven",
            group,
            name,
            version,
          };
        }
      } else {
        // Fallback for npm/pypi etc.: pkg:npm/name@version
        const name = (rest || "").split("?")[0];
        if (type && name) {
          return { ecosystem: type.toLowerCase(), name, version };
        }
      }
    } catch {}
    return null;
  }

  extractPackageInfo(component) {
    const purlInfo = this.parsePurl(component.purl);
    if (purlInfo) return purlInfo;
    const name = component.name || "";
    const version = component.version || "";
    // Try to infer Maven GA if group is present
    if (component.group && component.name) {
      return { ecosystem: "maven", group: component.group, name: component.name, version };
    }
    return { ecosystem: "unknown", name, version };
  }

  async fetchNpmData(packageName) {
    const key = `npm:${packageName}`;
    if (this.cache.has(key)) return this.cache.get(key);
    try {
      const res = await fetch(`https://registry.npmjs.org/${packageName}`);
      if (!res.ok) throw new Error(String(res.status));
      const data = await res.json();
      const result = {
        releaseDate: this.formatDate(data?.time?.created),
        latestVersion: data?.["dist-tags"]?.latest || null,
        description: data?.description || null,
        homepage: data?.homepage || null,
        repository: data?.repository?.url || null,
        license: typeof data?.license === "string" ? data.license : null,
        author: data?.author?.name || null,
      };
      this.cache.set(key, result);
      return result;
    } catch {
      return null;
    }
  }

  async fetchPyPiData(packageName) {
    const key = `pypi:${packageName}`;
    if (this.cache.has(key)) return this.cache.get(key);
    try {
      const res = await fetch(`https://pypi.org/pypi/${packageName}/json`);
      if (!res.ok) throw new Error(String(res.status));
      const data = await res.json();
      const info = data?.info || {};
      const result = {
        releaseDate: this.formatDate(info?.upload_time),
        latestVersion: info?.version || null,
        description: info?.summary || null,
        homepage: info?.home_page || null,
        repository: info?.project_urls?.Source || null,
        license: info?.license || null,
        author: info?.author || null,
      };
      this.cache.set(key, result);
      return result;
    } catch {
      return null;
    }
  }

  async fetchMavenData(group, artifact) {
    const key = `maven:${group}:${artifact}`;
    if (this.cache.has(key)) return this.cache.get(key);
    try {
      // Query Maven Central for latest doc and timestamp
      const q = encodeURIComponent(`g:"${group}" AND a:"${artifact}"`);
      const url = `https://search.maven.org/solrsearch/select?q=${q}&rows=1&wt=json`;
      const res = await fetch(url);
      if (!res.ok) throw new Error(String(res.status));
      const data = await res.json();
      const doc = data?.response?.docs?.[0] || null;
      const timestampMs = doc?.timestamp || null;
      const latestVersion = doc?.latestVersion || null;
      const result = {
        releaseDate: this.msToDdMmYyyy(timestampMs),
        latestVersion: latestVersion || null,
        description: null,
        homepage: null,
        repository: null,
        license: null,
        author: null,
      };
      this.cache.set(key, result);
      return result;
    } catch {
      return null;
    }
  }

  msToDdMmYyyy(ms) {
    if (!ms) return null;
    const d = new Date(ms);
    if (isNaN(d.getTime())) return null;
    const dd = String(d.getDate()).padStart(2, "0");
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const yyyy = d.getFullYear();
    return `${dd}-${mm}-${yyyy}`;
  }

  formatDate(dateString) {
    if (!dateString) return null;
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return null;
    // DD-MM-YYYY
    const dd = String(d.getDate()).padStart(2, "0");
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const yyyy = d.getFullYear();
    return `${dd}-${mm}-${yyyy}`;
  }
}

export default PackageRegistryService;



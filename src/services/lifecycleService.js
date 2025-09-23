// Lifecycle service to determine End-of-Life dates

class LifecycleService {
  constructor() {
    this.overrideCache = null; // from optional /eol-overrides.json
  }

  async loadOverridesOnce() {
    if (this.overrideCache !== null) return this.overrideCache;
    try {
      const res = await fetch(`/eol-overrides.json`, { cache: "no-store" });
      if (!res.ok) throw new Error(String(res.status));
      const json = await res.json();
      this.overrideCache = json || {};
    } catch {
      this.overrideCache = {};
    }
    return this.overrideCache;
  }

  // Try endoflife.date using heuristic slug candidates derived from component name.
  async fetchEolFromEndOfLife(pkgInfo, component) {
    try {
      const candidates = this.generateSlugCandidates(component.name || "");
      for (const slug of candidates) {
        const hit = await this.queryEolApi(slug, component.version);
        if (hit) return hit;
      }
    } catch {}
    return null;
  }

  async queryEolApi(product, version) {
    try {
      const res = await fetch(`https://endoflife.date/api/${product}.json`);
      if (!res.ok) throw new Error(String(res.status));
      const rows = await res.json();
      if (!Array.isArray(rows)) return null;
      // Find matching cycle by major/minor prefix when possible
      const v = String(version || "");
      const found = rows.find((r) => {
        if (!r.cycle) return false;
        const cycle = String(r.cycle);
        return v === cycle || v.startsWith(cycle + ".");
      });
      const eol = found?.eol || null;
      if (!eol || eol === false) return null;
      // eol is YYYY-MM-DD
      const [yyyy, mm, dd] = String(eol).split("-");
      if (yyyy && mm && dd) return `${dd}-${mm}-${yyyy}`;
      return null;
    } catch {
      return null;
    }
  }

  generateSlugCandidates(name) {
    const raw = String(name || "").toLowerCase().trim();
    if (!raw) return [];
    // Normalize to words
    const words = raw
      .replace(/[^a-z0-9\s\.\-\+]/g, " ")
      .split(/\s+/)
      .filter(Boolean);
    const stop = new Set(["linux", "os", "framework", "library", "lang", "language"]);
    const uniques = new Set();
    const add = (s) => {
      const slug = s
        .toLowerCase()
        .replace(/[^a-z0-9\s\.\-\+]/g, "")
        .replace(/\s+/g, "-");
      if (slug) uniques.add(slug);
    };

    // Full name slug
    add(raw);
    // Individual significant tokens
    words.forEach((w) => {
      if (!stop.has(w)) add(w);
    });
    // Combined without stopwords
    const filtered = words.filter((w) => !stop.has(w));
    if (filtered.length > 1) add(filtered.join("-"));

    return Array.from(uniques);
  }

  normalizeGa(group, artifact) {
    return `${group}:${artifact}`.toLowerCase();
  }

  async fetchEol(component, pkgInfo) {
    // 1) Overrides file (for libraries like Maven where no public EOL data is available)
    const overrides = await this.loadOverridesOnce();
    if (pkgInfo?.ecosystem === "maven" && pkgInfo.group && pkgInfo.name) {
      const key = this.normalizeGa(pkgInfo.group, pkgInfo.name);
      const date = overrides?.maven?.[key] || null;
      if (date) return date; // expected DD-MM-YYYY in overrides
    }

    // 2) endoflife.date using heuristic slug candidates (no product hardcoding)
    const eol = await this.fetchEolFromEndOfLife(pkgInfo, component);
    if (eol) return eol;

    return null;
  }
}

export default LifecycleService;



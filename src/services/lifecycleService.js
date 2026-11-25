// Lifecycle service: End-of-Life dates from endoflife.date (plus an optional /eol-overrides.json).
//
// Products are matched against endoflife.date's published product list instead of guessing
// URL slugs, and package names that differ from the product slug are aliased
// (e.g. log4j-core -> log4j, spring-core -> spring-framework).

import cacheService from "./cacheService";

const ALIASES = {
  "spring-core": "spring-framework", "spring-webmvc": "spring-framework", "spring-context": "spring-framework",
  "spring-boot": "spring-boot", "spring-boot-starter": "spring-boot", "tomcat-catalina": "tomcat",
  "tomcat-embed-core": "tomcat", "log4j-core": "log4j", "log4j-api": "log4j", "@angular/core": "angular",
  "laravel/framework": "laravel", "symfony/symfony": "symfony", "symfony/http-kernel": "symfony", node: "nodejs",
  "struts2-core": "apache-struts", "hibernate-core": "hibernate", next: "nextjs", "@nestjs/core": "nestjs",
  railties: "rails", activerecord: "rails", "kotlin-stdlib": "kotlin", "scala-library": "scala",
  "drupal/core": "drupal", "typo3/cms-core": "typo3", "react-native": "react-native",
  "org.elasticsearch:elasticsearch": "elasticsearch", libssl3: "openssl", "libssl1.1": "openssl", python3: "python",
};

let productsPromise = null;

class LifecycleService {
  constructor() {
    this.overrideCache = null; // from optional /eol-overrides.json
  }

  async loadOverridesOnce() {
    if (this.overrideCache !== null) return this.overrideCache;
    try {
      const res = await fetch(`/eol-overrides.json`, { cache: "no-store" });
      if (!res.ok) throw new Error(String(res.status));
      this.overrideCache = (await res.json()) || {};
    } catch {
      this.overrideCache = {};
    }
    return this.overrideCache;
  }

  async products() {
    if (!productsPromise) {
      // Promise.resolve().then(...) turns a synchronous fetch failure into a handled rejection
      productsPromise = Promise.resolve()
        .then(() => fetch("https://endoflife.date/api/all.json"))
        .then((r) => (r.ok ? r.json() : []))
        .then((list) => new Set(Array.isArray(list) ? list : []))
        .catch(() => new Set());
    }
    return productsPromise;
  }

  async resolveProduct(component, pkgInfo) {
    const names = [pkgInfo?.name, component?.name, pkgInfo?.group && `${pkgInfo.group}:${pkgInfo.name}`]
      .filter(Boolean).map((n) => String(n).toLowerCase());
    for (const n of names) if (ALIASES[n]) return ALIASES[n];
    const known = await this.products();
    return names.find((n) => known.has(n)) || null;
  }

  async queryEolApi(product, version) {
    const key = cacheService.generateKey("eol2", product);
    let rows = cacheService.has(key) ? cacheService.get(key) : null;
    if (!rows) {
      try {
        const res = await fetch(`https://endoflife.date/api/${product}.json`);
        rows = res.ok ? await res.json() : [];
      } catch {
        rows = [];
      }
      if (Array.isArray(rows)) {
        // keep only what we need to stay small in sessionStorage
        rows = rows.map((r) => ({ cycle: r.cycle, eol: r.eol }));
        cacheService.set(key, rows);
      }
    }
    if (!Array.isArray(rows)) return null;
    const v = String(version || "").replace(/^v/, "").split("+")[0];
    // longest matching cycle first ("4.2" before "4")
    const found = [...rows]
      .sort((a, b) => String(b.cycle).length - String(a.cycle).length)
      .find((r) => r.cycle && (v === String(r.cycle) || v.startsWith(String(r.cycle) + ".")));
    if (!found) return null;
    if (found.eol === true) return "Ended (date not published)";
    if (found.eol === false || found.eol == null) return "Not announced";
    const [yyyy, mm, dd] = String(found.eol).split("-");
    return yyyy && mm && dd ? `${dd}-${mm}-${yyyy}` : String(found.eol);
  }

  normalizeGa(group, artifact) {
    return `${group}:${artifact}`.toLowerCase();
  }

  async fetchEol(component, pkgInfo) {
    // 1) Overrides file (for libraries where no public EOL data exists)
    const overrides = await this.loadOverridesOnce();
    if (pkgInfo?.ecosystem === "maven" && pkgInfo.group && pkgInfo.name) {
      const date = overrides?.maven?.[this.normalizeGa(pkgInfo.group, pkgInfo.name)] || null;
      if (date) return date; // expected DD-MM-YYYY in overrides
    }
    // OS packages (deb/rpm/apk) are supported by the distribution, which backports fixes; the
    // upstream product's EOL date does not apply to them.
    if (["deb", "rpm", "apk", "alpm"].includes(pkgInfo?.ecosystem)) return null;
    // 2) endoflife.date
    const product = await this.resolveProduct(component, pkgInfo);
    if (!product) return null;
    return this.queryEolApi(product, pkgInfo?.version || component?.version);
  }
}

export default LifecycleService;

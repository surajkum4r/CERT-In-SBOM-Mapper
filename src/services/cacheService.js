// Centralized cache service for persistent session-wide caching
class CacheService {
  constructor() {
    this.cache = new Map();
    this.sessionStartTime = Date.now();
    this.storageKey = 'cert-in-sbom-cache';
    this.maxCacheAge = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
    this.loadFromStorage();
  }

  // Load cache from localStorage on initialization
  loadFromStorage() {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        const data = JSON.parse(stored);
        const now = Date.now();
        
        // Check if cache is still valid (not expired)
        if (data.timestamp && (now - data.timestamp) < this.maxCacheAge) {
          this.cache = new Map(data.cache || []);
          this.sessionStartTime = data.sessionStartTime || Date.now();
        } else {
          // Cache expired, clear it
          this.clearStorage();
        }
      }
    } catch (error) {
      console.warn('Failed to load cache from storage:', error);
      this.clearStorage();
    }
  }

  // Save cache to localStorage
  saveToStorage() {
    try {
      const data = {
        cache: Array.from(this.cache.entries()),
        timestamp: Date.now(),
        sessionStartTime: this.sessionStartTime
      };
      localStorage.setItem(this.storageKey, JSON.stringify(data));
    } catch (error) {
      console.warn('Failed to save cache to storage:', error);
    }
  }

  // Clear localStorage
  clearStorage() {
    try {
      localStorage.removeItem(this.storageKey);
    } catch (error) {
      console.warn('Failed to clear storage:', error);
    }
  }

  // Generate a cache key for different types of requests
  generateKey(type, ...params) {
    return `${type}:${params.join(':')}`;
  }

  // Get cached data
  get(key) {
    return this.cache.get(key);
  }

  // Set cached data
  set(key, value) {
    this.cache.set(key, value);
    this.saveToStorage(); // Persist to localStorage
  }

  // Check if key exists in cache
  has(key) {
    return this.cache.has(key);
  }

  // Clear all cache
  clear() {
    this.cache.clear();
    this.sessionStartTime = Date.now();
    this.clearStorage();
  }

  // Get cache statistics
  getStats() {
    return {
      size: this.cache.size,
      sessionDuration: Date.now() - this.sessionStartTime,
      keys: Array.from(this.cache.keys())
    };
  }

  // Force clear cache and storage (useful for debugging or manual cache reset)
  forceClear() {
    this.cache.clear();
    this.sessionStartTime = Date.now();
    this.clearStorage();
    console.log('Cache forcefully cleared');
  }

  // Get cache info for debugging
  getCacheInfo() {
    const stats = this.getStats();
    return {
      ...stats,
      isPersistent: true,
      maxAge: this.maxCacheAge,
      storageKey: this.storageKey
    };
  }

  // Generate checksum for component data
  generateComponentChecksum(component, sbomVulnerabilities = []) {
    // Create a stable string representation of the component and vulnerabilities
    const componentData = {
      name: component.name,
      version: component.version,
      purl: component.purl,
      group: component.group,
      externalReferences: component.externalReferences,
      // Include relevant vulnerability data that affects the result
      vulnerabilities: sbomVulnerabilities.filter(v => 
        v.affects && v.affects.some(a => a.ref === (component["bom-ref"] || component.bomRef))
      )
    };
    
    // Create a deterministic string
    const dataString = JSON.stringify(componentData, Object.keys(componentData).sort());
    
    // Simple hash function (you could use crypto.subtle for production)
    let hash = 0;
    for (let i = 0; i < dataString.length; i++) {
      const char = dataString.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return `component:${Math.abs(hash).toString(36)}`;
  }

  // Cache component result with checksum
  setComponentResult(component, sbomVulnerabilities, result) {
    const checksum = this.generateComponentChecksum(component, sbomVulnerabilities);
    this.set(checksum, result);
    return checksum;
  }

  // Get cached component result
  getComponentResult(component, sbomVulnerabilities) {
    const checksum = this.generateComponentChecksum(component, sbomVulnerabilities);
    return this.get(checksum);
  }

  // Check if component result is cached
  hasComponentResult(component, sbomVulnerabilities) {
    const checksum = this.generateComponentChecksum(component, sbomVulnerabilities);
    return this.has(checksum);
  }

  // Get checksum cache statistics
  getChecksumCacheStats() {
    const allKeys = Array.from(this.cache.keys());
    const componentKeys = allKeys.filter(key => key.startsWith('component:'));
    const fileKeys = allKeys.filter(key => key.startsWith('file:'));
    return {
      totalComponentResults: componentKeys.length,
      totalFileResults: fileKeys.length,
      componentKeys: componentKeys.slice(0, 10), // Show first 10 for debugging
      totalCacheSize: this.cache.size
    };
  }

  // Generate checksum for entire SBOM file
  generateFileChecksum(sbomData) {
    // Create a stable representation of the entire SBOM
    const fileData = {
      components: sbomData.components?.map(c => ({
        name: c.name,
        version: c.version,
        purl: c.purl,
        group: c.group,
        externalReferences: c.externalReferences,
        bomRef: c["bom-ref"] || c.bomRef
      })) || [],
      vulnerabilities: sbomData.vulnerabilities || [],
      metadata: {
        timestamp: sbomData.metadata?.timestamp,
        version: sbomData.metadata?.version
      }
    };
    
    // Create deterministic string
    const dataString = JSON.stringify(fileData, Object.keys(fileData).sort());
    
    // Generate hash
    let hash = 0;
    for (let i = 0; i < dataString.length; i++) {
      const char = dataString.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return `file:${Math.abs(hash).toString(36)}`;
  }

  // Cache entire SBOM processing result
  setFileResult(sbomData, processedComponents) {
    const checksum = this.generateFileChecksum(sbomData);
    this.set(checksum, processedComponents);
    return checksum;
  }

  // Get cached SBOM processing result
  getFileResult(sbomData) {
    const checksum = this.generateFileChecksum(sbomData);
    return this.get(checksum);
  }

  // Check if SBOM processing result is cached
  hasFileResult(sbomData) {
    const checksum = this.generateFileChecksum(sbomData);
    return this.has(checksum);
  }

  // Cache with TTL (Time To Live) - optional feature for future use
  setWithTTL(key, value, ttlMs = 0) {
    const entry = {
      value,
      timestamp: Date.now(),
      ttl: ttlMs
    };
    this.cache.set(key, entry);
    this.saveToStorage(); // Persist to localStorage
  }

  // Get with TTL check
  getWithTTL(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    
    if (entry.ttl > 0 && (Date.now() - entry.timestamp) > entry.ttl) {
      this.cache.delete(key);
      this.saveToStorage(); // Persist deletion to localStorage
      return null;
    }
    
    return entry.value;
  }
}

// Create a singleton instance
const cacheService = new CacheService();

export default cacheService;

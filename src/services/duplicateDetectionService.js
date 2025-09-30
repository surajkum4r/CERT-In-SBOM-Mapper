class DuplicateDetectionService {
  constructor() {
    this.detectionMethods = {
      exact: 'Exact Match',
      nameVersion: 'Name + Version',
      purl: 'PURL Match',
      hash: 'Hash Match'
    };
  }




  // Extract PURL from component
  extractPurl(component) {
    if (component.purl) return component.purl;
    
    // Look for PURL in properties
    if (component.properties) {
      const purlProperty = component.properties.find(p => 
        p.name === 'purl' || p.name === 'PURL' || p.name === 'Package URL'
      );
      if (purlProperty) return purlProperty.value;
    }
    
    return null;
  }

  // Extract hashes from component
  extractHashes(component) {
    const hashes = [];
    
    if (component.hashes) {
      component.hashes.forEach(hash => {
        hashes.push(`${hash.alg}:${hash.content}`);
      });
    }
    
    // Look for hashes in properties
    if (component.properties) {
      component.properties.forEach(prop => {
        if (prop.name.toLowerCase().includes('hash') || 
            prop.name.toLowerCase().includes('sha') ||
            prop.name.toLowerCase().includes('md5')) {
          hashes.push(`${prop.name}:${prop.value}`);
        }
      });
    }
    
    return hashes;
  }

  // Detect exact duplicates
  detectExactDuplicates(components) {
    const duplicates = [];
    const processed = new Set();
    
    for (let i = 0; i < components.length; i++) {
      if (processed.has(i)) continue;
      
      const group = [i];
      const component1 = components[i];
      
      for (let j = i + 1; j < components.length; j++) {
        if (processed.has(j)) continue;
        
        const component2 = components[j];
        
        if (this.isExactMatch(component1, component2)) {
          group.push(j);
          processed.add(j);
        }
      }
      
      if (group.length > 1) {
        duplicates.push({
          type: 'exact',
          method: this.detectionMethods.exact,
          components: group.map(idx => ({ index: idx, component: components[idx] })),
          confidence: 1.0
        });
        processed.add(i);
      }
    }
    
    return duplicates;
  }

  // Check if two components are exact matches
  isExactMatch(comp1, comp2) {
    return comp1.name === comp2.name &&
           comp1.version === comp2.version &&
           comp1.type === comp2.type;
  }




  // Detect duplicates by name and version
  detectNameVersionDuplicates(components) {
    const duplicates = [];
    const nameVersionMap = new Map();
    
    components.forEach((component, index) => {
      const key = `${component.name || ''}::${component.version || ''}`;
      
      if (!nameVersionMap.has(key)) {
        nameVersionMap.set(key, []);
      }
      nameVersionMap.get(key).push({ index, component });
    });
    
    nameVersionMap.forEach((group, key) => {
      if (group.length > 1) {
        duplicates.push({
          type: 'nameVersion',
          method: this.detectionMethods.nameVersion,
          components: group,
          confidence: 1.0,
          key: key
        });
      }
    });
    
    return duplicates;
  }

  // Detect duplicates by PURL
  detectPurlDuplicates(components) {
    const duplicates = [];
    const purlMap = new Map();
    
    components.forEach((component, index) => {
      const purl = this.extractPurl(component);
      if (purl) {
        if (!purlMap.has(purl)) {
          purlMap.set(purl, []);
        }
        purlMap.get(purl).push({ index, component });
      }
    });
    
    purlMap.forEach((group, purl) => {
      if (group.length > 1) {
        duplicates.push({
          type: 'purl',
          method: this.detectionMethods.purl,
          components: group,
          confidence: 1.0,
          purl: purl
        });
      }
    });
    
    return duplicates;
  }

  // Detect duplicates by hash
  detectHashDuplicates(components) {
    const duplicates = [];
    const hashMap = new Map();
    
    components.forEach((component, index) => {
      const hashes = this.extractHashes(component);
      hashes.forEach(hash => {
        if (!hashMap.has(hash)) {
          hashMap.set(hash, []);
        }
        hashMap.get(hash).push({ index, component });
      });
    });
    
    hashMap.forEach((group, hash) => {
      if (group.length > 1) {
        duplicates.push({
          type: 'hash',
          method: this.detectionMethods.hash,
          components: group,
          confidence: 1.0,
          hash: hash
        });
      }
    });
    
    return duplicates;
  }

  // Main duplicate detection function
  detectDuplicates(components, options = {}) {
    const {
      methods = ['exact', 'nameVersion', 'purl', 'fuzzy'],
      fuzzyThreshold = 0.8,
      includeConfidence = true
    } = options;

    const allDuplicates = [];
    
    if (methods.includes('exact')) {
      allDuplicates.push(...this.detectExactDuplicates(components));
    }
    
    if (methods.includes('nameVersion')) {
      allDuplicates.push(...this.detectNameVersionDuplicates(components));
    }
    
    if (methods.includes('purl')) {
      allDuplicates.push(...this.detectPurlDuplicates(components));
    }
    
    if (methods.includes('hash')) {
      allDuplicates.push(...this.detectHashDuplicates(components));
    }
    

    // Remove overlapping duplicates
    const uniqueDuplicates = this.removeOverlappingDuplicates(allDuplicates);
    
    // Sort by confidence and component count
    return uniqueDuplicates.sort((a, b) => {
      if (a.confidence !== b.confidence) {
        return b.confidence - a.confidence;
      }
      return b.components.length - a.components.length;
    });
  }

  // Remove overlapping duplicate groups
  removeOverlappingDuplicates(duplicates) {
    const uniqueDuplicates = [];
    const processedIndices = new Set();
    
    duplicates.forEach(duplicate => {
      const indices = duplicate.components.map(c => c.index);
      const hasOverlap = indices.some(idx => processedIndices.has(idx));
      
      if (!hasOverlap) {
        uniqueDuplicates.push(duplicate);
        indices.forEach(idx => processedIndices.add(idx));
      }
    });
    
    return uniqueDuplicates;
  }

  // Get duplicate statistics
  getDuplicateStats(duplicates) {
    const totalDuplicates = duplicates.length;
    const totalComponents = duplicates.reduce((sum, dup) => sum + dup.components.length, 0);
    const duplicateComponents = new Set();
    
    duplicates.forEach(duplicate => {
      duplicate.components.forEach(comp => {
        duplicateComponents.add(comp.index);
      });
    });
    
    return {
      totalGroups: totalDuplicates,
      totalComponents: totalComponents,
      uniqueDuplicateComponents: duplicateComponents.size,
      methods: [...new Set(duplicates.map(d => d.method))],
      averageConfidence: duplicates.length > 0 ? 
        duplicates.reduce((sum, d) => sum + d.confidence, 0) / duplicates.length : 0
    };
  }

  // Merge duplicate components
  mergeDuplicates(components, duplicateGroup, mergeStrategy = 'keepFirst') {
    if (duplicateGroup.components.length < 2) return components;
    
    const indices = duplicateGroup.components.map(c => c.index).sort((a, b) => a - b);
    const componentsToMerge = indices.map(idx => components[idx]);
    
    let mergedComponent;
    
    switch (mergeStrategy) {
      case 'keepFirst':
        mergedComponent = { ...componentsToMerge[0] };
        break;
      case 'keepLast':
        mergedComponent = { ...componentsToMerge[componentsToMerge.length - 1] };
        break;
      case 'mergeProperties':
        mergedComponent = this.mergeComponentProperties(componentsToMerge);
        break;
      default:
        mergedComponent = { ...componentsToMerge[0] };
    }
    
    // Create new components array
    const newComponents = [...components];
    
    // Remove all duplicate components
    indices.reverse().forEach(idx => {
      newComponents.splice(idx, 1);
    });
    
    // Add merged component
    newComponents.push(mergedComponent);
    
    return newComponents;
  }

  // Merge properties from multiple components
  mergeComponentProperties(components) {
    const merged = { ...components[0] };
    
    // Merge properties arrays
    const allProperties = [];
    components.forEach(comp => {
      if (comp.properties) {
        allProperties.push(...comp.properties);
      }
    });
    
    // Remove duplicate properties
    const uniqueProperties = [];
    const seenProperties = new Set();
    
    allProperties.forEach(prop => {
      const key = `${prop.name}:${prop.value}`;
      if (!seenProperties.has(key)) {
        uniqueProperties.push(prop);
        seenProperties.add(key);
      }
    });
    
    merged.properties = uniqueProperties;
    
    // Merge vulnerabilities
    const allVulnerabilities = [];
    components.forEach(comp => {
      if (comp.vulnerabilities) {
        allVulnerabilities.push(...comp.vulnerabilities);
      }
    });
    
    merged.vulnerabilities = [...new Set(allVulnerabilities)];
    
    return merged;
  }
}

export default DuplicateDetectionService;

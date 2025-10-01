class DuplicateDetectionService {
  constructor() {
    this.detectionMethods = {
      exact: 'Exact Match'
    };
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





  // Main duplicate detection function
  detectDuplicates(components, options = {}) {
    // Only use exact match detection
    const allDuplicates = this.detectExactDuplicates(components);
    
    // Sort by confidence and component count
    return allDuplicates.sort((a, b) => {
      if (a.confidence !== b.confidence) {
        return b.confidence - a.confidence;
      }
      return b.components.length - a.components.length;
    });
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

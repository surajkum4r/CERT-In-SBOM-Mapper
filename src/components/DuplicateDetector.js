import React, { useState, useEffect } from 'react';
import DuplicateDetectionService from '../services/duplicateDetectionService';
import '../styles/components/DuplicateDetector.css';

const DuplicateDetector = ({ components, onBackToTable, onComponentsUpdate, onDuplicateCountChange }) => {
  const [duplicates, setDuplicates] = useState([]);
  const [stats, setStats] = useState(null);
  const [isDetecting, setIsDetecting] = useState(false);
  const [selectedDuplicates, setSelectedDuplicates] = useState(new Set());
  const [selectedComponents, setSelectedComponents] = useState(new Map()); // Map of duplicateIndex -> Set of component indices
  const [isProcessing, setIsProcessing] = useState(false);

  const duplicateService = new DuplicateDetectionService();

  useEffect(() => {
    if (components && components.length > 0) {
      detectDuplicates();
    }
  }, [components]);

  const detectDuplicates = async () => {
    if (!components || components.length === 0) return;

    setIsDetecting(true);
    try {
      const detectedDuplicates = duplicateService.detectDuplicates(components);
      const duplicateStats = duplicateService.getDuplicateStats(detectedDuplicates);
      
      setDuplicates(detectedDuplicates);
      setStats(duplicateStats);
      
      // Notify parent about duplicate count change
      if (onDuplicateCountChange) {
        onDuplicateCountChange(detectedDuplicates.length);
      }
    } catch (error) {
      console.error('Duplicate detection error:', error);
    } finally {
      setIsDetecting(false);
    }
  };



  const toggleDuplicateSelection = (duplicateIndex) => {
    const newSelected = new Set(selectedDuplicates);
    if (newSelected.has(duplicateIndex)) {
      newSelected.delete(duplicateIndex);
    } else {
      newSelected.add(duplicateIndex);
    }
    setSelectedDuplicates(newSelected);
  };


  const clearGroupSelection = (duplicateIndex) => {
    setSelectedComponents(prev => {
      const newMap = new Map(prev);
      newMap.delete(duplicateIndex);
      return newMap;
    });
  };

  const toggleComponentSelection = (duplicateIndex, componentIndex) => {
    setSelectedComponents(prev => {
      const newMap = new Map(prev);
      if (!newMap.has(duplicateIndex)) {
        newMap.set(duplicateIndex, new Set());
      }
      const componentSet = new Set(newMap.get(duplicateIndex));
      if (componentSet.has(componentIndex)) {
        componentSet.delete(componentIndex);
      } else {
        componentSet.add(componentIndex);
      }
      newMap.set(duplicateIndex, componentSet);
      return newMap;
    });
  };


  const isAllComponentsSelected = (duplicateIndex) => {
    const duplicate = duplicates[duplicateIndex];
    const selectedSet = selectedComponents.get(duplicateIndex) || new Set();
    return duplicate.components.every(comp => selectedSet.has(comp.index));
  };

  const hasAnyComponentsSelected = (duplicateIndex) => {
    const duplicate = duplicates[duplicateIndex];
    const selectedSet = selectedComponents.get(duplicateIndex) || new Set();
    return duplicate.components.some(comp => selectedSet.has(comp.index));
  };

  const toggleAllComponentsInGroup = (duplicateIndex) => {
    const duplicate = duplicates[duplicateIndex];
    const allIndices = duplicate.components.map(comp => comp.index);
    const selectedSet = selectedComponents.get(duplicateIndex) || new Set();
    
    setSelectedComponents(prev => {
      const newMap = new Map(prev);
      if (isAllComponentsSelected(duplicateIndex)) {
        // If all are selected, deselect all
        newMap.set(duplicateIndex, new Set());
      } else {
        // If not all are selected, select all
        newMap.set(duplicateIndex, new Set(allIndices));
      }
      return newMap;
    });
  };

  const handleMergeSingleGroup = async (duplicateIndex) => {
    setIsProcessing(true);
    try {
      let updatedComponents = [...components];
      const duplicate = duplicates[duplicateIndex];
      const selectedComponentIndices = selectedComponents.get(duplicateIndex) || new Set();
      
      // If no components selected, keep first one by default
      if (selectedComponentIndices.size === 0) {
        selectedComponentIndices.add(duplicate.components[0].index);
      }
      
      // Create custom merge with selected components
      updatedComponents = mergeSelectedComponents(
        updatedComponents, 
        duplicate, 
        selectedComponentIndices
      );

      onComponentsUpdate(updatedComponents);
      setSelectedDuplicates(new Set());
      setSelectedComponents(new Map());
      
      // Update local state and re-detect duplicates immediately
      setDuplicates([]); // Clear current duplicates
      setStats(null); // Clear stats
      
      // Re-detect duplicates with updated components
      setTimeout(() => {
        // Use the updated components for detection
        const updatedDuplicates = duplicateService.detectDuplicates(updatedComponents);
        const duplicateStats = duplicateService.getDuplicateStats(updatedDuplicates);
        
        setDuplicates(updatedDuplicates);
        setStats(duplicateStats);
        
        // Notify parent about duplicate count change
        if (onDuplicateCountChange) {
          onDuplicateCountChange(updatedDuplicates.length);
        }
      }, 100);
      
    } catch (error) {
      console.error('Merge error:', error);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleRemoveSingleGroup = async (duplicateIndex) => {
    setIsProcessing(true);
    try {
      let updatedComponents = [...components];
      const duplicate = duplicates[duplicateIndex];
      const selectedComponentIndices = selectedComponents.get(duplicateIndex) || new Set();
      
      // If no components selected, remove all by default
      if (selectedComponentIndices.size === 0) {
        duplicate.components.forEach(comp => {
          const indexToRemove = updatedComponents.findIndex(c => c === comp.component);
          if (indexToRemove !== -1) {
            updatedComponents.splice(indexToRemove, 1);
          }
        });
      } else {
        // Remove only selected components
        const indicesToRemove = Array.from(selectedComponentIndices).sort((a, b) => b - a);
        indicesToRemove.forEach(index => {
          updatedComponents.splice(index, 1);
        });
      }

      onComponentsUpdate(updatedComponents);
      setSelectedDuplicates(new Set());
      setSelectedComponents(new Map());
      
      // Update local state and re-detect duplicates immediately
      setDuplicates([]); // Clear current duplicates
      setStats(null); // Clear stats
      
      // Re-detect duplicates with updated components
      setTimeout(() => {
        // Use the updated components for detection
        const updatedDuplicates = duplicateService.detectDuplicates(updatedComponents);
        const duplicateStats = duplicateService.getDuplicateStats(updatedDuplicates);
        
        setDuplicates(updatedDuplicates);
        setStats(duplicateStats);
        
        // Notify parent about duplicate count change
        if (onDuplicateCountChange) {
          onDuplicateCountChange(updatedDuplicates.length);
        }
      }, 100);
      
    } catch (error) {
      console.error('Remove error:', error);
    } finally {
      setIsProcessing(false);
    }
  };


  // Merge selected components into one
  const mergeSelectedComponents = (components, duplicate, selectedIndices) => {
    if (selectedIndices.size === 0) return components;
    
    const indices = Array.from(selectedIndices).sort((a, b) => a - b);
    const componentsToMerge = indices.map(idx => components[idx]);
    
    // Merge properties from selected components
    const mergedComponent = mergeComponentProperties(componentsToMerge);
    
    // Create new components array
    const newComponents = [...components];
    
    // Remove all selected components
    indices.reverse().forEach(idx => {
      newComponents.splice(idx, 1);
    });
    
    // Add merged component
    newComponents.push(mergedComponent);
    
    return newComponents;
  };

  // Merge properties from multiple components
  const mergeComponentProperties = (components) => {
    const merged = { ...components[0] };
    
    // Merge properties array
    if (merged.properties) {
      const allProperties = components.flatMap(comp => comp.properties || []);
      const uniqueProperties = [];
      const seen = new Set();
      
      allProperties.forEach(prop => {
        const key = `${prop.name}:${prop.value}`;
        if (!seen.has(key)) {
          seen.add(key);
          uniqueProperties.push(prop);
        }
      });
      
      merged.properties = uniqueProperties;
    }
    
    // Merge other arrays
    ['licenses', 'hashes', 'externalReferences'].forEach(field => {
      if (merged[field]) {
        const allItems = components.flatMap(comp => comp[field] || []);
        const uniqueItems = [];
        const seen = new Set();
        
        allItems.forEach(item => {
          const key = JSON.stringify(item);
          if (!seen.has(key)) {
            seen.add(key);
            uniqueItems.push(item);
          }
        });
        
        merged[field] = uniqueItems;
      }
    });
    
    return merged;
  };

  const getConfidenceColor = (confidence) => {
    if (confidence >= 0.9) return '#28a745';
    if (confidence >= 0.7) return '#ffc107';
    return '#dc3545';
  };

  const getConfidenceText = (confidence) => {
    if (confidence >= 0.9) return 'High';
    if (confidence >= 0.7) return 'Medium';
    return 'Low';
  };

  const getMethodIcon = (method) => {
    switch (method) {
      case 'Exact Match': return '🎯';
      case 'Fuzzy Match': return '🔍';
      case 'Name + Version': return '📝';
      case 'PURL Match': return '🔗';
      case 'Hash Match': return '🔐';
      default: return '❓';
    }
  };

  const getMethodColor = (method) => {
    switch (method) {
      case 'Exact Match': return '#28a745';
      case 'Fuzzy Match': return '#ffc107';
      case 'Name + Version': return '#17a2b8';
      case 'PURL Match': return '#6f42c1';
      case 'Hash Match': return '#fd7e14';
      default: return '#6c757d';
    }
  };

  return (
    <div className="duplicate-detector">
      <div className="detector-header">
        <h2>🔍 Duplicate Detection</h2>
        <button onClick={onBackToTable} className="btn btn-secondary">
          ← Back to Components
        </button>
      </div>

      {/* Detection Options */}
      <div className="detection-options">
        <button 
          onClick={detectDuplicates} 
          className="btn btn-primary"
          disabled={isDetecting}
        >
          {isDetecting ? 'Detecting...' : '🔍 Detect Duplicates'}
        </button>
      </div>

      {/* Statistics */}
      {stats && (
        <div className="duplicate-stats">
          <h3>Detection Results</h3>
          <div className="stats-grid">
            <div className="stat-item">
              <span className="stat-value">{stats.totalGroups}</span>
              <span className="stat-label">Duplicate Groups</span>
            </div>
            <div className="stat-item">
              <span className="stat-value">{stats.uniqueDuplicateComponents}</span>
              <span className="stat-label">Components with Duplicates</span>
            </div>
            <div className="stat-item">
              <span className="stat-value">{Math.round(stats.averageConfidence * 100)}%</span>
              <span className="stat-label">Average Confidence</span>
            </div>
            <div className="stat-item">
              <span className="stat-value">{stats.methods.length}</span>
              <span className="stat-label">Detection Methods</span>
            </div>
          </div>
        </div>
      )}

      {/* Duplicates List */}
      {duplicates.length > 0 && (
        <div className="duplicates-section">
          <div className="duplicates-header">
            <h3>Detected Duplicates ({duplicates.length})</h3>
          </div>

          <div className="duplicates-list">
            {duplicates.map((duplicate, index) => (
              <div 
                key={index} 
                className={`duplicate-group ${selectedDuplicates.has(index) ? 'selected' : ''}`}
                onClick={() => toggleDuplicateSelection(index)}
              >
                <div className="duplicate-header">
                  <div className="duplicate-info">
                    <div className="duplicate-method-badge" style={{ backgroundColor: getMethodColor(duplicate.method) }}>
                      <span className="method-icon">{getMethodIcon(duplicate.method)}</span>
                      <span className="method-text">{duplicate.method}</span>
                    </div>
                    <div className="duplicate-meta">
                      <span 
                        className="duplicate-confidence"
                        style={{ color: getConfidenceColor(duplicate.confidence) }}
                      >
                        {getConfidenceText(duplicate.confidence)} ({Math.round(duplicate.confidence * 100)}%)
                      </span>
                      <span className="duplicate-count">
                        {duplicate.components.length} components
                      </span>
                    </div>
                  </div>
                </div>

                <div className="duplicate-components">
                  <div className="master-selection-control">
                    <div className="master-checkbox-section">
                      <input
                        type="checkbox"
                        checked={isAllComponentsSelected(index)}
                        onChange={() => toggleAllComponentsInGroup(index)}
                        onClick={(e) => e.stopPropagation()}
                        title="Select all components in this group"
                      />
                    </div>
                    <div className="group-actions">
                      <button 
                        onClick={() => clearGroupSelection(index)}
                        disabled={!hasAnyComponentsSelected(index)}
                        className="btn btn-sm btn-secondary"
                        title="Clear selection for this group"
                      >
                        Clear
                      </button>
                      <button 
                        onClick={() => handleMergeSingleGroup(index)}
                        disabled={!hasAnyComponentsSelected(index) || isProcessing}
                        className="btn btn-sm btn-success"
                        title="Merge selected components in this group"
                      >
                        {isProcessing ? 'Processing...' : 'Merge'}
                      </button>
                      <button 
                        onClick={() => handleRemoveSingleGroup(index)}
                        disabled={!hasAnyComponentsSelected(index) || isProcessing}
                        className="btn btn-sm btn-danger"
                        title="Remove selected components in this group"
                      >
                        {isProcessing ? 'Processing...' : 'Remove'}
                      </button>
                    </div>
                  </div>
                  {duplicate.components.map((comp, compIndex) => {
                    const isSelected = selectedComponents.get(index)?.has(comp.index) || false;
                    return (
                      <div key={compIndex} className={`duplicate-component ${isSelected ? 'selected' : ''}`}>
                        <div className="component-checkbox">
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => toggleComponentSelection(index, comp.index)}
                            onClick={(e) => e.stopPropagation()}
                          />
                        </div>
                        <div className="component-info">
                          <strong>{comp.component.name || 'Unnamed'}</strong>
                          <span className="component-version">{comp.component.version || 'No version'}</span>
                          <span className="component-type">{comp.component.type || 'Unknown'}</span>
                        </div>
                      <div className="component-details">
                        {comp.component.description && (
                          <div className="component-description">
                            {comp.component.description.length > 100 
                              ? `${comp.component.description.substring(0, 100)}...`
                              : comp.component.description
                            }
                          </div>
                        )}
                        {duplicate.purl && (
                          <div className="component-purl">
                            <strong>PURL:</strong> {duplicate.purl}
                          </div>
                        )}
                        {duplicate.hash && (
                          <div className="component-hash">
                            <strong>Hash:</strong> {duplicate.hash}
                          </div>
                        )}
                      </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {duplicates.length === 0 && !isDetecting && (
        <div className="no-duplicates">
          <h3>✅ No Duplicates Found</h3>
          <p>All components appear to be unique based on the selected detection methods.</p>
        </div>
      )}
    </div>
  );
};

export default DuplicateDetector;

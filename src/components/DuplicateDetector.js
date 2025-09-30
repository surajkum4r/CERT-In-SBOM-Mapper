import React, { useState, useEffect } from 'react';
import DuplicateDetectionService from '../services/duplicateDetectionService';
import '../styles/components/DuplicateDetector.css';

const DuplicateDetector = ({ components, onBackToTable, onComponentsUpdate, onDuplicateCountChange }) => {
  const [duplicates, setDuplicates] = useState([]);
  const [stats, setStats] = useState(null);
  const [isDetecting, setIsDetecting] = useState(false);
  const [detectionOptions, setDetectionOptions] = useState({
    methods: ['exact', 'nameVersion', 'purl'],
    includeConfidence: true
  });
  const [selectedDuplicates, setSelectedDuplicates] = useState(new Set());
  const [mergeStrategy, setMergeStrategy] = useState('keepFirst');
  const [isProcessing, setIsProcessing] = useState(false);

  const duplicateService = new DuplicateDetectionService();

  useEffect(() => {
    if (components && components.length > 0) {
      detectDuplicates();
    }
  }, [components, detectionOptions]);

  const detectDuplicates = async () => {
    if (!components || components.length === 0) return;

    setIsDetecting(true);
    try {
      const detectedDuplicates = duplicateService.detectDuplicates(components, detectionOptions);
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

  const handleMethodToggle = (method) => {
    setDetectionOptions(prev => ({
      ...prev,
      methods: prev.methods.includes(method)
        ? prev.methods.filter(m => m !== method)
        : [...prev.methods, method]
    }));
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

  const selectAllDuplicates = () => {
    setSelectedDuplicates(new Set(duplicates.map((_, index) => index)));
  };

  const clearSelection = () => {
    setSelectedDuplicates(new Set());
  };

  const handleMergeSelected = async () => {
    if (selectedDuplicates.size === 0) return;

    setIsProcessing(true);
    try {
      let updatedComponents = [...components];
      const sortedIndices = Array.from(selectedDuplicates).sort((a, b) => b - a);

      // Process duplicates in reverse order to maintain indices
      for (const duplicateIndex of sortedIndices) {
        const duplicate = duplicates[duplicateIndex];
        updatedComponents = duplicateService.mergeDuplicates(
          updatedComponents, 
          duplicate, 
          mergeStrategy
        );
      }

      onComponentsUpdate(updatedComponents);
      setSelectedDuplicates(new Set());
      
      // Re-detect duplicates with updated components
      setTimeout(() => {
        detectDuplicates();
      }, 100);
      
    } catch (error) {
      console.error('Merge error:', error);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleRemoveSelected = async () => {
    if (selectedDuplicates.size === 0) return;

    setIsProcessing(true);
    try {
      let updatedComponents = [...components];
      const indicesToRemove = new Set();

      // Collect all component indices to remove
      selectedDuplicates.forEach(duplicateIndex => {
        const duplicate = duplicates[duplicateIndex];
        duplicate.components.forEach(comp => {
          indicesToRemove.add(comp.index);
        });
      });

      // Remove components in reverse order
      const sortedIndices = Array.from(indicesToRemove).sort((a, b) => b - a);
      sortedIndices.forEach(index => {
        updatedComponents.splice(index, 1);
      });

      onComponentsUpdate(updatedComponents);
      setSelectedDuplicates(new Set());
      
      // Re-detect duplicates with updated components
      setTimeout(() => {
        detectDuplicates();
      }, 100);
      
    } catch (error) {
      console.error('Remove error:', error);
    } finally {
      setIsProcessing(false);
    }
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
        <h3>Detection Methods</h3>
        <div className="method-options">
          {Object.entries(duplicateService.detectionMethods).map(([key, label]) => (
            <label key={key} className="method-option">
              <input
                type="checkbox"
                checked={detectionOptions.methods.includes(key)}
                onChange={() => handleMethodToggle(key)}
                disabled={isDetecting}
              />
              <span>{label}</span>
            </label>
          ))}
        </div>


        <button 
          onClick={detectDuplicates} 
          className="btn btn-primary"
          disabled={isDetecting || detectionOptions.methods.length === 0}
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
            <div className="bulk-actions">
              <button onClick={selectAllDuplicates} className="btn btn-sm btn-secondary">
                Select All
              </button>
              <button onClick={clearSelection} className="btn btn-sm btn-secondary">
                Clear Selection
              </button>
              <select 
                value={mergeStrategy} 
                onChange={(e) => setMergeStrategy(e.target.value)}
                className="merge-strategy-select"
              >
                <option value="keepFirst">Keep First</option>
                <option value="keepLast">Keep Last</option>
                <option value="mergeProperties">Merge Properties</option>
              </select>
              <button 
                onClick={handleMergeSelected}
                disabled={selectedDuplicates.size === 0 || isProcessing}
                className="btn btn-sm btn-success"
              >
                {isProcessing ? 'Processing...' : `Merge Selected (${selectedDuplicates.size})`}
              </button>
              <button 
                onClick={handleRemoveSelected}
                disabled={selectedDuplicates.size === 0 || isProcessing}
                className="btn btn-sm btn-danger"
              >
                {isProcessing ? 'Processing...' : `Remove Selected (${selectedDuplicates.size})`}
              </button>
            </div>
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
                  <input 
                    type="checkbox" 
                    checked={selectedDuplicates.has(index)}
                    onChange={() => toggleDuplicateSelection(index)}
                    onClick={(e) => e.stopPropagation()}
                  />
                </div>

                <div className="duplicate-components">
                  {duplicate.components.map((comp, compIndex) => (
                    <div key={compIndex} className="duplicate-component">
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
                  ))}
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

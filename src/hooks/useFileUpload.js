import { useState } from 'react';
import errorService from '../services/errorService';
import cacheService from '../services/cacheService';

export const useFileUpload = ({
  setSbom,
  setComponents,
  setVulnerabilities,
  setSelectedIndex,
  setEditComponent,
  setShowSignatureManager,
  setShowDuplicateDetector,
  setDuplicateCount,
  setTableKey,
  setIsNewUpload,
  setHasModifications,
  setOriginalComponents,
  setDuplicateNotificationShown,
  setNameFilter,
  setShowFilterDropdown,
  setFetchProgress,
  setFetchLabel,
  showNotification,
  checkForDuplicates,
  propertyMapper,
  hasModifications,
  setShowUploadWarning,
}) => {
  const [pendingFile, setPendingFile] = useState(null);

  const processFileUpload = async (file) => {
    try {
      const text = await file.text();
      const json = JSON.parse(text);
      
      if (json.components && Array.isArray(json.components)) {
        const updatedComponents = json.components.map(component => {
          const props = component.properties || [];
          return { ...component, properties: props };
        });
        
        json.components = updatedComponents;
        setSbom(json);
        setComponents(updatedComponents);
        setSelectedIndex(null);
        setEditComponent(null);
        setVulnerabilities(json.vulnerabilities || []);
        
        // Hide signature manager and duplicate detector, show main table
        setShowSignatureManager(false);
        setShowDuplicateDetector(false);
        setDuplicateCount(0);
        
        // Force re-render to update button appearance and table
        setTableKey(prev => prev + 1);
        setIsNewUpload(true);
        
        // Reset new upload state after animation
        setTimeout(() => setIsNewUpload(false), 600);
        
        // Trigger duplicate detection for the new SBOM with updated components
        setTimeout(() => {
          if (updatedComponents && updatedComponents.length > 0) {
            checkForDuplicates(updatedComponents);
          }
        }, 200);
        
        // Clear the file input to allow re-uploading the same file
        const fileInput = document.getElementById('sbomUpload');
        if (fileInput) {
          fileInput.value = '';
        }

        // Background auto-populate of CERT-In properties with visible progress
        (async () => {
          const cacheInfo = cacheService.getCacheInfo();
          setFetchProgress(0);
          setFetchLabel(`Processing components (${cacheInfo.size} cached items available)...`);
          
          // Check if we have cached results for this exact file
          const cachedResult = cacheService.getFileResult(json);
          if (cachedResult) {
            setComponents(cachedResult);
            setOriginalComponents([...cachedResult]);
            setHasModifications(false);
            setSbom((prev) => ({ ...(prev || {}), components: cachedResult }));
            
            setFetchProgress(100);
            
            showNotification(
              `Successfully loaded ${updatedComponents.length} components from cache!`, 
              'success', 
              3000
            );
            
            setTimeout(() => {
              setFetchProgress(null);
              setFetchLabel("");
              // Trigger duplicate detection after cached results are loaded
              if (updatedComponents && updatedComponents.length > 0) {
                checkForDuplicates(updatedComponents);
              }
            }, 600);
            return;
          }
          
          setFetchProgress(10);
          
          // Process all components in parallel since cache makes it fast
          const results = await Promise.all(
            updatedComponents.map((c) =>
              propertyMapper
                .fetchComponentData(c, json.vulnerabilities || [])
                .catch(() => ({}))
            )
          );
          
          const merged = updatedComponents.map((comp, idx) => {
            const result = results[idx];
            return { ...comp, ...result };
          });
          
          setComponents(merged);
          setOriginalComponents([...merged]);
          setHasModifications(false);
          setSbom((prev) => ({ ...(prev || {}), components: merged }));
          
          // Cache the entire processing result for future use
          cacheService.setFileResult(json, merged);
          
          setFetchProgress(100);
          
          showNotification(
            `Successfully processed ${updatedComponents.length} components with CERT-In properties!`, 
            'success', 
            4000
          );
          
          setTimeout(() => {
            setFetchProgress(null);
            setFetchLabel("");
            // Trigger duplicate detection after background processing is complete
            if (updatedComponents && updatedComponents.length > 0) {
              checkForDuplicates(updatedComponents);
            }
          }, 600);
        })();
      } else {
        const errorInfo = errorService.handleSBOMError(
          new Error('No components field'), 
          file.name
        );
        showNotification(errorInfo.message, 'error');
        // Clear input on error
        const fileInput = document.getElementById('sbomUpload');
        if (fileInput) fileInput.value = '';
      }
    } catch (ex) {
      errorService.logError(ex, 'File parsing', { fileName: file.name });
      const errorInfo = errorService.handleSBOMError(ex, file.name);
      showNotification(errorInfo.message, 'error');
      // Clear input on error
      const fileInput = document.getElementById('sbomUpload');
      if (fileInput) fileInput.value = '';
    }
  };

  const handleUploadButtonClick = (e) => {
    // Check for modifications before opening file dialog
    if (hasModifications) {
      e.preventDefault();
      setPendingFile(null);
      setShowUploadWarning(true);
      return;
    }
    
    // If no modifications, proceed with upload
    const fileInput = document.getElementById('sbomUpload');
    if (fileInput) {
      fileInput.click();
    }
  };

  const onFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      if (hasModifications) {
        setPendingFile(file);
        setShowUploadWarning(true);
      } else {
        processFileUpload(file);
      }
    }
  };

  return {
    pendingFile,
    setPendingFile,
    processFileUpload,
    handleUploadButtonClick,
    onFileChange,
  };
};

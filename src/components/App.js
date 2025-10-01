import React, { useState, useEffect } from "react";
import { ComponentEditor } from "./ComponentEditor";
import SignatureManager from "./SignatureManager";
import DuplicateDetector from "./DuplicateDetector";
import ExcelJS from "exceljs";
import { saveAs } from "file-saver";
import { Pencil } from "lucide-react";
import "../styles/components/AppView.css";
import PropertyMapperService from "../services/propertyMapperService";
import StandaloneSignatureService from "../services/standaloneSignatureService";
import PDFExportService from "../services/pdfExportService";
import ProgressBar from "./ProgressBar";
import Notification from "./Notification";
import errorService from "../services/errorService";
import cacheService from "../services/cacheService";
import DuplicateDetectionService from "../services/duplicateDetectionService";

import { CERT_IN_PROPERTIES } from "../constants/appConstants";
import { updateProperty } from "../utils/appUtils";
import ExportDialog from "./dialogs/ExportDialog";

export default function App() {
  const [sbom, setSbom] = useState(null);
  const [components, setComponents] = useState([]);
  const [selectedIndex, setSelectedIndex] = useState(null);
  const [editComponent, setEditComponent] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [propertyMapper] = useState(() => new PropertyMapperService());
  const [fetchProgress, setFetchProgress] = useState(null); // null = idle, 0-100 fetching
  const [fetchLabel, setFetchLabel] = useState("");
  const [notification, setNotification] = useState(null);
  const [tableKey, setTableKey] = useState(0); // Force table re-render
  const [isNewUpload, setIsNewUpload] = useState(false);
  const [isCacheDropdownOpen, setIsCacheDropdownOpen] = useState(false);
  const [showSignatureManager, setShowSignatureManager] = useState(false);
  const [showDuplicateDetector, setShowDuplicateDetector] = useState(false);
  const [duplicateCount, setDuplicateCount] = useState(0);
  const [duplicateNotificationShown, setDuplicateNotificationShown] = useState(false);
  const [showExportDialog, setShowExportDialog] = useState(false);
  const [exportWithSignature, setExportWithSignature] = useState(false);
  const [exportKeyOption, setExportKeyOption] = useState('generate'); // 'generate' or 'upload'
  const [isExporting, setIsExporting] = useState(false);
  const [exportPrivateKeyFile, setExportPrivateKeyFile] = useState(null);
  const [exportPublicKeyFile, setExportPublicKeyFile] = useState(null);
  const [isUploadingKeys, setIsUploadingKeys] = useState(false);
  const [dialogResetKey, setDialogResetKey] = useState(0);
  const [nameFilter, setNameFilter] = useState('');
  const [showFilterDropdown, setShowFilterDropdown] = useState(false);
  const [hasModifications, setHasModifications] = useState(false);
  const [originalComponents, setOriginalComponents] = useState([]);
  const [showUploadWarning, setShowUploadWarning] = useState(false);
  const [pendingFile, setPendingFile] = useState(null);
  const [showRefreshWarning, setShowRefreshWarning] = useState(false);

  // Filter components by name
  const filteredComponents = components.filter(component => {
    if (!nameFilter.trim()) return true;
    return component.name?.toLowerCase().includes(nameFilter.toLowerCase());
  });

  // Track modifications by comparing current components with original
  useEffect(() => {
    if (originalComponents.length > 0 && components.length > 0) {
      const hasChanges = components.some((comp, index) => {
        const original = originalComponents[index];
        if (!original) return false;
        return JSON.stringify(comp) !== JSON.stringify(original);
      });
      setHasModifications(hasChanges);
    } else if (originalComponents.length === 0 && components.length > 0) {
      // If no original components set but we have components, no modifications yet
      setHasModifications(false);
    }
  }, [components, originalComponents]);

  // Page refresh warning - only show custom dialog, no browser warning
  useEffect(() => {
    const handleKeyDown = (event) => {
      
      // Check for F5, Ctrl+R, or Ctrl+Shift+R (refresh shortcuts)
      if (hasModifications && (
        event.key === 'F5' || 
        (event.ctrlKey && event.key === 'r') ||
        (event.ctrlKey && event.shiftKey && event.key === 'R') ||
        (event.ctrlKey && event.key === 'R')
      )) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();
        setShowRefreshWarning(true);
        return false;
      }
    };

    if (hasModifications) {
      // Add keyboard event listener to catch refresh shortcuts
      document.addEventListener('keydown', handleKeyDown, true);
      window.addEventListener('keydown', handleKeyDown, true);
      // Don't add beforeunload - this prevents browser warning
    }

    return () => {
      document.removeEventListener('keydown', handleKeyDown, true);
      window.removeEventListener('keydown', handleKeyDown, true);
    };
  }, [hasModifications]);

  // Handle redirect from signature page
  useEffect(() => {
    // Check if we're being redirected from signature page with a new SBOM
    const redirectFlag = sessionStorage.getItem('sbom_upload_redirect');
    const savedSBOM = sessionStorage.getItem('current_sbom');
    
    if (redirectFlag === 'true' && savedSBOM) {
      try {
        const json = JSON.parse(savedSBOM);
        if (json.components) {
          const updatedComponents = json.components.map((component) => {
            let props = component.properties ? [...component.properties] : [];
            CERT_IN_PROPERTIES.forEach(({ key }) => {
              if (!props.find((p) => p.name === key)) {
                props.push({ name: key, value: "NA" });
              }
            });
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
          
          // Trigger duplicate detection for the new SBOM with updated components
          setTimeout(() => {
            if (updatedComponents && updatedComponents.length > 0) {
              checkForDuplicates(updatedComponents);
            }
          }, 200);
          
          // Reset new upload state after animation
          setTimeout(() => setIsNewUpload(false), 600);
          
          
          // Clear the redirect flag
          sessionStorage.removeItem('sbom_upload_redirect');
          
          showNotification("SBOM loaded successfully! Redirected from signature page.", 'success');
        }
      } catch (error) {
        console.error('Failed to load SBOM from signature page redirect:', error);
        sessionStorage.removeItem('sbom_upload_redirect');
      }
    }
  }, []);

  // Helper functions for notifications
  const showNotification = (message, type = 'error', duration = 5000) => {
    setNotification({ message, type, duration });
  };

  const hideNotification = () => {
    setNotification(null);
  };

  // Cache management functions
  const clearCache = () => {
    cacheService.forceClear();
    showNotification('Cache cleared successfully!', 'success');
  };

  const getCacheInfo = () => {
    const info = cacheService.getCacheInfo();
    const checksumStats = cacheService.getChecksumCacheStats();
    showNotification(
      `Cache: ${info.size} items (${checksumStats.totalFileResults} file results, ${checksumStats.totalComponentResults} component results), ${Math.round(info.sessionDuration / 1000)}s session`, 
      'info', 
      5000
    );
  };

  const toggleCacheDropdown = () => {
    setIsCacheDropdownOpen(!isCacheDropdownOpen);
  };

  // Upload warning dialog handlers
  const confirmUpload = () => {
    setShowUploadWarning(false);
    processFileUpload(pendingFile);
    setPendingFile(null);
    setHasModifications(false); // Reset after new upload
  };

  const cancelUpload = () => {
    setShowUploadWarning(false);
    setPendingFile(null);
    // Reset file input
    const fileInput = document.getElementById('sbomUpload');
    if (fileInput) fileInput.value = '';
  };

  // Refresh warning dialog handlers
  const confirmRefresh = () => {
    setShowRefreshWarning(false);
    setHasModifications(false); // Reset modification flag
    // Allow the page to refresh/close
    window.location.reload();
  };

  const cancelRefresh = () => {
    setShowRefreshWarning(false);
    // Stay on the page
  };

  const handleUploadButtonClick = (e) => {
    
    // Check for modifications before opening file dialog
    if (hasModifications) {
      e.preventDefault();
      e.stopPropagation();
      
      // Create a temporary file input to capture the file when user confirms
      const tempInput = document.createElement('input');
      tempInput.type = 'file';
      tempInput.accept = '.json';
      tempInput.onchange = (event) => {
        const file = event.target.files[0];
        if (file) {
          setPendingFile(file);
          setShowUploadWarning(true);
        }
      };
      tempInput.click();
      return;
    }
    
    // No modifications, allow normal file dialog to open
  };

  const onFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    
    // If we reach here, it means no modifications were detected in handleUploadButtonClick
    // So we can proceed directly with upload
    processFileUpload(file);
  };

  const processFileUpload = (file) => {
    // Validate file type
    if (!file.name.toLowerCase().endsWith('.json')) {
      const errorInfo = errorService.getUserFriendlyMessage(
        new Error('Invalid file type'), 
        'Please upload a JSON file'
      );
      showNotification(errorInfo.message, 'error');
      return;
    }

    // Validate file size (max 10MB)
    const maxSizeInMB = 10;
    const maxSizeInBytes = maxSizeInMB * 1024 * 1024;
    const fileSizeInMB = (file.size / (1024 * 1024)).toFixed(2);
    
    if (file.size > maxSizeInBytes) {
      showNotification(
        `File too large: ${fileSizeInMB}MB exceeds the 10MB limit. Please compress or split your SBOM file.`, 
        'error'
      );
      return;
    }

    // Show file processing notification
    showNotification(`Processing file (${fileSizeInMB}MB)...`, 'info', 3000);
    
    const reader = new FileReader();
    reader.onload = (evt) => {
      try {
        const json = JSON.parse(evt.target.result);
        if (json.components) {
          const updatedComponents = json.components.map((component) => {
            let props = component.properties ? [...component.properties] : [];
            CERT_IN_PROPERTIES.forEach(({ key }) => {
              if (!props.find((p) => p.name === key)) {
                props.push({ name: key, value: "NA" });
              }
            });
            return { ...component, properties: props };
          });
          json.components = updatedComponents;

          setSbom(json);
          setComponents(updatedComponents);
          setSelectedIndex(null);
          setEditComponent(null);
          setVulnerabilities(json.vulnerabilities || []);
          
          // Reset filter when new file is uploaded
          setNameFilter('');
          setShowFilterDropdown(false);
          
          
          // Force re-render to update button appearance
          setTableKey(prev => prev + 1);
          
          // Hide signature manager and duplicate detector, show main table when new file is uploaded
          setShowSignatureManager(false);
          setShowDuplicateDetector(false);
          setDuplicateCount(0);
          
          // Trigger fresh table appearance
          setTableKey(prev => prev + 1);
          setIsNewUpload(true);
          
          // Trigger duplicate detection for the new SBOM with updated components
          setTimeout(() => {
            if (updatedComponents && updatedComponents.length > 0) {
              checkForDuplicates(updatedComponents);
            }
          }, 200);
          
          // Reset new upload state after animation
          setTimeout(() => setIsNewUpload(false), 600);
          
          
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
            
            try {
              // ULTRA-FAST PATH: Check if entire SBOM processing result is cached
              if (cacheService.hasFileResult(json)) {
                setFetchProgress(50);
                setFetchLabel('Loading cached results...');
                
                const cachedResult = cacheService.getFileResult(json);
                setComponents(cachedResult);
                setOriginalComponents([...cachedResult]); // Save original components
                setHasModifications(false); // Reset modification flag
                setSbom((prev) => ({ ...(prev || {}), components: cachedResult }));
                
                setFetchProgress(100);
                
                // Show success notification for cached results
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
              
              setFetchProgress(90);

              // Optimized property merging - much faster
              const merged = updatedComponents.map((c, idx) => {
                const fetched = results[idx] || {};
                const existingProps = Array.isArray(c.properties) ? c.properties : [];
                const newProps = [...existingProps];
                
                // Fast property update without function calls
                CERT_IN_PROPERTIES.forEach(({ key }) => {
                  const val = fetched[key];
                  if (val && val !== "NA") {
                    const existingIdx = newProps.findIndex(p => p.name === key);
                    if (existingIdx >= 0) {
                      newProps[existingIdx] = { name: key, value: String(val) };
                    } else {
                      newProps.push({ name: key, value: String(val) });
                    }
                  }
                });
                
                return { ...c, properties: newProps };
              });
              setComponents(merged);
              setOriginalComponents([...merged]); // Save original components
              setHasModifications(false); // Reset modification flag
              setSbom((prev) => ({ ...(prev || {}), components: merged }));
              
              // Cache the entire processing result for future use
              cacheService.setFileResult(json, merged);
            } catch (err) {
              errorService.logError(err, 'Background auto-fetch');
              const errorInfo = errorService.getUserFriendlyMessage(err, 'Error fetching component data');
              showNotification(errorInfo.message, 'warning');
            } finally {
              // Ensure user can see 100% before hiding
              setFetchProgress(100);
              
              // Show success notification only after processing is 100% complete
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
            }
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
    reader.readAsText(file);
  };

  const selectComponent = (idx) => {
    const c = components[idx];
    setSelectedIndex(idx);
    setEditComponent(JSON.parse(JSON.stringify(c)));
  };

  const updateEditField = (field, value) => {
    setEditComponent((prev) => ({ ...prev, [field]: value }));
  };

  const updateNestedField = (arrayName, idx, key, value) => {
    setEditComponent((prev) => {
      const arrCopy = [...(prev[arrayName] || [])];
      if (!arrCopy[idx]) arrCopy[idx] = {};
      if (key === "license.id") {
        if (!arrCopy[idx].license) arrCopy[idx].license = {};
        arrCopy[idx].license.id = value;
      } else {
        arrCopy[idx][key] = value;
      }
      return { ...prev, [arrayName]: arrCopy };
    });
  };

  const addNestedItem = (arrayName) => {
    setEditComponent((prev) => {
      const arrCopy = [...(prev[arrayName] || [])];
      if (arrayName === "hashes") arrCopy.push({ alg: "", content: "" });
      else if (arrayName === "licenses") arrCopy.push({ license: { id: "" } });
      else if (arrayName === "externalReferences")
        arrCopy.push({ type: "", url: "" });
      return { ...prev, [arrayName]: arrCopy };
    });
  };

  const removeNestedItem = (arrayName, idx) => {
    setEditComponent((prev) => {
      const arrCopy = [...(prev[arrayName] || [])];
      arrCopy.splice(idx, 1);
      return { ...prev, [arrayName]: arrCopy };
    });
  };

  const updatePropertyField = (name, value) => {
    setEditComponent((prev) => {
      const updatedProps = updateProperty(prev.properties, name, value);
      return { ...prev, properties: updatedProps };
    });
  };

  const saveChanges = () => {
    if (selectedIndex === null) return;
    const newComps = [...components];
    newComps[selectedIndex] = editComponent;
    setComponents(newComps);
    setSbom((prev) => ({ ...prev, components: newComps }));
    showNotification("Component updated successfully!", 'success');
    // Modification tracking will be handled by useEffect
  };

  const exportSbom = () => {
    if (!sbom) return;
    // Force dialog reset by incrementing key
    setDialogResetKey(prev => prev + 1);
    setShowExportDialog(true);
  };

  // Reset export states when dialog opens
  useEffect(() => {
    if (showExportDialog) {
      // Reset to default state - as if opening for the first time
      setExportWithSignature(false);
      setExportKeyOption('generate');
      setExportPrivateKeyFile(null);
      setExportPublicKeyFile(null);
      setIsUploadingKeys(false);
      
      // Clear file inputs to remove any selected files
      setTimeout(() => {
        const privateInput = document.getElementById('exportPrivateKeyInput');
        const publicInput = document.getElementById('exportPublicKeyInput');
        if (privateInput) {
          privateInput.value = '';
          privateInput.checked = false;
        }
        if (publicInput) {
          publicInput.value = '';
          publicInput.checked = false;
        }
      }, 0);
    }
  }, [showExportDialog]);

  // Clear file inputs when switching export types or key options
  useEffect(() => {
    if (showExportDialog) {
      clearAllFileStates();
    }
  }, [exportWithSignature, exportKeyOption]);

  const handleExportWithSignature = async () => {
    if (!sbom) return;
    
    setIsExporting(true);
    try {
      const signatureService = new StandaloneSignatureService();
      
      // Generate or upload keys based on selected option
      if (exportKeyOption === 'generate') {
        // Always generate new keys when "Generate new key pair" is selected
        await signatureService.generateAndSaveKeys();
        showNotification("Generated new key pair for signing", 'success');
      } else if (exportKeyOption === 'upload') {
        // Check if files are selected for inline upload
        if (!exportPrivateKeyFile || !exportPublicKeyFile) {
          showNotification("Please select both private and public key files", 'error');
          return;
        }
        // Upload the keys
        const result = await signatureService.uploadKeyPair(exportPrivateKeyFile, exportPublicKeyFile);
        showNotification(result.message, 'success');
      } else {
        showNotification("Please select a key option", 'error');
        return;
      }
      
      // Sign the SBOM
      const result = await signatureService.signSBOM(sbom, 'cyclonedx-sbom-updated.json');
      
      // Store signature file content for potential verification
      sessionStorage.setItem('sbom_signature_file', JSON.stringify(result.signatureFile.content));
      
      // Export the original SBOM (unchanged)
      const dataStr = JSON.stringify(result.sbom, null, 2);
      const blob = new Blob([dataStr], { type: "application/json" });
      saveAs(blob, "cyclonedx-sbom-updated.json");
      
      // Export the signature file
      const signatureStr = JSON.stringify(result.signatureFile.content, null, 2);
      const signatureBlob = new Blob([signatureStr], { type: "application/json" });
      saveAs(signatureBlob, result.signatureFile.filename);
      
      showNotification("SBOM exported with signature successfully!", 'success');
      setShowExportDialog(false);
    } catch (error) {
      showNotification("Failed to export with signature: " + error.message, 'error');
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportWithoutSignature = () => {
    if (!sbom) return;
    
    const dataStr = JSON.stringify(sbom, null, 2);
    const blob = new Blob([dataStr], { type: "application/json" });
    saveAs(blob, "cyclonedx-sbom-updated.json");
    
    showNotification("SBOM exported successfully!", 'success');
    setShowExportDialog(false);
  };

  const cancelExport = () => {
    setShowExportDialog(false);
    // Reset to default state
    setExportWithSignature(false);
    setExportKeyOption('generate');
    setExportPrivateKeyFile(null);
    setExportPublicKeyFile(null);
    setIsUploadingKeys(false);
    // Reset file inputs
    const privateInput = document.getElementById('exportPrivateKeyInput');
    const publicInput = document.getElementById('exportPublicKeyInput');
    if (privateInput) {
      privateInput.value = '';
      privateInput.checked = false;
    }
    if (publicInput) {
      publicInput.value = '';
      publicInput.checked = false;
    }
  };

  // Clear all file-related states and inputs
  const clearAllFileStates = () => {
    setExportPrivateKeyFile(null);
    setExportPublicKeyFile(null);
    setIsUploadingKeys(false);
    
    // Clear file inputs
    setTimeout(() => {
      const privateInput = document.getElementById('exportPrivateKeyInput');
      const publicInput = document.getElementById('exportPublicKeyInput');
      if (privateInput) {
        privateInput.value = '';
        privateInput.checked = false;
      }
      if (publicInput) {
        publicInput.value = '';
        publicInput.checked = false;
      }
    }, 0);
  };

  const handleExportPrivateKeyUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      setExportPrivateKeyFile(file);
    }
  };

  const handleExportPublicKeyUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      setExportPublicKeyFile(file);
    }
  };

  const uploadKeysForExport = async () => {
    if (!exportPrivateKeyFile || !exportPublicKeyFile) {
      showNotification("Please select both private and public key files.", 'error');
      return;
    }

    setIsUploadingKeys(true);
    try {
      const signatureService = new StandaloneSignatureService();
      const result = await signatureService.uploadKeyPair(exportPrivateKeyFile, exportPublicKeyFile);
      showNotification(result.message, 'success');
      setExportKeyOption('upload'); // Switch to upload option
    } catch (error) {
      showNotification(error.message, 'error');
    } finally {
      setIsUploadingKeys(false);
    }
  };

  const exportCsv = () => {
    if (!components || components.length === 0) {
      showNotification("No components to export. Please upload an SBOM file first.", 'warning');
      return;
    }

    try {

    const certInKeys = CERT_IN_PROPERTIES.map((p) => p.key);

    const headers = [
      "Component Name",
      "Component Version",
      "Component Description",
      "Unique Identifier",
      ...certInKeys,
      "Vulnerabilities",
    ];

    const compVulnMap = mapVulnerabilities();

    const escapeCsv = (val) => {
      if (val == null) return "";
      val = val.toString();
      if (val.search(/("|,|\n)/g) >= 0) {
        val = '"' + val.replace(/"/g, '""') + '"';
      }
      return val;
    };

    const rows = components.map((comp) => {
      const uniqueId =
        comp.purl ||
        (comp.properties &&
          comp.properties.find((p) => p.name === "Unique Identifier")?.value) ||
        "";

      const certInValues = certInKeys.map(
        (key) =>
          comp.properties?.find((p) => p.name === key)?.value?.toString() || ""
      );

      const vulnIds = compVulnMap.get(comp["bom-ref"]) || [];
      const vulnerabilitiesStr = vulnIds.length > 0 ? vulnIds.join(", ") : "None";

      return [
        comp.name || "",
        comp.version || "",
        comp.description || "",
        uniqueId,
        ...certInValues,
        vulnerabilitiesStr,
      ]
        .map(escapeCsv)
        .join(",");
    });

    const csvContent = [headers.join(","), ...rows].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    saveAs(blob, "cyclonedx-sbom-report.csv");
    showNotification("CSV file exported successfully!", 'success');
    } catch (error) {
      errorService.logError(error, 'CSV export');
      showNotification("Failed to export CSV file. Please try again.", 'error');
    }
  };

  const exportXlsx = async () => {
    if (!components || components.length === 0) {
      showNotification("No components to export. Please upload an SBOM file first.", 'warning');
      return;
    }

    try {
      const workbook = new ExcelJS.Workbook();
      
      // Document Control Sheet
      const docControlSheet = workbook.addWorksheet('Document Control');
      docControlSheet.addRow(['Report Name', '<OrgName-ClientName-ProductName-#-DD-MM-YYYY>']);
      docControlSheet.addRow(['Report Version', '<X.X>']);
      docControlSheet.addRow(['Product Name', '<Product Name>']);
      docControlSheet.addRow(['Product Version', '<X.X.X>']);
      docControlSheet.addRow(['Product Description', '<Short description about project>']);
      docControlSheet.addRow(['Timestamp', '<Add the value from metadata from json file>']);
      docControlSheet.addRow(['Author', 'Suraj Kumar']);

      // Components Sheet
      const componentsSheet = workbook.addWorksheet('Components');
      
      const certInKeys = CERT_IN_PROPERTIES.map((p) => p.key);
      const compVulnMap = mapVulnerabilities();

      const headers = [
        "Component Name",
        "Component Version",
        "Component Description",
        "Unique Identifier",
        ...certInKeys,
        "Vulnerabilities",
      ];

      // Add headers with styling
      const headerRow = componentsSheet.addRow(headers);
      headerRow.font = { bold: true };
      headerRow.fill = {
        type: 'pattern',
        pattern: 'solid',
        fgColor: { argb: 'FFE6E6FA' }
      };

      // Add data rows
      components.forEach((comp) => {
        const uniqueId =
          comp.purl ||
          (comp.properties &&
            comp.properties.find((p) => p.name === "Unique Identifier")?.value) ||
          "";

        const certInValues = certInKeys.map(
          (key) => comp.properties?.find((p) => p.name === key)?.value || ""
        );

        const vulnIds = compVulnMap.get(comp["bom-ref"]) || [];
        const vulnerabilitiesStr = vulnIds.length > 0 ? vulnIds.join(", ") : "None";

        componentsSheet.addRow([
          comp.name || "",
          comp.version || "",
          comp.description || "",
          uniqueId,
          ...certInValues,
          vulnerabilitiesStr,
        ]);
      });

      // Auto-fit columns
      componentsSheet.columns.forEach(column => {
        column.width = 15;
      });

      // Generate Excel file
      const buffer = await workbook.xlsx.writeBuffer();
      const blob = new Blob([buffer], { 
        type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' 
      });
      
      saveAs(blob, "cyclonedx-sbom-report.xlsx");
      showNotification("Excel file exported successfully!", 'success');
    } catch (error) {
      errorService.logError(error, 'Excel export');
      showNotification("Failed to export Excel file. Please try again.", 'error');
    }
  };


  const exportPDF = () => {
    if (!sbom || !components.length) {
      showNotification("No SBOM data to export. Please upload an SBOM file first.", 'error');
      return;
    }

    try {
      const pdfService = new PDFExportService();
      const result = pdfService.exportDetailedPDF(sbom, components, 'sbom-comprehensive-report.pdf');
      
      if (result.success) {
        showNotification("Comprehensive PDF report exported successfully!", 'success');
      } else {
        showNotification(result.message, 'error');
      }
    } catch (error) {
      console.error('PDF export error:', error);
      showNotification("Failed to export PDF file. Please try again.", 'error');
    }
  };

  // Check for duplicates and update count
  const checkForDuplicates = async (componentsToCheck = null) => {
    const componentsToUse = componentsToCheck || components;
    
    if (!componentsToUse || componentsToUse.length === 0) {
      setDuplicateCount(0);
      return;
    }

    try {
      const duplicateService = new DuplicateDetectionService();
      const duplicates = duplicateService.detectDuplicates(componentsToUse);
      
      setDuplicateCount(duplicates.length);
      
      // Only show notification once when duplicates are first detected
      if (duplicates.length > 0 && !duplicateNotificationShown) {
        showNotification(`Found ${duplicates.length} duplicate groups in your SBOM. Click "Find Duplicates" to manage them.`, 'warning');
        setDuplicateNotificationShown(true);
      }
    } catch (error) {
      console.error('Duplicate check error:', error);
    }
  };

  // Check for duplicates when components change
  useEffect(() => {
    if (components && components.length > 0) {
      checkForDuplicates();
    }
  }, [components]);

  // Handle page refresh warnings (custom modal only)
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Intercept F5, Ctrl+R, Ctrl+F5 refresh shortcuts - show custom modal
      if (e.key === 'F5' || (e.ctrlKey && e.key === 'r') || (e.ctrlKey && e.shiftKey && e.key === 'R')) {
        if (hasModifications) {
          e.preventDefault();
          e.stopPropagation();
          setShowRefreshWarning(true);
        }
      }
    };

    // Add event listener for keyboard shortcuts only
    window.addEventListener('keydown', handleKeyDown, true); // Use capture phase

    // Cleanup
    return () => {
      window.removeEventListener('keydown', handleKeyDown, true);
    };
  }, [hasModifications]);

  // Update page title to show unsaved changes
  useEffect(() => {
    if (hasModifications) {
      document.title = '⚠️ CERT-In SBOM Mapper (Unsaved Changes)';
    } else {
      document.title = 'CERT-In SBOM Mapper';
    }
  }, [hasModifications]);

  const mapVulnerabilities = () => {
    const map = new Map();
    vulnerabilities.forEach((vuln) => {
      const vulnId = vuln.id || "";
      if (!vuln.affects) return;
      vuln.affects.forEach((affect) => {
        const ref = affect.ref;
        if (!ref) return;
        if (!map.has(ref)) map.set(ref, []);
        map.get(ref).push(vulnId);
      });
    });
    return map;
  };

  const goBack = () => {
    setEditComponent(null);
    setSelectedIndex(null);
  };



  return (
    <div className="app-container">
      <header className="app-header">
        <h1>CERT-In SBOM Mapper</h1>
        <p className="app-subtitle">Make SBOM Cert-In Compliant</p>
      </header>

      <div className="app-body">
        {/* Sidebar */}
        <aside className="sidebar">
          <h2>Upload SBOM</h2>
          <label 
            htmlFor="sbomUpload" 
            className="upload-btn"
            onClick={handleUploadButtonClick}
          >
            Choose CycloneDX File
          </label>
          <input
            id="sbomUpload"
            type="file"
            accept=".json"
            onChange={onFileChange}
            className="hidden-input"
          />
          <p className="sidebar-note">Note: It supports CycloneDX only. Maximum file size limit is 10MB.</p>
          
          <div className="sidebar-section digital-signatures">
            <h3>Signature Verification</h3>
            <button
              onClick={() => {
                setShowSignatureManager(true);
                if (showDuplicateDetector) {
                  setShowDuplicateDetector(false);
                }
              }}
              className="sidebar-btn"
              title="Verify digital signatures"
            >
              Verify Signature
            </button>
          </div>
          
          {sbom && components.length > 0 && (
            <div className="sidebar-section duplicate-detection">
              <h3>Data Quality</h3>
              <button
                onClick={() => {
                  setShowDuplicateDetector(true);
                  if (showSignatureManager) {
                    setShowSignatureManager(false);
                  }
                }}
                className={`sidebar-btn ${duplicateCount > 0 ? 'has-duplicates' : ''}`}
                title="Detect and manage duplicate components"
              >
                Find Duplicates
                {duplicateCount > 0 && (
                  <span className="duplicate-badge">{duplicateCount}</span>
                )}
              </button>
              {duplicateCount > 0 && (
                <p className="duplicate-notice">
                  {duplicateCount} duplicate group{duplicateCount !== 1 ? 's' : ''} found
                </p>
              )}
            </div>
          )}
          

          
          {/* Bottom section with cache management and reference link */}
          <div className="sidebar-bottom">
            {/* Cache Management Dropdown */}
            <div className="cache-management-compact">
              <button 
                onClick={toggleCacheDropdown}
                className="cache-toggle-btn"
                title="Cache Management"
              >
                <span>Cache Management</span>
                <span className={`dropdown-arrow ${isCacheDropdownOpen ? 'open' : ''}`}>▼</span>
              </button>
              
              {isCacheDropdownOpen && (
                <div className="cache-dropdown-content">
                  <button 
                    onClick={getCacheInfo}
                    className="cache-btn info"
                    title="Show cache information"
                  >
                    Cache Info
                  </button>
                  <button 
                    onClick={clearCache}
                    className="cache-btn clear"
                    title="Clear all cached data"
                  >
                    Clear Cache
                  </button>
                  <p className="cache-note">
                    Cache persists for 24 hours
                  </p>
                </div>
              )}
            </div>
            
            <a
              href="https://www.cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf"
              target="_blank"
              rel="noopener noreferrer"
              className="sidebar-link"
            >
              Reference: SBOM Guidelines
            </a>
          </div>
        </aside>

        {/* Main Body */}
        <main className="main-content">
          {fetchProgress !== null && (
            <ProgressBar progress={fetchProgress} label={fetchLabel} />
          )}
          {!editComponent && components.length > 0 && !showSignatureManager && (
            <>
              <h2 className={`main-heading ${isNewUpload ? 'heading-fresh' : ''}`}>
                Components <span className="component-count">({filteredComponents.length} {nameFilter ? 'filtered' : 'loaded'})</span>
              </h2>
              <div className={`table-wrapper ${isNewUpload ? 'new-upload' : ''}`}>
                <table key={tableKey} className={`component-table ${isNewUpload ? 'table-fresh' : ''}`}>
                  <thead>
                    <tr>
                      <th className="table-header">#</th>
                      <th className="table-header">
                        <div className="header-with-filter">
                          Component Name
                          <button
                            className="filter-icon"
                            onClick={() => setShowFilterDropdown(!showFilterDropdown)}
                            title="Filter components by name"
                          >
                            ☰
                          </button>
                        </div>
                      </th>
                      <th className="table-header">Version</th>
                      <th className="table-header">Description</th>
                      <th className="table-header">Action</th>
                    </tr>
                    {showFilterDropdown && (
                      <tr className="filter-row">
                        <td colSpan="5" className="filter-cell">
                          <div className="table-filter-controls">
                            <input
                              type="text"
                              placeholder="Search by component name..."
                              value={nameFilter}
                              onChange={(e) => setNameFilter(e.target.value)}
                              className="table-filter-input"
                              autoFocus
                            />
                            {nameFilter && (
                              <button
                                onClick={() => setNameFilter('')}
                                className="table-clear-filter-btn"
                                title="Clear filter"
                              >
                                ✕
                              </button>
                            )}
                            <button
                              onClick={() => setShowFilterDropdown(false)}
                              className="table-close-filter-btn"
                              title="Close filter"
                            >
                              Close
                            </button>
                          </div>
                          {nameFilter && (
                            <div className="table-filter-results">
                              Showing {filteredComponents.length} of {components.length} components
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </thead>
                  <tbody>
                    {filteredComponents.map((c, i) => (
                      <tr
                        key={i}
                        className={`table-row ${
                          i === selectedIndex ? "selected" : ""
                        }`}
                      >
                        <td className="table-cell center">{i + 1}</td>
                        <td className="table-cell">{c.name}</td>
                        <td className="table-cell">{c.version}</td>
                        <td
                          className="table-cell truncate"
                          title={c.description || "(No description)"}
                          data-full-text={c.description || "(No description)"}
                        >
                          {c.description || "(No description)"}
                        </td>
                        <td className="table-cell">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              selectComponent(i);
                            }}
                            className="btn-primary"
                          >
                            <Pencil size={14} />
                            Edit
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {editComponent && (
            <ComponentEditor
              editComponent={editComponent}
              updateEditField={updateEditField}
              updateNestedField={updateNestedField}
              addNestedItem={addNestedItem}
              removeNestedItem={removeNestedItem}
              updatePropertyField={updatePropertyField}
              saveChanges={saveChanges}
              goBack={goBack}
              selectedIndex={selectedIndex}
            />
          )}


          {/* Digital Signature Verification */}
          {!editComponent && showSignatureManager && (
            <div className="signature-wrapper">
              <SignatureManager 
                sbom={sbom} 
                onBackToTable={() => setShowSignatureManager(false)}
              />
            </div>
          )}

          {/* Duplicate Detection */}
          {!editComponent && showDuplicateDetector && (
            <div className="duplicate-detector-wrapper">
              <DuplicateDetector 
                components={components}
                onBackToTable={() => {
                  setShowDuplicateDetector(false);
                  setTableKey(prev => prev + 1); // Force a refresh of the main table when going back
                }}
                onComponentsUpdate={(updatedComponents) => {
                  setComponents(updatedComponents);
                  setSbom((prev) => ({ ...prev, components: updatedComponents }));
                  setTableKey(prev => prev + 1);
                  // Don't update originalComponents - merging is a modification
                  setHasModifications(true); // Mark as modified since we merged duplicates
                  showNotification("Components updated successfully!", 'success');
                }}
                onDuplicateCountChange={(count) => setDuplicateCount(count)}
              />
            </div>
          )}

          {sbom && !editComponent && !showSignatureManager && !showDuplicateDetector && (
            <div className="export-actions">
              <button
                onClick={exportSbom}
                className="export-button green"
                title="Export SBOM with optional digital signature"
                disabled={fetchProgress !== null}
              >
                Export SBOM
              </button>
              <button
                onClick={exportCsv}
                className="export-button blue"
                title="Export SBOM Data as CSV"
                disabled={fetchProgress !== null}
              >
                Export CSV Report
              </button>
              <button
                onClick={exportXlsx}
                className="export-button purple"
                title="Export SBOM Data as XLSX (Excel) with Document Control sheet"
                disabled={fetchProgress !== null}
              >
                Export XLSX Report
              </button>
              <button
                onClick={exportPDF}
                className="export-button orange"
                title="Export Comprehensive PDF with All Component Details and CERT-In Compliance"
                disabled={fetchProgress !== null}
              >
                Export PDF Report
              </button>
            </div>
          )}

        </main>
      </div>
      
      {/* Export Dialog */}
      <ExportDialog
        showExportDialog={showExportDialog}
        exportWithSignature={exportWithSignature}
        setExportWithSignature={setExportWithSignature}
        exportKeyOption={exportKeyOption}
        setExportKeyOption={setExportKeyOption}
        isExporting={isExporting}
        isUploadingKeys={isUploadingKeys}
        exportPrivateKeyFile={exportPrivateKeyFile}
        setExportPrivateKeyFile={setExportPrivateKeyFile}
        exportPublicKeyFile={exportPublicKeyFile}
        setExportPublicKeyFile={setExportPublicKeyFile}
        dialogResetKey={dialogResetKey}
        clearAllFileStates={clearAllFileStates}
        handleExportWithSignature={handleExportWithSignature}
        handleExportWithoutSignature={handleExportWithoutSignature}
        cancelExport={cancelExport}
        handleExportPrivateKeyUpload={handleExportPrivateKeyUpload}
        handleExportPublicKeyUpload={handleExportPublicKeyUpload}
        uploadKeysForExport={uploadKeysForExport}
      />

      {/* Upload Warning Dialog */}
      {showUploadWarning && (
        <div className="confirmation-overlay">
          <div className="confirmation-dialog">
            <h4>⚠️ Unsaved Changes</h4>
            <p>You have unsaved modifications to your current SBOM. Uploading a new file will replace your current work.</p>
            <p><strong>Are you sure you want to continue?</strong></p>
            
            <div className="confirmation-buttons">
              <button onClick={confirmUpload} className="btn btn-danger">
                Yes, Replace Current Work
              </button>
              <button onClick={cancelUpload} className="btn btn-secondary">
                Cancel Upload
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Refresh Warning Dialog */}
      {showRefreshWarning && (
        <div className="confirmation-overlay">
          <div className="confirmation-dialog">
            <h4>⚠️ Unsaved Changes</h4>
            <p>You have unsaved modifications to your current SBOM. Refreshing the page will replace your current work.</p>
            <p><strong>Are you sure you want to continue?</strong></p>
            
            <div className="confirmation-buttons">
              <button onClick={confirmRefresh} className="btn btn-danger">
                Yes, Replace Current Work
              </button>
              <button onClick={cancelRefresh} className="btn btn-secondary">
                Cancel Refresh
              </button>
            </div>
          </div>
        </div>
      )}
      
      {/* Notification Component */}
      {notification && (
        <Notification
          message={notification.message}
          type={notification.type}
          duration={notification.duration}
          onClose={hideNotification}
        />
      )}
    </div>
  );
}

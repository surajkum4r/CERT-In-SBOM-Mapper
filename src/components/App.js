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
import DuplicateDetectionService from "../services/duplicateDetectionService";
import ProgressBar from "./ProgressBar";
import Notification from "./Notification";
import errorService from "../services/errorService";
import cacheService from "../services/cacheService";

const CERT_IN_PROPERTIES = [
  { key: "Patch Status", label: "Patch Status" },
  { key: "Release Date", label: "Release Date" },
  { key: "End-of-Life Date", label: "End-of-Life (EOL) Date" },
  { key: "Criticality", label: "Criticality" },
  { key: "Usage Restrictions", label: "Usage Restrictions" },
  { key: "Comments or Notes", label: "Comments or Notes" },
  { key: "Executable Property", label: "Executable Property" },
  { key: "Archive Property", label: "Archive Property" },
  { key: "Structured Property", label: "Structured Property" },
  { key: "Unique Identifier", label: "Unique Identifier" },
  { key: "Component Supplier", label: "Component Supplier" },
  { key: "Component Origin", label: "Component Origin" },
];

function updateProperty(properties, name, value) {
  let props = properties ? [...properties] : [];
  const idx = props.findIndex((p) => p.name === name);
  if (idx >= 0) {
    if (value.trim() === "") {
      props.splice(idx, 1);
    } else {
      props[idx] = { name, value };
    }
  } else if (value.trim() !== "") {
    props.push({ name, value });
  }
  return props;
}

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

  // Filter components by name
  const filteredComponents = components.filter(component => {
    if (!nameFilter.trim()) return true;
    return component.name?.toLowerCase().includes(nameFilter.toLowerCase());
  });

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
          
          // Hide signature manager and show main table
          setShowSignatureManager(false);
          
          // Trigger fresh table appearance
          setTableKey(prev => prev + 1);
          setIsNewUpload(true);
          
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

  const onFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Validate file type
    if (!file.name.toLowerCase().endsWith('.json')) {
      const errorInfo = errorService.getUserFriendlyMessage(
        new Error('Invalid file type'), 
        'Please upload a JSON file'
      );
      showNotification(errorInfo.message, 'error');
      // Clear input on error too
      e.target.value = '';
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
      // Clear input on error
      e.target.value = '';
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
          
          // Hide signature manager and show main table when new file is uploaded
          setShowSignatureManager(false);
          
          // Trigger fresh table appearance
          setTableKey(prev => prev + 1);
          setIsNewUpload(true);
          
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
                if (process.env.NODE_ENV === 'development') {
                  console.log('[FILE_CHECKSUM] Cache HIT for entire SBOM');
                }
                setFetchProgress(50);
                setFetchLabel('Loading cached results...');
                
                const cachedResult = cacheService.getFileResult(json);
                setComponents(cachedResult);
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
                }, 600);
                return;
              }
              
              if (process.env.NODE_ENV === 'development') {
                console.log('[FILE_CHECKSUM] Cache MISS for SBOM, processing components...');
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
              setSbom((prev) => ({ ...(prev || {}), components: merged }));
              
              // Cache the entire processing result for future use
              cacheService.setFileResult(json, merged);
              if (process.env.NODE_ENV === 'development') {
                console.log('[FILE_CHECKSUM] Cached entire SBOM processing result');
              }
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
          e.target.value = '';
        }
      } catch (ex) {
        errorService.logError(ex, 'File parsing', { fileName: file.name });
        const errorInfo = errorService.handleSBOMError(ex, file.name);
        showNotification(errorInfo.message, 'error');
        // Clear input on error
        e.target.value = '';
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
  const checkForDuplicates = async () => {
    if (!components || components.length === 0) {
      setDuplicateCount(0);
      return;
    }

    try {
      const duplicateService = new DuplicateDetectionService();
      const duplicates = duplicateService.detectDuplicates(components);
      
      setDuplicateCount(duplicates.length);
      
      if (duplicates.length > 0) {
        showNotification(`Found ${duplicates.length} duplicate groups in your SBOM. Click "Find Duplicates" to manage them.`, 'warning');
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

  const openSignaturePage = () => {
    // Instead of opening a separate HTML file, show the signature manager in the current app
    setShowSignatureManager(true);
  };

  const showContextMenu = (event, type) => {
    // Create context menu
    const contextMenu = document.createElement('div');
    contextMenu.style.cssText = `
      position: fixed;
      top: ${event.clientY}px;
      left: ${event.clientX}px;
      background: white;
      border: 1px solid #ddd;
      border-radius: 6px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      z-index: 1000;
      padding: 8px 0;
      min-width: 200px;
    `;

    const menuItems = [
      {
        text: 'Open in Current Tab',
        action: () => {
          if (type === 'signature-new') {
            openSignaturePage();
          } else {
            setShowSignatureManager(true);
          }
        }
      },
      {
        text: 'Open in New Window',
        action: () => {
          if (type === 'signature-new') {
            // For signature, we'll open in current tab since it's now integrated
            openSignaturePage();
          } else {
            const newWindow = window.open('', '_blank', 'width=1200,height=800');
            newWindow.document.write(`
              <html>
                <head><title>Signature Management</title></head>
                <body>
                  <h2>Signature Management</h2>
                  <p>This would be the signature management interface.</p>
                  <button onclick="window.close()">Close</button>
                </body>
              </html>
            `);
          }
        }
      }
    ];

    menuItems.forEach(item => {
      const menuItem = document.createElement('div');
      menuItem.style.cssText = `
        padding: 8px 16px;
        cursor: pointer;
        font-size: 14px;
        color: #333;
      `;
      menuItem.textContent = item.text;
      menuItem.addEventListener('mouseenter', () => {
        menuItem.style.backgroundColor = '#f0f0f0';
      });
      menuItem.addEventListener('mouseleave', () => {
        menuItem.style.backgroundColor = 'transparent';
      });
      menuItem.addEventListener('click', () => {
        item.action();
        document.body.removeChild(contextMenu);
      });
      contextMenu.appendChild(menuItem);
    });

    document.body.appendChild(contextMenu);

    // Remove context menu when clicking elsewhere
    const removeMenu = (e) => {
      if (!contextMenu.contains(e.target)) {
        if (document.body.contains(contextMenu)) {
          document.body.removeChild(contextMenu);
        }
        document.removeEventListener('click', removeMenu);
      }
    };

    setTimeout(() => {
      document.addEventListener('click', removeMenu);
    }, 100);
  };

  return (
    <div className="app-container">
      <header className="app-header">
        <h1>CERT-In SBOM Mapper</h1>
        {/* <p className="app-subtitle">Made with &#10084;</p> */}
        <p className="app-subtitle">Make SBOM Cert-In Compliant</p>
      </header>

      <div className="app-body">
        {/* Sidebar */}
        <aside className="sidebar">
          <h2>Upload SBOM</h2>
          <label htmlFor="sbomUpload" className="upload-btn">
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
                onBackToTable={() => setShowDuplicateDetector(false)}
                onComponentsUpdate={(updatedComponents) => {
                  setComponents(updatedComponents);
                  setTableKey(prev => prev + 1); // Force table re-render
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
      {showExportDialog && (
        <div className="confirmation-overlay">
          <div className="confirmation-dialog export-dialog" key={dialogResetKey}>
            <h4>📤 Export SBOM</h4>
            <p>Choose how you want to export your SBOM:</p>
            
            <div className="export-options">
              <div className="export-option">
                <label>
                  <input
                    type="radio"
                    name="exportType"
                    value="without"
                    checked={!exportWithSignature}
                    onChange={() => {
                      setExportWithSignature(false);
                      setExportKeyOption('generate');
                      clearAllFileStates();
                    }}
                  />
                  <span className="option-label">
                    <strong>Export without signature</strong>
                    <small>Standard JSON export</small>
                  </span>
                </label>
              </div>
              
              <div className="export-option">
                <label>
                  <input
                    type="radio"
                    name="exportType"
                    value="with"
                    checked={exportWithSignature}
                    onChange={() => {
                      setExportWithSignature(true);
                      setExportKeyOption('generate');
                      clearAllFileStates();
                    }}
                  />
                  <span className="option-label">
                    <strong>Export with digital signature</strong>
                    <small>Creates both SBOM and signature files</small>
                  </span>
                </label>
              </div>
            </div>
            
            {exportWithSignature && (
              <div className="signature-options">
                <p><strong>Key Options:</strong></p>
                <div className="key-option">
                  <label>
                    <input
                      type="radio"
                      name="keyOption"
                      value="generate"
                      checked={exportKeyOption === 'generate'}
                      onChange={() => {
                        setExportKeyOption('generate');
                        clearAllFileStates();
                      }}
                    />
                    <span>Generate new key pair</span>
                  </label>
                </div>
                <div className="key-option">
                  <label>
                    <input
                      type="radio"
                      name="keyOption"
                      value="upload"
                      checked={exportKeyOption === 'upload'}
                      onChange={() => {
                        setExportKeyOption('upload');
                        clearAllFileStates();
                      }}
                    />
                    <span>Upload your own keys</span>
                  </label>
                </div>
                
                {exportKeyOption === 'upload' && (
                  <div className="inline-key-upload">
                    <div className="file-input-group">
                      <label htmlFor="exportPrivateKeyInput">Private Key (.pem, .key):</label>
                      <input
                        id="exportPrivateKeyInput"
                        type="file"
                        accept=".pem,.key,.txt"
                        onChange={handleExportPrivateKeyUpload}
                        className="file-input"
                      />
                      {exportPrivateKeyFile && (
                        <span className="file-selected">✅ {exportPrivateKeyFile.name}</span>
                      )}
                    </div>
                    
                    <div className="file-input-group">
                      <label htmlFor="exportPublicKeyInput">Public Key (.pem, .pub):</label>
                      <input
                        id="exportPublicKeyInput"
                        type="file"
                        accept=".pem,.pub,.txt"
                        onChange={handleExportPublicKeyUpload}
                        className="file-input"
                      />
                      {exportPublicKeyFile && (
                        <span className="file-selected">✅ {exportPublicKeyFile.name}</span>
                      )}
                    </div>
                    
                    <div className="upload-keys-section">
                      <button 
                        onClick={uploadKeysForExport}
                        className="btn btn-secondary btn-sm"
                        disabled={isUploadingKeys || !exportPrivateKeyFile || !exportPublicKeyFile}
                      >
                        {isUploadingKeys ? 'Uploading...' : 'Upload Keys'}
                      </button>
                    </div>
                    
                    <div className="key-format-info">
                      <p><strong>Key Format Requirements:</strong></p>
                      <ul>
                        <li>PEM format (-----BEGIN PRIVATE KEY----- / -----BEGIN PUBLIC KEY-----)</li>
                        <li>RSA keys (2048-bit or higher recommended)</li>
                        <li>Private key should be in PKCS#8 format</li>
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            )}
            
            <div className="confirmation-buttons">
              <button 
                onClick={exportWithSignature ? handleExportWithSignature : handleExportWithoutSignature}
                className="btn btn-primary"
                disabled={isExporting || isUploadingKeys}
              >
                {isExporting ? 'Exporting...' : isUploadingKeys ? 'Uploading Keys...' : 'Export SBOM'}
              </button>
              <button 
                onClick={cancelExport}
                className="btn btn-secondary"
                disabled={isExporting}
              >
                Cancel
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

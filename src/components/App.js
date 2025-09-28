import React, { useState } from "react";
import { ComponentEditor } from "./ComponentEditor";
import SignatureManager from "./SignatureManager";
import ExcelJS from "exceljs";
import { saveAs } from "file-saver";
import { Pencil } from "lucide-react";
import "../styles/components/AppView.css";
import PropertyMapperService from "../services/propertyMapperService";
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
    if (file.size > 10 * 1024 * 1024) {
      showNotification('File is too large. Please upload a file smaller than 10MB.', 'error');
      // Clear input on error too
      e.target.value = '';
      return;
    }

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
    const dataStr = JSON.stringify(sbom, null, 2);
    const blob = new Blob([dataStr], { type: "application/json" });
    saveAs(blob, "cyclonedx-sbom-updated.json");
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
    // Save current SBOM to sessionStorage for better security
    if (sbom) {
      try {
        sessionStorage.setItem('current_sbom', JSON.stringify(sbom));
      } catch (error) {
        console.warn('Failed to save SBOM to session storage:', error);
        showNotification('Failed to prepare SBOM for signing. Please try again.', 'error');
        return;
      }
    }
    
    // Open signature page in new window
    const signatureWindow = window.open(
      '/signature.html',
      'signatureWindow',
      'width=1200,height=800,scrollbars=yes,resizable=yes'
    );
    
    // Send SBOM data to the new window
    if (signatureWindow) {
      signatureWindow.addEventListener('load', () => {
        signatureWindow.postMessage({
          type: 'SBOM_DATA',
          sbom: sbom
        }, '*');
      });
    }
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
        text: 'Open in New Tab',
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
          <p className="sidebar-note">Note: It supports CycloneDX only.</p>
          
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
          
          {sbom && (
            <div className="sidebar-section digital-signatures">
              <h3>Digital Signatures</h3>
              <button
                onClick={() => setShowSignatureManager(!showSignatureManager)}
                className="sidebar-btn"
                title="Toggle Digital Signature Management"
              >
                🔐 Digital Signatures
              </button>
            </div>
          )}
          
          <a
            href="https://www.cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf"
            target="_blank"
            rel="noopener noreferrer"
            className="sidebar-link"
          >
            Reference: SBOM Guidelines
          </a>
        </aside>

        {/* Main Body */}
        <main className="main-content">
          {fetchProgress !== null && (
            <ProgressBar progress={fetchProgress} label={fetchLabel} />
          )}
          {!editComponent && components.length > 0 && !showSignatureManager && (
            <>
              <h2 className={`main-heading ${isNewUpload ? 'heading-fresh' : ''}`}>
                Components <span className="component-count">({components.length} loaded)</span>
              </h2>
              <div className={`table-wrapper ${isNewUpload ? 'new-upload' : ''}`}>
                <table key={tableKey} className={`component-table ${isNewUpload ? 'table-fresh' : ''}`}>
                  <thead>
                    <tr>
                      <th className="table-header">#</th>
                      <th className="table-header">Component Name</th>
                      <th className="table-header">Version</th>
                      <th className="table-header">Description</th>
                      <th className="table-header">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {components.map((c, i) => (
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

          {sbom && !editComponent && (
            <div className="export-actions">
              <button
                onClick={exportSbom}
                className="export-button green"
                title="Export the updated CycloneDX SBOM JSON file"
                disabled={fetchProgress !== null}
              >
                Export SBOM JSON
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
            </div>
          )}

          {/* Digital Signature Management */}
          {sbom && !editComponent && showSignatureManager && (
            <div className="signature-wrapper">
              <SignatureManager 
                sbom={sbom} 
                onSignatureUpdate={(signedSBOM) => {
                  setSbom(signedSBOM);
                  showNotification("SBOM signature updated successfully!", 'success');
                }}
                onBackToTable={() => setShowSignatureManager(false)}
              />
            </div>
          )}

        </main>
      </div>
      
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

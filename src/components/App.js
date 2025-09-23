import React, { useState } from "react";
import { ComponentEditor } from "./ComponentEditor";
import * as XLSX from "xlsx";
import { saveAs } from "file-saver";
import { Pencil } from "lucide-react";
import "../styles/components/AppView.css";
import PropertyMapperService from "../services/propertyMapperService";
import ProgressBar from "./ProgressBar";

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

  const onFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
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

          // Background auto-populate of CERT-In properties with visible progress
          (async () => {
            setFetchProgress(0);
            setFetchLabel("Fetching CERT-In properties for components...");
            try {
              const batchSize = 10; // fetch in batches to avoid rate limits and update progress
              const total = updatedComponents.length;
              let fetchedList = [];
              for (let i = 0; i < total; i += batchSize) {
                const batch = updatedComponents.slice(i, i + batchSize);
                const results = await Promise.all(
                  batch.map((c) =>
                    propertyMapper
                      .fetchComponentData(c, json.vulnerabilities || [])
                      .catch(() => ({}))
                  )
                );
                fetchedList = [...fetchedList, ...results];
                const pct = Math.round(((i + batch.length) / total) * 100);
                setFetchProgress(pct);
              }

              const merged = updatedComponents.map((c, idx) => {
                const fetched = fetchedList[idx] || {};
                let props = Array.isArray(c.properties) ? [...c.properties] : [];
                CERT_IN_PROPERTIES.forEach(({ key }) => {
                  const val = fetched[key];
                  if (val && val !== "NA") {
                    props = updateProperty(props, key, String(val));
                  }
                });
                // Ensure we never wipe existing non-NA comments when fetched returns NA/undefined
                if (!fetched["Comments or Notes"] || fetched["Comments or Notes"] === "NA") {
                  const existing = props.find((p) => p.name === "Comments or Notes");
                  if (existing && existing.value) {
                    props = updateProperty(props, "Comments or Notes", existing.value);
                  }
                }
                return { ...c, properties: props };
              });
              setComponents(merged);
              setSbom((prev) => ({ ...(prev || {}), components: merged }));
            } catch (err) {
              // eslint-disable-next-line no-console
              console.error("[BG] auto-fetch error", err);
            } finally {
              // Ensure user can see 100% before hiding
              setFetchProgress(100);
              setTimeout(() => {
                setFetchProgress(null);
                setFetchLabel("");
              }, 600);
            }
          })();
        } else {
          alert("Invalid CycloneDX SBOM: No components field");
        }
      } catch (ex) {
        alert("Invalid JSON file");
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
    alert("Component updated!");
  };

  const exportSbom = () => {
    if (!sbom) return;
    const dataStr = JSON.stringify(sbom, null, 2);
    const blob = new Blob([dataStr], { type: "application/json" });
    saveAs(blob, "cyclonedx-sbom-updated.json");
  };

  const exportCsv = () => {
    if (!components || components.length === 0) {
      alert("No components to export");
      return;
    }

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
  };

  const exportXlsx = () => {
    if (!components || components.length === 0) {
      alert("No components to export");
      return;
    }

    const docControl = [
      ["Report Name", "<Payatu-ClientName-ProductName-#-DD-MM-YYYY>"],
      ["Report Version", "<X.X>"],
      ["Product Name", "<Product Name>"],
      ["Product Version", "<X.X.X>"],
      ["Product Description", "<Short description about project>"],
      ["Timestamp", "<Add the value from metadata from json file>"],
      ["Author", "Payatu"],
    ];
    const wsDoc = XLSX.utils.aoa_to_sheet(docControl);

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

    const rows = components.map((comp) => {
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

      return [
        comp.name || "",
        comp.version || "",
        comp.description || "",
        uniqueId,
        ...certInValues,
        vulnerabilitiesStr,
      ];
    });

    const wsComponents = XLSX.utils.aoa_to_sheet([headers, ...rows]);

    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, wsDoc, "Document Control");
    XLSX.utils.book_append_sheet(wb, wsComponents, "Components");

    const wbout = XLSX.write(wb, { bookType: "xlsx", type: "array" });
    const blob = new Blob([wbout], { type: "application/octet-stream" });
    saveAs(blob, "cyclonedx-sbom-report.xlsx");
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
          {sbom && (
            <p className="sidebar-info" title={sbom?.metadata?.timestamp || ""}>
              {components.length} component
              {components.length !== 1 ? "s" : ""} loaded
            </p>
          )}
          <p className="sidebar-note">Note: It supports CycloneDX only.</p>
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
          {!editComponent && components.length > 0 && (
            <>
              <h2 className="main-heading">Components</h2>
              <div className="table-wrapper">
                <table className="component-table">
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
        </main>
      </div>
    </div>
  );
}

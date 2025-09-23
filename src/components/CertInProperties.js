import React from "react";
import "../styles/components/CertInProperties.css";
import { InfoIcon } from "./InfoIcon";

export const descriptions = {
  Name: "The name of the software component or library included in the SBOM.",
  Version: "The version number or identifier of the software component.",
  Description: "A brief description or summary of the functionality and purpose of the software component.",
  Hashes: "Cryptographic checksums or hashes to ensure component file integrity and authenticity.",
  Licenses: "The license under which the software component is distributed, including type, terms, and restrictions.",
  Vulnerabilities: "Known security vulnerabilities or weaknesses, including severity ratings and CVE references relevant to the component.",
  Criticality: "The importance level of the component to overall functionality or security, e.g., critical, high, medium, or low.",
  Timestamp: "Record of the date and time when the SBOM data was assembled.",
  Identifier: "A unique identifier such as Package URL (purl) to track the component.",
  // --- Above element we get from OWASP Dependency Track ---

  // --- Additional element suggested by CERT-In properties ---
  "Component Origin": "The source or origin of the software component (proprietary, open-source, or third-party vendor).",
  "Component Dependencies": "Other components or libraries the current component depends on, with their names and versions.",
  "Patch Status": "Indicates if patches or updates are available to address known vulnerabilities or issues.",
  "Release Date": "The date when the software component was released or made available for use.",
  "End-of-Life Date": "The date when support or maintenance for the component ends, marking its lifecycle completion.",
  "Usage Restrictions": "Restrictions or limitations on component usage such as export control or IP rights.",
  "Comments or Notes": "Additional comments or annotations relevant to the component or its inclusion in the SBOM.",
  "Component Supplier": "The entity or organization that supplied the component, such as vendor, third-party, or open-source project.",
  "Executable Property": "Attributes indicating whether a component can be executed within the SBOM.",
  "Archive Property": "Flags denoting if the component is stored as an archive or compressed file.",
  "Structured Property": "Descriptors defining the organized format of data within a component listed in the SBOM.",
  "Unique Identifier": "A distinct code assigned to each component to track ownership and version changes, ensuring accurate management.",
  "External References": "References such as documentation, repositories, or websites related to the component.",
};

export function CertInProperties({ properties, onChange }) {
  function getPropValue(name) {
    if (!properties) return "";
    const p = properties.find((prop) => prop.name === name);
    return p ? p.value : "";
  }

  const renderLabel = (labelKey) => (
    <span className="certin-label">
      {labelKey} <InfoIcon text={descriptions[labelKey]} />
    </span>
  );

  return (
    <fieldset className="certin-fieldset">
      <legend className="certin-legend">
        CERT-In Required Properties
      </legend>

      <label className="certin-input-label">
        {renderLabel("Patch Status")}:{" "}
        <select
          value={getPropValue("Patch Status") || "NA"}
          onChange={(e) => onChange("Patch Status", e.target.value)}
          className="certin-select"
        >
          <option>Up to date</option>
          <option>NA</option>
          <option>Update available</option>
        </select>
      </label>

      {["Release Date", "End-of-Life Date"].map((key) => {
        const currentVal = getPropValue(key) || "NA";
        const displayVal = currentVal === "NA" ? "" : currentVal;

        return (
          <label key={key} className="certin-input-label">
            {renderLabel(key)}:{" "}
            <input
              type="text"
              placeholder="Enter date (DD-MM-YYYY). Default is NA"
              value={displayVal}
              onChange={(e) => onChange(key, e.target.value)}
              onBlur={(e) => {
                if (!e.target.value.trim()) {
                  onChange(key, "NA");
                }
              }}
              className="certin-input monospace"
            />
          </label>
        );
      })}

      <label className="certin-input-label">
        {renderLabel("Criticality")}:{" "}
        <select
          value={getPropValue("Criticality") || ""}
          onChange={(e) => onChange("Criticality", e.target.value)}
          className="certin-select"
        >
          <option value="">-- Select --</option>
          <option>Critical</option>
          <option>High</option>
          <option>Medium</option>
          <option>Low</option>
        </select>
      </label>

      {["Executable Property", "Archive Property", "Structured Property"].map(
        (key) => (
          <label key={key} className="certin-input-label">
            {renderLabel(key)}:{" "}
            <select
              value={getPropValue(key) || ""}
              onChange={(e) => onChange(key, e.target.value)}
              className="certin-select"
            >
              <option value="">-- Select --</option>
              <option>Yes</option>
              <option>No</option>
            </select>
          </label>
        )
      )}

      {["Usage Restrictions", "Comments or Notes", "Unique Identifier"].map(
        (key) => (
          <label key={key} className="certin-input-label">
            {renderLabel(key)}:{" "}
            <input
              type="text"
              value={getPropValue(key) || ""}
              onChange={(e) => onChange(key, e.target.value)}
              className="certin-input"
              placeholder={`Enter ${key}`}
            />
          </label>
        )
      )}

      <label className="certin-input-label">
        {renderLabel("Component Supplier")}:{" "}
        <select
          value={getPropValue("Component Supplier") || ""}
          onChange={(e) => onChange("Component Supplier", e.target.value)}
          className="certin-select"
        >
          <option value="">-- Select --</option>
          <option>Vendor</option>
          <option>Third-party</option>
          <option>Open-source</option>
        </select>
      </label>

      <label className="certin-input-label">
        {renderLabel("Component Origin")}:{" "}
        <select
          value={getPropValue("Component Origin") || ""}
          onChange={(e) => onChange("Component Origin", e.target.value)}
          className="certin-select"
        >
          <option value="">-- Select --</option>
          <option>Proprietary</option>
          <option>Open-source</option>
          <option>Third-party vendor</option>
        </select>
      </label>
    </fieldset>
  );
}

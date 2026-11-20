import React, { useMemo, useState } from "react";
import "../styles/components/VexPanel.css";
import { sbomConformance } from "../utils/conformance";

// CERT-In Table 5: which of the 21 data fields are present, declared NA, or missing.
export default function ConformancePanel({ sbom, onOpenComponent, onBack }) {
  const [onlyGaps, setOnlyGaps] = useState(true);
  const result = useMemo(() => sbomConformance(sbom), [sbom]);
  const rows = onlyGaps ? result.perComponent.filter((c) => c.missing.length) : result.perComponent;

  return (
    <div className="vex-panel">
      <div className="vex-header">
        <button className="btn btn-secondary" onClick={onBack}>← Back to components</button>
        <h3>CERT-In Table 5 conformance</h3>
      </div>
      <p className="vex-intro">
        <strong className={result.verdict === "Conformant" ? "conf-ok" : "conf-bad"}>{result.verdict}</strong>
        {" - "}{result.conformancePct}% of fields are supplied or declared NA (nothing silently missing);
        {" "}{result.completenessPct}% carry real values ({result.components} components × 21 fields).
        A field declared <em>NA</em> counts as a CERT-In "known unknown"; a <em>missing</em> field does not.
      </p>

      <div className="vex-table-wrap">
        <table className="vex-table">
          <thead>
            <tr><th>Field</th><th>Present</th><th>Declared NA</th><th>Missing</th></tr>
          </thead>
          <tbody>
            {result.fields.map((f) => (
              <tr key={f.key} className={f.missing ? "vex-row kev" : "vex-row"}>
                <td>{f.label}</td><td>{f.present}</td><td>{f.na}</td><td>{f.missing}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="vex-summary">
        <button className={onlyGaps ? "vex-chip active" : "vex-chip"} onClick={() => setOnlyGaps(true)}>
          Components with missing fields ({result.perComponent.filter((c) => c.missing.length).length})
        </button>
        <button className={!onlyGaps ? "vex-chip active" : "vex-chip"} onClick={() => setOnlyGaps(false)}>
          All components ({result.perComponent.length})
        </button>
      </div>

      {rows.length === 0 ? (
        <p className="vex-empty">Every component supplies or declares all 21 fields.</p>
      ) : (
        <div className="vex-table-wrap">
          <table className="vex-table">
            <thead>
              <tr><th>Component</th><th>Missing</th><th>Declared NA</th><th /></tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.ref || c.name} className="vex-row">
                  <td>{c.name}</td>
                  <td>{c.missing.join(", ") || "-"}</td>
                  <td>{c.na.join(", ") || "-"}</td>
                  <td>
                    <button className="btn btn-secondary btn-sm" onClick={() => onOpenComponent(c.ref)}>Edit</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

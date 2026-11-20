import React, { useMemo, useState } from "react";
import "../styles/components/VexPanel.css";
import { sbomConformance } from "../utils/conformance";

// CERT-In Table 5: which of the 21 data fields are present, declared NA, or missing.
export default function ConformancePanel({ sbom, onOpenComponent, onBack }) {
  const [onlyGaps, setOnlyGaps] = useState(true);
  const result = useMemo(() => sbomConformance(sbom), [sbom]);
  const rows = onlyGaps ? result.perComponent.filter((c) => c.missing.length || c.criticalityNeedsReview) : result.perComponent;

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
      {result.criticalityToReview > 0 && (
        <p className="vex-intro conf-warn">
          {result.criticalityToReview} component(s) have a Criticality derived from vulnerability severity. CERT-In defines
          criticality as the component's importance to the application: review these in the editor (the value is then kept
          on re-processing).
        </p>
      )}

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
          Components to fix or review ({result.perComponent.filter((c) => c.missing.length || c.criticalityNeedsReview).length})
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
                  <td>
                    {c.name}
                    {String(c.lookupStatus || "").startsWith("failed") && (
                      <div className="conf-bad" title={c.lookupStatus}>Automatic lookup failed - NA fields not collected</div>
                    )}
                  </td>
                  <td>
                    {c.missing.join(", ") || "-"}
                    {c.criticalityNeedsReview && <div className="conf-warn">Criticality to review</div>}
                  </td>
                  <td>
                    {c.na.length ? c.na.map((label, i) => {
                      const reason = c.reasons[label] || c.reasons[label.replace(" (EOL)", "")]
                        || (label === "Vulnerabilities" ? c.reasons["Patch Status"] : undefined);
                      return (
                        <span key={label} title={reason || "declared NA"} className={reason ? "conf-reason" : undefined}>
                          {i ? ", " : ""}{label}
                        </span>
                      );
                    }) : "-"}
                  </td>
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

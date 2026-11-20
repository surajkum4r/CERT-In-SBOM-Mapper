import React, { useMemo, useState } from "react";
import "../styles/components/VexPanel.css";
import {
  REMEDIATION_DATE_PROPERTY, RESTART_PROPERTY, RESTART_REQUIRED, VEX_JUSTIFICATIONS, VEX_RESPONSES, VEX_STATUSES, statusOf,
} from "../services/certInDocumentService";

const prop = (v, name) => (v.properties || []).find((p) => p.name === name)?.value;
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

// CERT-In section 6: record the exploitability status of every vulnerability, then publish
// it as CycloneDX VEX and a CSAF 2.0 advisory.
export default function VexPanel({ vulnerabilities, components, onChange, onExportVex, onExportCsaf, onBack }) {
  const [filter, setFilter] = useState("all");
  const [publisher, setPublisher] = useState("");
  const [namespace, setNamespace] = useState("");
  const [expanded, setExpanded] = useState(() => new Set());
  const toggle = (index) => setExpanded((prev) => {
    const next = new Set(prev);
    if (next.has(index)) next.delete(index);
    else next.add(index);
    return next;
  });

  const names = useMemo(() => {
    const m = new Map();
    for (const c of components || []) m.set(c["bom-ref"], `${c.name}${c.version ? "@" + c.version : ""}`);
    return m;
  }, [components]);

  const rows = useMemo(() => (vulnerabilities || [])
    .map((v, index) => ({ v, index, status: statusOf(v) }))
    .filter(({ status }) => filter === "all" || status.key === filter)
    .sort((a, b) => String(prop(a.v, "cert-in:priority") || "P9").localeCompare(String(prop(b.v, "cert-in:priority") || "P9"))
      || (SEV_RANK[a.v.ratings?.[0]?.severity] ?? 9) - (SEV_RANK[b.v.ratings?.[0]?.severity] ?? 9)), [vulnerabilities, filter]);

  const counts = useMemo(() => {
    const out = Object.fromEntries(VEX_STATUSES.map((s) => [s.key, 0]));
    for (const v of vulnerabilities || []) out[statusOf(v).key] += 1;
    return out;
  }, [vulnerabilities]);

  // only the changed fields are sent; setVulnerabilityAnalysis keeps the rest
  const update = (index, v, patch) => onChange(index, patch);
  const toggleResponse = (index, v, value) => {
    const current = v.analysis?.response || [];
    update(index, v, { response: current.includes(value) ? current.filter((r) => r !== value) : [...current, value] });
  };

  return (
    <div className="vex-panel">
      <div className="vex-header">
        <button className="btn btn-secondary" onClick={onBack}>← Back to components</button>
        <h3>Vulnerability status (VEX) - CERT-In section 6</h3>
      </div>
      <p className="vex-intro">
        Record the exploitability status of each vulnerability. New findings start as <em>Under Investigation</em>.
        Choose <em>Not affected</em> with a justification when the vulnerable code cannot be reached in your product.
      </p>

      <div className="vex-summary">
        <button className={filter === "all" ? "vex-chip active" : "vex-chip"} onClick={() => setFilter("all")}>
          All ({(vulnerabilities || []).length})
        </button>
        {VEX_STATUSES.map((s) => (
          <button key={s.key} className={filter === s.key ? "vex-chip active" : "vex-chip"} onClick={() => setFilter(s.key)}>
            {s.label} ({counts[s.key]})
          </button>
        ))}
      </div>

      {!(vulnerabilities || []).length ? (
        <p className="vex-empty">No vulnerabilities in this SBOM. Upload an SBOM and wait for processing to finish.</p>
      ) : (
        <div className="vex-table-wrap">
          <table className="vex-table">
            <thead>
              <tr>
                <th>Priority</th><th>ID</th><th>Component(s)</th><th>Severity</th><th>Exploitation</th>
                <th>Status</th><th>Justification</th><th>Detail</th><th />
              </tr>
            </thead>
            <tbody>
              {rows.map(({ v, index, status }) => {
                const kev = prop(v, "cert-in:kev_date_added");
                const epss = prop(v, "cert-in:epss");
                const r = v.ratings?.[0] || {};
                const open = expanded.has(index);
                return (
                  <React.Fragment key={`${v.id}-${index}`}>
                  <tr className={kev ? "vex-row kev" : "vex-row"}>
                    <td>{String(prop(v, "cert-in:priority") || "").split(" - ")[0] || "-"}</td>
                    <td>
                      <a href={v.source?.url || `https://osv.dev/vulnerability/${v.id}`} target="_blank" rel="noreferrer">{v.id}</a>
                      {v.recommendation && <div className="vex-fix">{v.recommendation}</div>}
                    </td>
                    <td>{(v.affects || []).map((a) => names.get(a.ref) || a.ref).join(", ")}</td>
                    <td>{[r.severity, r.score].filter((x) => x !== undefined && x !== null).join(" ") || "-"}</td>
                    <td>
                      {kev && <span className="vex-kev" title={`Added to CISA KEV ${kev}`}>CISA KEV</span>}
                      {epss && <span className="vex-epss">EPSS {Number(epss).toFixed(2)}</span>}
                      {!kev && !epss && "-"}
                    </td>
                    <td>
                      <select value={status.key} onChange={(e) => update(index, v, { status: e.target.value })} aria-label={`Status of ${v.id}`}>
                        {VEX_STATUSES.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
                      </select>
                    </td>
                    <td>
                      {status.key === "not_affected" ? (
                        <select value={v.analysis?.justification || ""} onChange={(e) => update(index, v, { justification: e.target.value })}
                          aria-label={`Justification for ${v.id}`}>
                          <option value="">-- Select --</option>
                          {VEX_JUSTIFICATIONS.map((j) => <option key={j.cdx} value={j.cdx}>{j.label}</option>)}
                        </select>
                      ) : "-"}
                    </td>
                    <td>
                      <input type="text" value={v.analysis?.detail || ""} placeholder="Analysis, impact, fix version..."
                        onChange={(e) => update(index, v, { detail: e.target.value })} aria-label={`Detail for ${v.id}`} />
                    </td>
                    <td>
                      <button className="btn btn-secondary btn-sm" onClick={() => toggle(index)} aria-expanded={open}
                        aria-label={`Remediation details for ${v.id}`}>
                        {open ? "Hide" : "Remediation"}
                      </button>
                    </td>
                  </tr>
                  {open && (
                    <tr className="vex-details">
                      <td colSpan={9}>
                        <div className="vex-details-grid">
                          <fieldset>
                            <legend>Response</legend>
                            {VEX_RESPONSES.map((resp) => (
                              <label key={resp.cdx}>
                                <input type="checkbox" checked={(v.analysis?.response || []).includes(resp.cdx)}
                                  onChange={() => toggleResponse(index, v, resp.cdx)} /> {resp.label}
                              </label>
                            ))}
                          </fieldset>
                          <label>Workaround
                            <textarea rows={2} value={v.workaround || ""} placeholder="Steps to mitigate until a fix is applied"
                              onChange={(e) => update(index, v, { workaround: e.target.value })} aria-label={`Workaround for ${v.id}`} />
                          </label>
                          <label>Restart / downtime required
                            <select value={prop(v, RESTART_PROPERTY) || ""} aria-label={`Restart required for ${v.id}`}
                              onChange={(e) => update(index, v, { restartRequired: e.target.value })}>
                              <option value="">-- Not specified --</option>
                              {RESTART_REQUIRED.map((rr) => <option key={rr.csaf} value={rr.csaf}>{rr.label}</option>)}
                            </select>
                          </label>
                          <label>Fix / remediation available on
                            <input type="date" value={prop(v, REMEDIATION_DATE_PROPERTY) || ""} aria-label={`Remediation date for ${v.id}`}
                              onChange={(e) => update(index, v, { remediationDate: e.target.value })} />
                          </label>
                          <div className="vex-dates">
                            {v.published && <div>Published: {String(v.published).slice(0, 10)}</div>}
                            {v.analysis?.firstIssued && <div>Status first set: {v.analysis.firstIssued.slice(0, 10)}</div>}
                            {v.analysis?.lastUpdated && <div>Last updated: {v.analysis.lastUpdated.slice(0, 10)}</div>}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="vex-export">
        <label>Publisher (organisation)
          <input type="text" value={publisher} onChange={(e) => setPublisher(e.target.value)} placeholder="e.g. Example Org Pvt Ltd" />
        </label>
        <label>Publisher namespace (URL)
          <input type="text" value={namespace} onChange={(e) => setNamespace(e.target.value)} placeholder="e.g. https://example.in" />
        </label>
        <button className="export-button green" onClick={() => onExportVex()} disabled={!(vulnerabilities || []).length}>
          Export CycloneDX VEX
        </button>
        <button className="export-button blue" onClick={() => onExportCsaf({ publisher, namespace })}
          disabled={!(vulnerabilities || []).length || !publisher.trim() || !namespace.trim()}
          title="CSAF requires a publisher name and namespace">
          Export CSAF 2.0 advisory
        </button>
      </div>
    </div>
  );
}

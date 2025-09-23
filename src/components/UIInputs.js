import React from "react";
import { InfoIcon } from "./InfoIcon";
import "../styles/components/UIInputs.css";

export function LabelInput({ label, value, onChange, tooltip }) {
  return (
    <label className="ui-label">
      <span className="ui-label-text">
        {label} <InfoIcon text={tooltip} />
      </span>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="ui-input"
      />
    </label>
  );
}

export function LabelTextArea({ label, value, onChange, rows, tooltip }) {
  return (
    <label className="ui-label">
      <span className="ui-label-text">
        {label} <InfoIcon text={tooltip} />
      </span>
      <textarea
        value={value}
        onChange={(e) => onChange(e.target.value)}
        rows={rows || 3}
        className="ui-textarea"
      />
    </label>
  );
}

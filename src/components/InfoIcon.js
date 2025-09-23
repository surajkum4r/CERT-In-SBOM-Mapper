import React from "react";
import "../styles/components/UIInputs.css"; 

export function InfoIcon({ text }) {
  if (!text) return null;
  return (
    <span className="tooltip">
      <span className="tooltip-icon">i</span>
      <span className="tooltip-text">{text}</span>
    </span>
  );
}

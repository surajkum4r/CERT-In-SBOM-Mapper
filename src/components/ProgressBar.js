import React from "react";
import "../styles/components/ProgressBar.css";

export default function ProgressBar({ progress, label }) {
  return (
    <div className="progress-bar-container">
      {label && <div className="progress-bar-label">{label}</div>}
      <div className="progress-bar-track">
        <div
          className="progress-bar-fill"
          style={{ width: `${progress}%` }}
        />
      </div>
      <div className="progress-bar-percent">{progress}%</div>
    </div>
  );
}

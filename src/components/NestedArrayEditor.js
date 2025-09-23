import React from "react";
import { InfoIcon } from "./InfoIcon";
import "../styles/components/NestedArrayEditor.css";

export function NestedArrayEditor({
  title,
  array,
  onChange,
  onAdd,
  onRemove,
  isLicense = false,
  tooltip,
}) {
  return (
    <fieldset className="nested-editor">
      <legend className="nested-editor-title">
        {title} <InfoIcon text={tooltip} />
      </legend>

      {(array || []).map((item, idx) => (
        <div key={idx} className="nested-editor-row">
          {isLicense ? (
            <input
              type="text"
              placeholder="License ID"
              value={item.license?.id || ""}
              onChange={(e) => onChange(idx, "license.id", e.target.value)}
              className="nested-editor-input"
            />
          ) : (
            Object.keys(item).map((key) => (
              <input
                key={key}
                type="text"
                placeholder={key}
                value={item[key]}
                onChange={(e) => onChange(idx, key, e.target.value)}
                className="nested-editor-input"
              />
            ))
          )}

          <button
            type="button"
            onClick={() => onRemove(idx)}
            className="nested-editor-remove"
          >
            ✕
          </button>
        </div>
      ))}

      <button type="button" onClick={onAdd} className="nested-editor-add">
        + Add {title}
      </button>
    </fieldset>
  );
}

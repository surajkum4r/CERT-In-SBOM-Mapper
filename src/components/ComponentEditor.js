import React from "react";
import { NestedArrayEditor } from "./NestedArrayEditor";
import { CertInProperties, descriptions } from "./CertInProperties"; 
import { LabelInput, LabelTextArea } from "./UIInputs";
import "../styles/components/ComponentEditor.css";

export function ComponentEditor({
  editComponent,
  updateEditField,
  updateNestedField,
  addNestedItem,
  removeNestedItem,
  updatePropertyField,
  saveChanges,
  goBack,
  selectedIndex,
}) {
  return (
    <div>
      <button onClick={goBack} className="back-btn">← Back</button>

      <h2 className="editor-heading">
        Edit Component #{selectedIndex + 1}
      </h2>

      <div className="editor-wrapper">
        <div className="editor-box">
          <LabelInput
            label="Name"
            value={editComponent.name}
            onChange={updateEditField.bind(null, "name")}
            tooltip={descriptions.Name}
          />
          <LabelInput
            label="Version"
            value={editComponent.version}
            onChange={updateEditField.bind(null, "version")}
            tooltip={descriptions.Version}
          />
          <LabelTextArea
            label="Description"
            value={editComponent.description || ""}
            onChange={updateEditField.bind(null, "description")}
            rows={4}
            tooltip={descriptions.Description}
          />
          <LabelInput
            label="Identifier"
            value={editComponent.purl || ""}
            onChange={updateEditField.bind(null, "purl")}
            tooltip={descriptions.Identifier}
          />

          <NestedArrayEditor
            title="Hashes"
            array={editComponent.hashes}
            onChange={(idx, key, val) => updateNestedField("hashes", idx, key, val)}
            onAdd={() => addNestedItem("hashes")}
            onRemove={removeNestedItem.bind(null, "hashes")}
            tooltip={descriptions.Hashes}
          />

          <NestedArrayEditor
            title="Licenses"
            array={editComponent.licenses}
            onChange={(idx, key, val) => updateNestedField("licenses", idx, key, val)}
            onAdd={() => addNestedItem("licenses")}
            onRemove={removeNestedItem.bind(null, "licenses")}
            isLicense
            tooltip={descriptions.Licenses}
          />

          <NestedArrayEditor
            title="External References"
            array={editComponent.externalReferences}
            onChange={(idx, key, val) =>
              updateNestedField("externalReferences", idx, key, val)
            }
            onAdd={() => addNestedItem("externalReferences")}
            onRemove={removeNestedItem.bind(null, "externalReferences")}
            tooltip={descriptions["External References"]}
          />

          <CertInProperties
            properties={editComponent.properties}
            onChange={updatePropertyField}
          />

          <button onClick={saveChanges} className="save-btn">
            Save Changes
          </button>
        </div>
      </div>
    </div>
  );
}

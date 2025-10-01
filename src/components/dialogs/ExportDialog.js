import React from 'react';

const ExportDialog = ({
  showExportDialog,
  exportWithSignature,
  setExportWithSignature,
  exportKeyOption,
  setExportKeyOption,
  isExporting,
  isUploadingKeys,
  exportPrivateKeyFile,
  setExportPrivateKeyFile,
  exportPublicKeyFile,
  setExportPublicKeyFile,
  dialogResetKey,
  clearAllFileStates,
  handleExportWithSignature,
  handleExportWithoutSignature,
  cancelExport,
  handleExportPrivateKeyUpload,
  handleExportPublicKeyUpload,
  uploadKeysForExport,
}) => {
  if (!showExportDialog) return null;

  return (
    <div className="confirmation-overlay">
      <div className="confirmation-dialog export-dialog" key={dialogResetKey}>
        <h4>📤 Export SBOM</h4>
        <p>Choose how you want to export your SBOM:</p>
        
        <div className="export-options">
          <div className="export-option">
            <label>
              <input
                type="radio"
                name="exportType"
                value="without"
                checked={!exportWithSignature}
                onChange={() => {
                  setExportWithSignature(false);
                  setExportKeyOption('generate');
                  clearAllFileStates();
                }}
              />
              <span className="option-label">
                <strong>Export without signature</strong>
                <small>Standard JSON export</small>
              </span>
            </label>
          </div>
          
          <div className="export-option">
            <label>
              <input
                type="radio"
                name="exportType"
                value="with"
                checked={exportWithSignature}
                onChange={() => {
                  setExportWithSignature(true);
                  setExportKeyOption('generate');
                  clearAllFileStates();
                }}
              />
              <span className="option-label">
                <strong>Export with digital signature</strong>
                <small>Creates both SBOM and signature files</small>
              </span>
            </label>
          </div>
        </div>
        
        {exportWithSignature && (
          <div className="signature-options">
            <p><strong>Key Options:</strong></p>
            <div className="key-option">
              <label>
                <input
                  type="radio"
                  name="keyOption"
                  value="generate"
                  checked={exportKeyOption === 'generate'}
                  onChange={() => {
                    setExportKeyOption('generate');
                    clearAllFileStates();
                  }}
                />
                <span>Generate new key pair</span>
              </label>
            </div>
            <div className="key-option">
              <label>
                <input
                  type="radio"
                  name="keyOption"
                  value="upload"
                  checked={exportKeyOption === 'upload'}
                  onChange={() => {
                    setExportKeyOption('upload');
                    clearAllFileStates();
                  }}
                />
                <span>Upload your own keys</span>
              </label>
            </div>
            
            {exportKeyOption === 'upload' && (
              <div className="inline-key-upload">
                <div className="file-input-group">
                  <label htmlFor="exportPrivateKeyInput">Private Key (.pem, .key):</label>
                  <input
                    id="exportPrivateKeyInput"
                    type="file"
                    accept=".pem,.key,.txt"
                    onChange={handleExportPrivateKeyUpload}
                    className="file-input"
                  />
                  {exportPrivateKeyFile && (
                    <span className="file-selected">✅ {exportPrivateKeyFile.name}</span>
                  )}
                </div>
                
                <div className="file-input-group">
                  <label htmlFor="exportPublicKeyInput">Public Key (.pem, .pub):</label>
                  <input
                    id="exportPublicKeyInput"
                    type="file"
                    accept=".pem,.pub,.txt"
                    onChange={handleExportPublicKeyUpload}
                    className="file-input"
                  />
                  {exportPublicKeyFile && (
                    <span className="file-selected">✅ {exportPublicKeyFile.name}</span>
                  )}
                </div>
                
                <div className="upload-keys-section">
                  <button 
                    onClick={uploadKeysForExport}
                    className="btn btn-secondary btn-sm"
                    disabled={isUploadingKeys || !exportPrivateKeyFile || !exportPublicKeyFile}
                  >
                    {isUploadingKeys ? 'Uploading...' : 'Upload Keys'}
                  </button>
                </div>
                
                <div className="key-format-info">
                  <p><strong>Key Format Requirements:</strong></p>
                  <ul>
                    <li>PEM format (-----BEGIN PRIVATE KEY----- / -----BEGIN PUBLIC KEY-----)</li>
                    <li>RSA keys (2048-bit or higher recommended)</li>
                    <li>Private key should be in PKCS#8 format</li>
                  </ul>
                </div>
              </div>
            )}
          </div>
        )}
        
        <div className="confirmation-buttons">
          <button 
            onClick={exportWithSignature ? handleExportWithSignature : handleExportWithoutSignature}
            className="btn btn-primary"
            disabled={isExporting || isUploadingKeys}
          >
            {isExporting ? 'Exporting...' : isUploadingKeys ? 'Uploading Keys...' : 'Export SBOM'}
          </button>
          <button 
            onClick={cancelExport}
            className="btn btn-secondary"
            disabled={isExporting}
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};

export default ExportDialog;
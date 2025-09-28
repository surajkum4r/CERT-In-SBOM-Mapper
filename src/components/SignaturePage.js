import React, { useState, useEffect } from 'react';
import SignatureManager from './SignatureManager';
import '../styles/components/SignaturePage.css';

const SignaturePage = () => {
  const [sbom, setSbom] = useState(null);
  const [notification, setNotification] = useState(null);

  useEffect(() => {
    // Try to load SBOM from sessionStorage or parent window
    const savedSBOM = sessionStorage.getItem('current_sbom');
    if (savedSBOM) {
      try {
        setSbom(JSON.parse(savedSBOM));
      } catch (error) {
        console.error('Failed to load SBOM from sessionStorage:', error);
      }
    }

    // Listen for messages from parent window
    const handleMessage = (event) => {
      if (event.data.type === 'SBOM_DATA') {
        setSbom(event.data.sbom);
        sessionStorage.setItem('current_sbom', JSON.stringify(event.data.sbom));
      }
    };

    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  const showNotification = (message, type = 'error', duration = 5000) => {
    setNotification({ message, type, duration });
    setTimeout(() => setNotification(null), duration);
  };

  const handleSignatureUpdate = (signedSBOM) => {
    setSbom(signedSBOM);
    sessionStorage.setItem('current_sbom', JSON.stringify(signedSBOM));
    
    // Notify parent window
    if (window.opener) {
      window.opener.postMessage({
        type: 'SBOM_UPDATED',
        sbom: signedSBOM
      }, '*');
    }
    
    showNotification("SBOM signature updated successfully!", 'success');
  };

  const loadSBOMFromFile = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const json = JSON.parse(e.target.result);
        if (json.components) {
          setSbom(json);
          sessionStorage.setItem('current_sbom', JSON.stringify(json));
          showNotification("SBOM loaded successfully!", 'success');
        } else {
          showNotification("Invalid SBOM file. Must contain components array.", 'error');
        }
      } catch (error) {
        showNotification("Failed to parse SBOM file: " + error.message, 'error');
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="signature-page">
      <header className="signature-header">
        <h1>🔐 Digital Signature Management</h1>
        <p>CERT-In SBOM Digital Signature Tools</p>
      </header>

      <div className="signature-content">
        {!sbom ? (
          <div className="no-sbom">
            <div className="no-sbom-content">
              <h2>No SBOM Loaded</h2>
              <p>Please load an SBOM file to manage digital signatures.</p>
              
              <div className="load-options">
                <label htmlFor="sbomFile" className="load-btn">
                  📁 Load SBOM File
                </label>
                <input
                  id="sbomFile"
                  type="file"
                  accept=".json"
                  onChange={loadSBOMFromFile}
                  style={{ display: 'none' }}
                />
                
                <button
                  onClick={() => window.close()}
                  className="close-btn"
                >
                  ← Back to Main App
                </button>
              </div>
            </div>
          </div>
        ) : (
          <div className="signature-workspace">
            <div className="sbom-info">
              <h3>Current SBOM</h3>
              <div className="sbom-details">
                <p><strong>Components:</strong> {sbom.components?.length || 0}</p>
                <p><strong>Format:</strong> CycloneDX {sbom.specVersion || 'Unknown'}</p>
                <p><strong>Timestamp:</strong> {sbom.metadata?.timestamp || 'Unknown'}</p>
              </div>
            </div>

            <SignatureManager 
              sbom={sbom} 
              onSignatureUpdate={handleSignatureUpdate}
            />
          </div>
        )}
      </div>

      {notification && (
        <div className={`notification ${notification.type}`}>
          {notification.message}
        </div>
      )}
    </div>
  );
};

export default SignaturePage;

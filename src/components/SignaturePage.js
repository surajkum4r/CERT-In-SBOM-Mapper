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

  const showNotification = (message, type = 'error', duration = 5000, showRedirectButton = false) => {
    setNotification({ message, type, duration, showRedirectButton });
    if (duration > 0) {
      setTimeout(() => setNotification(null), duration);
    }
  };

  const handleManualRedirect = () => {
    // Try to redirect the parent window first, then fallback to current window
    if (window.opener && !window.opener.closed) {
      window.opener.location.href = '/';
      window.close();
    } else {
      window.location.href = '/';
    }
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
          showNotification("SBOM loaded successfully! Redirecting to main view...", 'success');
          
          // Show redirect button as backup
          setTimeout(() => {
            setNotification({
              message: "If you're not redirected automatically, click the button below to go to the main view.",
              type: 'info',
              duration: 10000,
              showRedirectButton: true
            });
          }, 2000);
          
          // Redirect to main app after a short delay
          setTimeout(() => {
            // Store SBOM in sessionStorage for the main app to pick up
            sessionStorage.setItem('current_sbom', JSON.stringify(json));
            sessionStorage.setItem('sbom_upload_redirect', 'true');
            
            // Try to redirect the parent window first, then fallback to current window
            if (window.opener && !window.opener.closed) {
              // Redirect the parent window to main app
              window.opener.location.href = '/';
              window.close();
            } else {
              // If no parent window or parent is closed, redirect current window
              window.location.href = '/';
            }
          }, 1500);
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
          {notification.showRedirectButton && (
            <button 
              onClick={handleManualRedirect}
              className="redirect-button"
              style={{
                marginLeft: '10px',
                padding: '5px 10px',
                backgroundColor: '#007bff',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Go to Main View
            </button>
          )}
        </div>
      )}
    </div>
  );
};

export default SignaturePage;

import React, { useState, useEffect } from 'react';
import StandaloneSignatureService from '../services/standaloneSignatureService';
import '../styles/components/SignatureManager.css';

const SignatureManager = ({ sbom, onBackToTable }) => {
  const [signatureService] = useState(new StandaloneSignatureService());
  const [isVerifying, setIsVerifying] = useState(false);
  const [signatureStatus, setSignatureStatus] = useState(null);
  const [signatureFile, setSignatureFile] = useState(null);
  const [sbomFile, setSbomFile] = useState(null);
  const [verificationSbom, setVerificationSbom] = useState(null);

  const handleSignatureFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      setSignatureFile(file);
      // Clear previous verification status when new file is uploaded
      setSignatureStatus(null);
    }
  };

  const handleSbomFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      setSbomFile(file);
      // Clear previous verification status when new file is uploaded
      setSignatureStatus(null);
      // Read and parse the SBOM file
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const sbomData = JSON.parse(e.target.result);
          setVerificationSbom(sbomData);
        } catch (error) {
          setSignatureStatus({ type: 'error', message: 'Invalid SBOM file format. Please upload a valid JSON file.' });
        }
      };
      reader.readAsText(file);
    }
  };

  const verifySBOM = async () => {
    if (!verificationSbom) {
      setSignatureStatus({ type: 'error', message: 'Please upload the SBOM file to verify.' });
      return;
    }

    if (!signatureFile) {
      setSignatureStatus({ type: 'error', message: 'Please select a signature file (.sig) to verify.' });
      return;
    }

    setIsVerifying(true);
    setSignatureStatus({ type: 'info', message: 'Verifying signature...' });
    try {
      // Read the signature file content
      const signatureContent = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => resolve(e.target.result);
        reader.onerror = (e) => reject(new Error('Failed to read signature file'));
        reader.readAsText(signatureFile);
      });

      const signatureFileContent = JSON.parse(signatureContent);

      // Verify signature using standalone service with separate signature file
      const result = await signatureService.verifySBOM(verificationSbom, signatureFileContent);
      
      if (result.valid) {
        setSignatureStatus({
          type: 'success',
          timestamp: result.signature?.timestamp || new Date().toISOString(),
          message: 'Signature is valid! The SBOM has not been modified since signing.'
        });
      } else {
        setSignatureStatus({
          type: 'error',
          timestamp: new Date().toISOString(),
          message: result.error || 'Signature verification failed. The SBOM may have been modified after signing.'
        });
      }
    } catch (error) {
      setSignatureStatus({ type: 'error', message: 'Failed to verify signature: ' + error.message });
    } finally {
      setIsVerifying(false);
    }
  };



  return (
    <div className="signature-manager">
      <div className="signature-header">
        <div className="header-top">
          <h3>Signature Verification</h3>
          <button 
            onClick={onBackToTable}
            className="btn btn-secondary back-btn"
            title="Back to Components Table"
          >
            ← Back to Table
          </button>
        </div>
        <p>Verify the digital signature of your SBOM using the signature file</p>
      </div>
      
      <div className="signature-section">
        <h4>Step 1: Upload Processed SBOM File</h4>
        <div className="signature-file-upload">
          <p>Upload the <strong>processed SBOM file</strong> (with CERT-In properties) that you want to verify:</p>
          <div className="file-input-group">
            <label htmlFor="sbomFileInput">Processed SBOM File (.json):</label>
            <input
              id="sbomFileInput"
              type="file"
              accept=".json"
              onChange={handleSbomFileUpload}
              className="file-input"
            />
            {sbomFile && (
              <span className="file-selected">✅ {sbomFile.name}</span>
            )}
          </div>
        </div>
      </div>

      <div className="signature-section">
        <h4>Step 2: Upload Signature File</h4>
        <div className="signature-file-upload">
          <p>Upload the signature file (.sig) that was created when the SBOM was signed:</p>
          <div className="file-input-group">
            <label htmlFor="signatureFileInput">Signature File (.sig):</label>
            <input
              id="signatureFileInput"
              type="file"
              accept=".sig,.json"
              onChange={handleSignatureFileUpload}
              className="file-input"
            />
            {signatureFile && (
              <span className="file-selected">✅ {signatureFile.name}</span>
            )}
          </div>
        </div>
      </div>

      <div className="signature-section">
        <h4>Step 3: Verify Signature</h4>
        <div className="signature-actions">
          <button 
            onClick={verifySBOM} 
            disabled={!verificationSbom || !signatureFile || isVerifying}
            className="btn btn-primary"
          >
            {isVerifying ? 'Verifying...' : '✅ Verify Signature'}
          </button>
        </div>
        
        {signatureStatus && (
          <div className="signature-status">
            <div className={`status-indicator ${signatureStatus.type}`}>
              {signatureStatus.type === 'success' && (
                <p>✅ Signature is valid!</p>
              )}
              {signatureStatus.type === 'error' && (
                <p>❌ Signature verification failed</p>
              )}
              {signatureStatus.type === 'info' && (
                <p>⏳ {signatureStatus.message}</p>
              )}
              {signatureStatus.timestamp && (
                <p>Timestamp: {new Date(signatureStatus.timestamp).toLocaleString()}</p>
              )}
              {signatureStatus.message && signatureStatus.type !== 'info' && (
                <p>{signatureStatus.message}</p>
              )}
            </div>
          </div>
        )}
        
        <div className="verification-info">
          <p><strong>How Signature Verification Works:</strong></p>
          <ol>
            <li><strong>Upload Processed SBOM:</strong> Select the processed SBOM file (with CERT-In properties) that was exported with signature</li>
            <li><strong>Upload Signature:</strong> Select the .sig file that was created when the SBOM was signed</li>
            <li><strong>Verification Process:</strong>
              <ul>
                <li>System reads both files</li>
                <li>Creates a canonical (standardized) version of the processed SBOM</li>
                <li>Uses the public key to verify the signature against the canonical SBOM</li>
                <li>Checks if the signature matches the current SBOM content</li>
              </ul>
            </li>
            <li><strong>Result:</strong>
              <ul>
                <li>✅ <strong>Valid:</strong> SBOM has not been modified since signing</li>
                <li>❌ <strong>Invalid:</strong> SBOM was modified after signing (tampered with)</li>
              </ul>
            </li>
          </ol>
        </div>
      </div>

    </div>
  );
};

export default SignatureManager;

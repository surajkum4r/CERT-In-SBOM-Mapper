import React, { useState, useEffect } from 'react';
import StandaloneSignatureService from '../services/standaloneSignatureService';
import '../styles/components/SignatureManager.css';

const SignatureManager = ({ sbom, onSignatureUpdate, onBackToTable }) => {
  const [signatureService] = useState(new StandaloneSignatureService());
  const [hasKeys, setHasKeys] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isSigning, setIsSigning] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [signatureStatus, setSignatureStatus] = useState(null);
  const [publicKey, setPublicKey] = useState('');
  const [showRegenerateConfirm, setShowRegenerateConfirm] = useState(false);

  useEffect(() => {
    setHasKeys(signatureService.hasKeys());
    if (signatureService.hasKeys()) {
      const keys = signatureService.loadKeys();
      setPublicKey(keys.publicKey);
    }
  }, []);

  const generateKeys = async () => {
    setIsGenerating(true);
    setSignatureStatus({ type: 'info', message: 'Generating RSA key pair...' });
    try {
      await signatureService.generateAndSaveKeys();
      setHasKeys(true);
      const keys = signatureService.loadKeys();
      setPublicKey(keys.publicKey);
      setSignatureStatus({ type: 'success', message: 'Key pair generated successfully!' });
    } catch (error) {
      setSignatureStatus({ type: 'error', message: 'Failed to generate keys: ' + error.message });
    } finally {
      setIsGenerating(false);
    }
  };

  const regenerateKeys = () => {
    // Show confirmation dialog
    setShowRegenerateConfirm(true);
  };

  const confirmRegenerate = async () => {
    setShowRegenerateConfirm(false);
    setIsGenerating(true);
    setSignatureStatus({ type: 'info', message: 'Regenerating RSA key pair...' });
    try {
      // Clear existing keys directly
      sessionStorage.removeItem('sbom_private_key');
      sessionStorage.removeItem('sbom_public_key');
      
      // Generate new keys
      await signatureService.generateAndSaveKeys();
      setHasKeys(true);
      const keys = signatureService.loadKeys();
      setPublicKey(keys.publicKey);
      setSignatureStatus({ type: 'success', message: 'New key pair generated successfully!' });
    } catch (error) {
      setSignatureStatus({ type: 'error', message: 'Failed to regenerate keys: ' + error.message });
    } finally {
      setIsGenerating(false);
    }
  };

  const cancelRegenerate = () => {
    setShowRegenerateConfirm(false);
  };

  const signSBOM = async () => {
    if (!sbom) {
      setSignatureStatus({ type: 'error', message: 'No SBOM loaded' });
      return;
    }

    setIsSigning(true);
    setSignatureStatus({ type: 'info', message: 'Signing SBOM...' });
    try {
      const keys = signatureService.loadKeys();
      if (!keys) {
        setSignatureStatus({ type: 'error', message: 'No keys found. Please generate keys first.' });
        return;
      }
      
      // Sign the SBOM using standalone service
      const signedSBOM = await signatureService.signSBOM(sbom);
      
      onSignatureUpdate(signedSBOM);
      setSignatureStatus({ type: 'success', message: 'SBOM signed successfully!', timestamp: new Date().toISOString() });
    } catch (error) {
      setSignatureStatus({ type: 'error', message: 'Failed to sign SBOM: ' + error.message });
    } finally {
      setIsSigning(false);
    }
  };

  const verifySBOM = async () => {
    if (!sbom) {
      setSignatureStatus({ type: 'error', message: 'No SBOM loaded' });
      return;
    }

    setIsVerifying(true);
    setSignatureStatus({ type: 'info', message: 'Verifying signature...' });
    try {
      const keys = signatureService.loadKeys();
      if (!keys) {
        setSignatureStatus({ type: 'error', message: 'No keys found. Please generate keys first.' });
        return;
      }

      // Verify signature using standalone service
      const result = await signatureService.verifySBOM(sbom);
      
      if (result.valid) {
        setSignatureStatus({
          type: 'success',
          timestamp: result.timestamp || new Date().toISOString(),
          message: 'Signature is valid!'
        });
      } else {
        setSignatureStatus({
          type: 'error',
          timestamp: new Date().toISOString(),
          message: result.error || 'Signature verification failed for unknown reason'
        });
      }
    } catch (error) {
      setSignatureStatus({ type: 'error', message: 'Failed to verify signature: ' + error.message });
    } finally {
      setIsVerifying(false);
    }
  };

  const downloadPublicKey = () => {
    if (!publicKey) {
      setSignatureStatus({ type: 'error', message: 'No public key available' });
      return;
    }
    try {
      signatureService.downloadPublicKey();
      setSignatureStatus({ type: 'success', message: 'Public key downloaded successfully!' });
    } catch (error) {
      setSignatureStatus({ type: 'error', message: 'Failed to download public key: ' + error.message });
    }
  };

  return (
    <div className="signature-manager">
      <div className="signature-header">
        <div className="header-top">
          <h3>Digital Signature Management</h3>
          <button 
            onClick={onBackToTable}
            className="btn btn-secondary back-btn"
            title="Back to Components Table"
          >
            ← Back to Table
          </button>
        </div>
        <p>Sign and verify your SBOM for CERT-In compliance</p>
      </div>
      
      <div className="signature-section">
        <h4>Key Management</h4>
        {!hasKeys ? (
          <div className="key-generation">
            <p>No signing keys found. Generate a new key pair to sign SBOMs.</p>
            <button 
              onClick={generateKeys} 
              disabled={isGenerating}
              className="btn btn-primary"
            >
              {isGenerating ? 'Generating...' : 'Generate Key Pair'}
            </button>
          </div>
        ) : (
          <div className="key-management">
            <p className="success">✅ Key pair available</p>
            <div className="key-actions">
              <button 
                onClick={downloadPublicKey}
                className="btn btn-secondary"
              >
                Download Public Key
              </button>
              <button 
                onClick={regenerateKeys}
                disabled={isGenerating}
                className="btn btn-warning"
                title="Generate new keys (this will delete current keys)"
              >
                {isGenerating ? 'Regenerating...' : '🔄 Regenerate Keys'}
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="signature-section">
        <h4>SBOM Signing & Verification</h4>
        <div className="signature-actions">
          <button 
            onClick={signSBOM} 
            disabled={!hasKeys || !sbom || isSigning}
            className="btn btn-primary"
          >
            {isSigning ? 'Signing...' : '🔐 Sign SBOM'}
          </button>
          
          <button 
            onClick={verifySBOM} 
            disabled={!hasKeys || !sbom || isVerifying}
            className="btn btn-secondary"
          >
            {isVerifying ? 'Verifying...' : '✅ Verify Signature'}
          </button>
        </div>
      </div>

      {signatureStatus && (
        <div className="signature-status">
          <h4>Signature Status</h4>
          <div className={`status-indicator ${signatureStatus.type}`}>
            {signatureStatus.type === 'signed' && (
              <p>✅ SBOM signed successfully</p>
            )}
            {signatureStatus.type === 'verified' && (
              <p>✅ Signature verified</p>
            )}
            {signatureStatus.type === 'invalid' && (
              <p>❌ Signature invalid</p>
            )}
            {signatureStatus.type === 'unsigned' && (
              <p>⚠️ No signature found</p>
            )}
            {signatureStatus.timestamp && (
              <p>Timestamp: {new Date(signatureStatus.timestamp).toLocaleString()}</p>
            )}
            {signatureStatus.message && (
              <p>{signatureStatus.message}</p>
            )}
          </div>
        </div>
      )}

      <div className="signature-info">
        <h4>About Digital Signatures</h4>
        <div className="info-grid">
          <div className="info-item">
            <span className="info-icon">🔒</span>
            <span><strong>Integrity:</strong> Tamper detection</span>
          </div>
          <div className="info-item">
            <span className="info-icon">🆔</span>
            <span><strong>Authenticity:</strong> Creator verification</span>
          </div>
          <div className="info-item">
            <span className="info-icon">✅</span>
            <span><strong>Compliance:</strong> CERT-In requirements</span>
          </div>
          <div className="info-item">
            <span className="info-icon">🤝</span>
            <span><strong>Trust:</strong> Supply chain confidence</span>
          </div>
        </div>
      </div>

      {/* Regenerate Keys Confirmation Dialog */}
      {showRegenerateConfirm && (
        <div className="confirmation-overlay">
          <div className="confirmation-dialog">
            <h4>⚠️ Regenerate Keys</h4>
            <p>This will delete your current keys and generate new ones. This action cannot be undone.</p>
            <p><strong>Are you sure you want to continue?</strong></p>
            <div className="confirmation-buttons">
              <button 
                onClick={confirmRegenerate}
                className="btn btn-danger"
                disabled={isGenerating}
              >
                {isGenerating ? 'Regenerating...' : 'Yes, Regenerate'}
              </button>
              <button 
                onClick={cancelRegenerate}
                className="btn btn-secondary"
                disabled={isGenerating}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SignatureManager;

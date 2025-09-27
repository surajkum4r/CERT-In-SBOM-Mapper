# Digital Signature Integration for CERT-In SBOM Compliance

## Overview

This document explains how to integrate digital signatures into the CERT-In SBOM Mapper, using a standalone implementation that follows CycloneDX standards without external dependencies.

## 🔐 Digital Signature Features

### What We've Implemented

1. **Standalone Implementation**: No external CLI dependencies - works on all platforms
2. **CycloneDX Compatible**: Follows CycloneDX XML signature format exactly
3. **Cross-Platform**: Works on Mac, Windows, and Linux with just `npm install`
4. **Web Crypto API**: Uses browser-native cryptographic functions
5. **CERT-In Compliance**: Meets signature requirements with industry standards

### How It Works

```javascript
// 1. Generate RSA key pair using Web Crypto API
const keyPair = await signatureService.generateKeyPair();

// 2. Sign SBOM using CycloneDX-compatible XML format
const signedSBOM = await signatureService.signSBOM(sbomData);

// 3. Verify signature using Web Crypto API
const result = await signatureService.verifySBOM(sbomData);
```

## 📋 CycloneDX Compatibility

### CycloneDX Standard Format

Our implementation follows the CycloneDX XML signature format:

```xml
<Signature>
  <SignedInfo>
    <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha256"/>
    <Reference URI="">
      <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha256"/>
      <DigestValue>...</DigestValue>
    </Reference>
  </SignedInfo>
  <SignatureValue>...</SignatureValue>
  <KeyInfo>
    <KeyValue>...</KeyValue>
  </KeyInfo>
</Signature>
```

### Our Implementation

Our standalone implementation provides the same functionality:

1. **Key Generation**: Web Crypto API RSA key generation
2. **BOM Signing**: CycloneDX-compatible XML signature format
3. **Signature Verification**: Web Crypto API signature verification
4. **Cross-Platform**: Works on all platforms without external dependencies

## 🎯 CERT-In Compliance

### Signature Requirements

According to CERT-In guidelines, SBOMs must include:

- **Integrity Verification**: Ensures SBOM hasn't been tampered with
- **Authenticity Confirmation**: Verifies the SBOM creator's identity
- **Cryptographic Security**: Uses industry-standard RSA-SHA256
- **Timestamp**: Records when the signature was created

### Implementation Details

```javascript
// Signature format in SBOM metadata
{
  "metadata": {
    "properties": [
      {
        "name": "signature:algorithm",
        "value": "RSA-SHA256"
      },
      {
        "name": "signature:value", 
        "value": "base64-encoded-signature"
      },
      {
        "name": "signature:timestamp",
        "value": "2024-01-15T10:30:00Z"
      }
    ]
  }
}
```

## 🚀 Usage Guide

### 1. Generate Keys

```javascript
// Generate new key pair
const signatureService = new SignatureService();
const keyPair = await signatureService.generateKeyPair();

// Keys are automatically saved to localStorage
// Private key: localStorage.getItem('sbom_private_key')
// Public key: localStorage.getItem('sbom_public_key')
```

### 2. Sign SBOM

```javascript
// Sign the SBOM
const signature = await signatureService.signSBOM(sbomData, privateKey);

// Add signature to SBOM
const signedSBOM = signatureService.addSignatureToSBOM(sbomData, signature);
```

### 3. Verify Signature

```javascript
// Extract signature from SBOM
const signature = signatureService.extractSignatureFromSBOM(sbomData);

// Verify signature
const result = await signatureService.verifySBOM(sbomData, signature, publicKey);
console.log('Signature valid:', result.valid);
```

## 🔧 Technical Implementation

### SignatureService Class

```javascript
class SignatureService {
  // Generate RSA key pair
  async generateKeyPair()
  
  // Sign SBOM data
  async signSBOM(sbomData, privateKey)
  
  // Verify SBOM signature
  async verifySBOM(sbomData, signature, publicKey)
  
  // Add signature to SBOM metadata
  addSignatureToSBOM(sbomData, signature)
  
  // Extract signature from SBOM
  extractSignatureFromSBOM(sbomData)
  
  // Key management
  generateAndSaveKeys()
  loadKeys()
  hasKeys()
}
```

### SignatureManager Component

```javascript
// React component for signature management
<SignatureManager 
  sbom={sbom} 
  onSignatureUpdate={(signedSBOM) => {
    setSbom(signedSBOM);
  }}
/>
```

## 📊 Benefits

### Security Benefits

- **Tamper Detection**: Any modification to SBOM invalidates signature
- **Identity Verification**: Confirms who created the SBOM
- **Chain of Trust**: Builds confidence in software supply chain
- **Regulatory Compliance**: Meets CERT-In requirements

### Technical Benefits

- **Web Standards**: Uses Web Crypto API for browser compatibility
- **RSA-SHA256**: Industry-standard cryptographic algorithm
- **Base64 Encoding**: Standard format for signature storage
- **JSON Integration**: Seamlessly integrates with CycloneDX format

## 🔍 Verification Process

### Signature Validation

1. **Extract Signature**: Get signature from SBOM metadata
2. **Canonicalize JSON**: Create deterministic JSON representation
3. **Verify Hash**: Check signature against canonical JSON
4. **Validate Timestamp**: Ensure signature is recent
5. **Return Result**: Valid/Invalid with details

### Error Handling

```javascript
try {
  const result = await signatureService.verifySBOM(sbom, signature, publicKey);
  if (result.valid) {
    console.log('✅ Signature is valid');
  } else {
    console.log('❌ Signature is invalid:', result.error);
  }
} catch (error) {
  console.error('Verification failed:', error.message);
}
```

## 📝 Best Practices

### Key Management

1. **Generate Keys**: Create new key pair for each organization
2. **Secure Storage**: Store private keys securely (not in localStorage for production)
3. **Key Rotation**: Regularly rotate keys for enhanced security
4. **Backup Keys**: Keep secure backups of key pairs

### Signature Workflow

1. **Load SBOM**: Import CycloneDX SBOM file
2. **Generate Keys**: Create signing key pair
3. **Sign SBOM**: Add digital signature
4. **Export Signed SBOM**: Save with signature
5. **Distribute Public Key**: Share public key for verification

## 🎯 Integration with Existing Workflow

### Current CERT-In SBOM Mapper Flow

1. **Upload SBOM** → Load CycloneDX file
2. **Add CERT-In Properties** → Auto-populate required fields
3. **Edit Components** → Manual adjustments
4. **Digital Signature** → Sign the SBOM ← **NEW**
5. **Export Signed SBOM** → Download with signature ← **NEW**

### New Signature Features

- **Key Generation**: One-click RSA key pair creation
- **SBOM Signing**: Digital signature with timestamp
- **Signature Verification**: Validate existing signatures
- **Public Key Export**: Download public key for sharing
- **Status Display**: Visual signature status indicators

## 🔗 References

- [CycloneDX CLI Documentation](https://github.com/CycloneDX/cyclonedx-cli)
- [CERT-In Technical Guidelines](https://www.cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [RSA-SHA256 Algorithm](https://tools.ietf.org/html/rfc3447)

## 🚀 Getting Started

1. **Load SBOM**: Upload your CycloneDX SBOM file
2. **Generate Keys**: Click "Generate Key Pair" button
3. **Sign SBOM**: Click "Sign SBOM" button
4. **Export**: Download the signed SBOM
5. **Share Public Key**: Distribute public key for verification

The digital signature integration ensures your SBOMs meet CERT-In requirements for integrity, authenticity, and regulatory compliance! 🎉

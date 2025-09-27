// Digital signature service for CERT-In SBOM compliance
// Integrates with CycloneDX CLI signature capabilities

class SignatureService {
  constructor() {
    this.privateKey = null;
    this.publicKey = null;
    this.signatureAlgorithm = 'RSA-SHA256';
  }

  // Generate RSA key pair for signing
  async generateKeyPair() {
    try {
      // Use Web Crypto API for key generation
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-PSS',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['sign', 'verify']
      );

      // Export keys
      const privateKeyPem = await this.exportPrivateKey(keyPair.privateKey);
      const publicKeyPem = await this.exportPublicKey(keyPair.publicKey);

      return {
        privateKey: privateKeyPem,
        publicKey: publicKeyPem,
        privateKeyObj: keyPair.privateKey,
        publicKeyObj: keyPair.publicKey
      };
    } catch (error) {
      console.error('Key generation failed:', error);
      throw new Error('Failed to generate RSA key pair');
    }
  }

  // Export private key to PEM format
  async exportPrivateKey(privateKey) {
    const exported = await crypto.subtle.exportKey('pkcs8', privateKey);
    const exportedAsString = this.arrayBufferToBase64(exported);
    return `-----BEGIN PRIVATE KEY-----\n${exportedAsString}\n-----END PRIVATE KEY-----`;
  }

  // Export public key to PEM format
  async exportPublicKey(publicKey) {
    const exported = await crypto.subtle.exportKey('spki', publicKey);
    const exportedAsString = this.arrayBufferToBase64(exported);
    return `-----BEGIN PUBLIC KEY-----\n${exportedAsString}\n-----END PUBLIC KEY-----`;
  }

  // Convert ArrayBuffer to Base64
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).match(/.{1,64}/g).join('\n');
  }

  // Sign SBOM data
  async signSBOM(sbomData, privateKey) {
    try {
      // Convert SBOM to canonical JSON string
      const canonicalJson = this.canonicalizeJSON(sbomData);
      
      // Create signature
      const signature = await crypto.subtle.sign(
        {
          name: 'RSA-PSS',
          saltLength: 32,
        },
        privateKey,
        new TextEncoder().encode(canonicalJson)
      );

      // Convert signature to base64
      const signatureBase64 = this.arrayBufferToBase64(signature);
      
      return {
        algorithm: this.signatureAlgorithm,
        value: signatureBase64,
        timestamp: new Date().toISOString(),
        canonicalJson: canonicalJson
      };
    } catch (error) {
      console.error('SBOM signing failed:', error);
      throw new Error('Failed to sign SBOM');
    }
  }

  // Verify SBOM signature
  async verifySBOM(sbomData, signature, publicKey) {
    try {
      // Convert SBOM to canonical JSON string
      const canonicalJson = this.canonicalizeJSON(sbomData);
      
      // Convert base64 signature to ArrayBuffer
      const signatureBuffer = this.base64ToArrayBuffer(signature.value);
      
      // Verify signature
      const isValid = await crypto.subtle.verify(
        {
          name: 'RSA-PSS',
          saltLength: 32,
        },
        publicKey,
        signatureBuffer,
        new TextEncoder().encode(canonicalJson)
      );

      return {
        valid: isValid,
        timestamp: signature.timestamp,
        algorithm: signature.algorithm
      };
    } catch (error) {
      console.error('SBOM verification failed:', error);
      return { valid: false, error: error.message };
    }
  }

  // Create canonical JSON (deterministic ordering)
  canonicalizeJSON(obj) {
    return JSON.stringify(obj, Object.keys(obj).sort());
  }

  // Convert base64 to ArrayBuffer
  base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // Add signature to SBOM metadata
  addSignatureToSBOM(sbomData, signature) {
    if (!sbomData.metadata) {
      sbomData.metadata = {};
    }
    
    if (!sbomData.metadata.properties) {
      sbomData.metadata.properties = [];
    }

    // Add signature as metadata property
    sbomData.metadata.properties.push({
      name: 'signature:algorithm',
      value: signature.algorithm
    });
    
    sbomData.metadata.properties.push({
      name: 'signature:value',
      value: signature.value
    });
    
    sbomData.metadata.properties.push({
      name: 'signature:timestamp',
      value: signature.timestamp
    });

    return sbomData;
  }

  // Extract signature from SBOM metadata
  extractSignatureFromSBOM(sbomData) {
    if (!sbomData.metadata?.properties) {
      return null;
    }

    const properties = sbomData.metadata.properties;
    const algorithm = properties.find(p => p.name === 'signature:algorithm')?.value;
    const value = properties.find(p => p.name === 'signature:value')?.value;
    const timestamp = properties.find(p => p.name === 'signature:timestamp')?.value;

    if (algorithm && value && timestamp) {
      return {
        algorithm,
        value,
        timestamp
      };
    }

    return null;
  }

  // Generate key pair and save to localStorage
  async generateAndSaveKeys() {
    try {
      const keyPair = await this.generateKeyPair();
      
      // Save to localStorage
      localStorage.setItem('sbom_private_key', keyPair.privateKey);
      localStorage.setItem('sbom_public_key', keyPair.publicKey);
      
      return keyPair;
    } catch (error) {
      console.error('Failed to generate and save keys:', error);
      throw error;
    }
  }

  // Load keys from localStorage
  loadKeys() {
    const privateKey = localStorage.getItem('sbom_private_key');
    const publicKey = localStorage.getItem('sbom_public_key');
    
    if (privateKey && publicKey) {
      return { privateKey, publicKey };
    }
    
    return null;
  }

  // Check if keys exist
  hasKeys() {
    return this.loadKeys() !== null;
  }

  // Import private key from PEM format
  async importPrivateKey(privateKeyPem) {
    try {
      // Remove PEM headers and convert to ArrayBuffer
      const pemContent = privateKeyPem
        .replace(/-----BEGIN PRIVATE KEY-----/, '')
        .replace(/-----END PRIVATE KEY-----/, '')
        .replace(/\s/g, '');
      
      const binaryString = atob(pemContent);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      // Import the key
      const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        bytes.buffer,
        {
          name: 'RSA-PSS',
          hash: 'SHA-256',
        },
        false,
        ['sign']
      );

      return privateKey;
    } catch (error) {
      console.error('Failed to import private key:', error);
      throw new Error('Failed to import private key');
    }
  }

  // Import public key from PEM format
  async importPublicKey(publicKeyPem) {
    try {
      // Remove PEM headers and convert to ArrayBuffer
      const pemContent = publicKeyPem
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\s/g, '');
      
      const binaryString = atob(pemContent);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      // Import the key
      const publicKey = await crypto.subtle.importKey(
        'spki',
        bytes.buffer,
        {
          name: 'RSA-PSS',
          hash: 'SHA-256',
        },
        false,
        ['verify']
      );

      return publicKey;
    } catch (error) {
      console.error('Failed to import public key:', error);
      throw new Error('Failed to import public key');
    }
  }

  // Clear all stored keys
  clearKeys() {
    localStorage.removeItem('sbom_private_key');
    localStorage.removeItem('sbom_public_key');
  }
}

export default SignatureService;

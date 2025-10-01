// Standalone signature service for CERT-In SBOM compliance
// Implements CycloneDX XML signature format without external dependencies
// Works across all platforms (Mac/Windows/Linux)

class StandaloneSignatureService {
  constructor() {
    this.privateKey = null;
    this.publicKey = null;
    this.signatureAlgorithm = 'RSA-SHA256';
  }

  // Generate RSA key pair using Web Crypto API
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

      // Store keys
      this.privateKey = keyPair.privateKey;
      this.publicKey = keyPair.publicKey;

      // Save to secure storage (sessionStorage for better security)
      try {
        sessionStorage.setItem('sbom_private_key', privateKeyPem);
        sessionStorage.setItem('sbom_public_key', publicKeyPem);
      } catch (error) {
        console.warn('Failed to save keys to session storage:', error);
        // Fallback to memory storage only
      }

      return {
        privateKey: privateKeyPem,
        publicKey: publicKeyPem,
        privateKeyObj: keyPair.privateKey,
        publicKeyObj: keyPair.publicKey
      };
    } catch (error) {
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

  // Create canonical XML representation of SBOM
  canonicalizeSBOM(sbomData) {
    // Convert SBOM to canonical JSON first
    const canonicalJson = JSON.stringify(sbomData, Object.keys(sbomData).sort());
    
    // Create XML representation similar to CycloneDX CLI
    const xmlContent = this.jsonToXML(canonicalJson);
    
    // Canonicalize XML (remove whitespace, normalize)
    return this.canonicalizeXML(xmlContent);
  }

  // Convert JSON to XML format (simplified CycloneDX format)
  jsonToXML(jsonData) {
    const data = JSON.parse(jsonData);
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">\n';
    
    // Add metadata
    if (data.metadata) {
      xml += '  <metadata>\n';
      if (data.metadata.timestamp) {
        xml += `    <timestamp>${data.metadata.timestamp}</timestamp>\n`;
      }
      if (data.metadata.tools) {
        xml += '    <tools>\n';
        data.metadata.tools.forEach(tool => {
          xml += '      <tool>\n';
          if (tool.vendor) xml += `        <vendor>${tool.vendor}</vendor>\n`;
          if (tool.name) xml += `        <name>${tool.name}</name>\n`;
          if (tool.version) xml += `        <version>${tool.version}</version>\n`;
          xml += '      </tool>\n';
        });
        xml += '    </tools>\n';
      }
      xml += '  </metadata>\n';
    }
    
    // Add components
    if (data.components) {
      data.components.forEach(component => {
        xml += '  <component type="library">\n';
        if (component.name) xml += `    <name>${component.name}</name>\n`;
        if (component.version) xml += `    <version>${component.version}</version>\n`;
        if (component.description) xml += `    <description>${component.description}</description>\n`;
        if (component.purl) xml += `    <purl>${component.purl}</purl>\n`;
        xml += '  </component>\n';
      });
    }
    
    xml += '</bom>';
    return xml;
  }

  // Canonicalize XML (remove extra whitespace, normalize)
  canonicalizeXML(xml) {
    return xml
      .replace(/\s+/g, ' ')  // Replace multiple spaces with single space
      .replace(/>\s+</g, '><')  // Remove spaces between tags
      .trim();
  }

  // Sign SBOM and create separate signature file (like CycloneDX CLI)
  async signSBOM(sbomData, filename = 'sbom.json') {
    try {
      // Always load keys from storage to ensure we have the latest keys
      const keys = this.loadKeys();
      if (!keys) {
        throw new Error('No private key found');
      }
      
      // Debug: Log key data
      console.log('Loaded keys for signing:', {
        hasPrivateKey: !!keys.privateKey,
        hasPublicKey: !!keys.publicKey,
        privateKeyLength: keys.privateKey?.length || 0,
        publicKeyLength: keys.publicKey?.length || 0,
        privateKeyPreview: keys.privateKey?.substring(0, 50) + '...'
      });
      
      // Import private key (always reload from storage)
      let privateKey;
      try {
        privateKey = await this.importPrivateKey(keys.privateKey);
        console.log('Successfully imported private key');
      } catch (error) {
        console.error('Failed to import private key:', error);
        throw new Error('Failed to import private key: ' + error.message);
      }

      // Clean SBOM data (no need to remove signature since we're not embedding)
      const cleanedSBOM = this.cleanSBOMData(sbomData);
      console.log('Cleaned SBOM data (removed Promise objects)');
      
      // Create canonical JSON from the cleaned SBOM
      const canonicalJson = JSON.stringify(this.canonicalizeJSON(cleanedSBOM));
      
      // Debug: Log canonical JSON for debugging
      console.log('Canonical JSON for signing:', canonicalJson);
      
      console.log('About to sign with:');
      console.log('- Private key:', privateKey);
      console.log('- Canonical JSON length:', canonicalJson.length);
      console.log('- Canonical JSON preview:', canonicalJson.substring(0, 100) + '...');
      
      // Create signature using Web Crypto API
      const signature = await crypto.subtle.sign(
        {
          name: 'RSA-PSS',
          saltLength: 32,
        },
        privateKey,
        new TextEncoder().encode(canonicalJson)
      );
      
      console.log('Signature created, length:', signature.byteLength);

      // Convert signature to base64
      const signatureBase64 = this.arrayBufferToBase64(signature);
      
      // Debug: Log signature data
      console.log('Created signature:', {
        algorithm: this.signatureAlgorithm,
        valueLength: signatureBase64.length,
        valuePreview: signatureBase64.substring(0, 50) + '...',
        fullSignature: signatureBase64
      });
      
      // Create separate signature file content (like CycloneDX CLI)
      const signatureFileContent = {
        algorithm: this.signatureAlgorithm,
        timestamp: new Date().toISOString(),
        value: signatureBase64,
        canonicalJson: canonicalJson
      };
      
      // Create signature file name (filename.json.sig)
      const signatureFileName = filename.endsWith('.json') 
        ? filename + '.sig' 
        : filename + '.json.sig';
      
      console.log('Creating separate signature file:', signatureFileName);
      
      // Return both the original SBOM (unchanged) and signature file info
      return {
        sbom: sbomData, // Original SBOM unchanged
        signatureFile: {
          filename: signatureFileName,
          content: signatureFileContent
        }
      };
    } catch (error) {
      throw new Error('Failed to sign SBOM: ' + error.message);
    }
  }

  // Create signature element
  createXMLSignature(signatureValue, canonicalJson) {
    const timestamp = new Date().toISOString();
    
    return {
      type: 'json-signature',
      algorithm: this.signatureAlgorithm,
      timestamp: timestamp,
      signatureValue: signatureValue,
      canonicalJson: canonicalJson
    };
  }

  // Calculate SHA-256 digest of content
  async calculateDigest(content) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return this.arrayBufferToBase64(hashBuffer);
  }

  // Add signature to SBOM
  addXMLSignatureToSBOM(sbomData, signatureElement) {
    // Create a copy of the SBOM
    const signedSBOM = JSON.parse(JSON.stringify(sbomData));
    
    // Add signature as a special property
    if (!signedSBOM.metadata) {
      signedSBOM.metadata = {};
    }
    
    if (!signedSBOM.metadata.properties) {
      signedSBOM.metadata.properties = [];
    }

    // Add signature properties
    signedSBOM.metadata.properties.push({
      name: 'signature:type',
      value: 'json-signature'
    });
    
    signedSBOM.metadata.properties.push({
      name: 'signature:algorithm',
      value: signatureElement.algorithm
    });
    
    signedSBOM.metadata.properties.push({
      name: 'signature:timestamp',
      value: signatureElement.timestamp
    });
    
    signedSBOM.metadata.properties.push({
      name: 'signature:value',
      value: signatureElement.signatureValue
    });

    return signedSBOM;
  }

  // Verify SBOM signature from separate signature file
  async verifySBOM(sbomData, signatureFileContent) {
    try {
      // Always load keys from storage to ensure we have the latest keys
      const keys = this.loadKeys();
      if (!keys) {
        return { valid: false, error: 'No public key found. Please generate keys first.' };
      }
      
      // Debug: Log key data
      console.log('Loaded keys from storage:', {
        hasPrivateKey: !!keys.privateKey,
        hasPublicKey: !!keys.publicKey,
        privateKeyLength: keys.privateKey?.length || 0,
        publicKeyLength: keys.publicKey?.length || 0,
        publicKeyPreview: keys.publicKey?.substring(0, 50) + '...'
      });
      
      // Import public key (always reload from storage)
      let publicKey;
      try {
        publicKey = await this.importPublicKey(keys.publicKey);
        console.log('Successfully imported public key');
      } catch (error) {
        console.error('Failed to import public key:', error);
        return { valid: false, error: 'Failed to import public key: ' + error.message };
      }

      // Check if signature file has required properties
      if (!signatureFileContent || !signatureFileContent.value || !signatureFileContent.algorithm) {
        return { valid: false, error: 'Invalid signature file format. Missing signature value or algorithm.' };
      }

      // Debug: Log signature data
      console.log('Signature file content:', {
        algorithm: signatureFileContent.algorithm,
        timestamp: signatureFileContent.timestamp,
        valueLength: signatureFileContent.value?.length || 0,
        valuePreview: signatureFileContent.value?.substring(0, 50) + '...',
        fullSignature: signatureFileContent.value
      });

      // Clean SBOM data (same as signing process)
      const cleanedSBOM = this.cleanSBOMData(sbomData);
      console.log('Cleaned SBOM data for verification (removed Promise objects)');
      
      // Create canonical JSON from the cleaned SBOM (same as signing)
      const canonicalJson = JSON.stringify(this.canonicalizeJSON(cleanedSBOM));
      
      // Debug: Log canonical JSON for debugging
      console.log('Canonical JSON for verification:', canonicalJson);
      console.log('Canonical JSON comparison - Are they identical?', 
        canonicalJson === signatureFileContent.canonicalJson
      );
      
      // Verify signature
      let signatureBuffer;
      try {
        console.log('Original signature value length:', signatureFileContent.value.length);
        console.log('Original signature value preview:', signatureFileContent.value.substring(0, 50) + '...');
        
        signatureBuffer = this.base64ToArrayBuffer(signatureFileContent.value);
        console.log('Decoded signature buffer length:', signatureBuffer.byteLength);
      } catch (error) {
        console.error('Base64 decode error:', error);
        return { valid: false, error: 'Invalid signature format. Cannot decode base64 signature.' };
      }
      
      console.log('About to verify signature with:');
      console.log('- Public key:', publicKey);
      console.log('- Signature buffer length:', signatureBuffer.byteLength);
      console.log('- Canonical JSON length:', canonicalJson.length);
      console.log('- Canonical JSON preview:', canonicalJson.substring(0, 100) + '...');
      
      const isValid = await crypto.subtle.verify(
        {
          name: 'RSA-PSS',
          saltLength: 32,
        },
        publicKey,
        signatureBuffer,
        new TextEncoder().encode(canonicalJson)
      );
      
      console.log('Verification result:', isValid);

      return {
        valid: isValid,
        message: isValid ? 'Signature is valid' : 'Signature verification failed',
        signature: signatureFileContent
      };
    } catch (error) {
      // Provide more specific error information
      const errorMessage = error.message || error.toString() || 'Unknown error occurred';
      
      // Check for specific error types
      if (errorMessage.includes('verification') || errorMessage.includes('signature')) {
        return { 
          valid: false, 
          error: 'Signature verification failed. This could be due to:\n• The SBOM was modified after signing\n• The signature was created with different keys\n• Please re-sign the SBOM with the current keys' 
        };
      }
      
      return { valid: false, error: 'Verification failed: ' + errorMessage };
    }
  }

  // Extract signature from SBOM
  extractSignatureFromSBOM(sbomData) {
    if (!sbomData.metadata?.properties) {
      return null;
    }

    const properties = sbomData.metadata.properties;
    const algorithm = properties.find(p => p.name === 'signature:algorithm')?.value;
    const value = properties.find(p => p.name === 'signature:value')?.value;
    const timestamp = properties.find(p => p.name === 'signature:timestamp')?.value;

    // Check if we have the required signature properties

    if (algorithm && value && timestamp) {
      return {
        algorithm,
        value,
        timestamp
      };
    }

    return null;
  }

  // Import private key from PEM format
  async importPrivateKey(privateKeyPem) {
    try {
      const pemContent = privateKeyPem
        .replace(/-----BEGIN PRIVATE KEY-----/, '')
        .replace(/-----END PRIVATE KEY-----/, '')
        .replace(/\s/g, '');
      
      const binaryString = atob(pemContent);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

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
      throw new Error('Failed to import private key');
    }
  }

  // Import public key from PEM format
  async importPublicKey(publicKeyPem) {
    try {
      const pemContent = publicKeyPem
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\s/g, '');
      
      const binaryString = atob(pemContent);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

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
      throw new Error('Failed to import public key');
    }
  }

  // Convert base64 to ArrayBuffer
  base64ToArrayBuffer(base64) {
    // Remove newlines that were added during encoding
    const cleanBase64 = base64.replace(/\s/g, '');
    const binaryString = atob(cleanBase64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // Load keys from secure storage
  loadKeys() {
    try {
      const privateKey = sessionStorage.getItem('sbom_private_key');
      const publicKey = sessionStorage.getItem('sbom_public_key');
      
      if (privateKey && publicKey) {
        return { privateKey, publicKey };
      }
    } catch (error) {
      console.warn('Failed to load keys from session storage:', error);
    }
    
    return null;
  }

  // Check if keys exist
  hasKeys() {
    return this.loadKeys() !== null;
  }

  // Upload and save private key
  async uploadPrivateKey(keyFile) {
    try {
      const keyContent = await this.readFileAsText(keyFile);
      
      // Validate the key format
      if (!this.isValidPrivateKey(keyContent)) {
        throw new Error('Invalid private key format. Please upload a valid PEM-formatted private key.');
      }
      
      // Save to sessionStorage
      sessionStorage.setItem('sbom_private_key', keyContent);
      
      return { success: true, message: 'Private key uploaded successfully!' };
    } catch (error) {
      throw new Error('Failed to upload private key: ' + error.message);
    }
  }

  // Upload and save public key
  async uploadPublicKey(keyFile) {
    try {
      const keyContent = await this.readFileAsText(keyFile);
      
      // Validate the key format
      if (!this.isValidPublicKey(keyContent)) {
        throw new Error('Invalid public key format. Please upload a valid PEM-formatted public key.');
      }
      
      // Save to sessionStorage
      sessionStorage.setItem('sbom_public_key', keyContent);
      
      return { success: true, message: 'Public key uploaded successfully!' };
    } catch (error) {
      throw new Error('Failed to upload public key: ' + error.message);
    }
  }

  // Upload both keys at once
  async uploadKeyPair(privateKeyFile, publicKeyFile) {
    try {
      const privateKeyContent = await this.readFileAsText(privateKeyFile);
      const publicKeyContent = await this.readFileAsText(publicKeyFile);
      
      // Validate both keys
      if (!this.isValidPrivateKey(privateKeyContent)) {
        throw new Error('Invalid private key format. Please upload a valid PEM-formatted private key.');
      }
      
      if (!this.isValidPublicKey(publicKeyContent)) {
        throw new Error('Invalid public key format. Please upload a valid PEM-formatted public key.');
      }
      
      // Save both keys to sessionStorage
      sessionStorage.setItem('sbom_private_key', privateKeyContent);
      sessionStorage.setItem('sbom_public_key', publicKeyContent);
      
      return { success: true, message: 'Key pair uploaded successfully!' };
    } catch (error) {
      throw new Error('Failed to upload key pair: ' + error.message);
    }
  }

  // Helper method to read file as text
  readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = (e) => reject(new Error('Failed to read file'));
      reader.readAsText(file);
    });
  }

  // Validate private key format
  isValidPrivateKey(keyContent) {
    return keyContent.includes('-----BEGIN PRIVATE KEY-----') && 
           keyContent.includes('-----END PRIVATE KEY-----');
  }

  // Validate public key format
  isValidPublicKey(keyContent) {
    return keyContent.includes('-----BEGIN PUBLIC KEY-----') && 
           keyContent.includes('-----END PUBLIC KEY-----');
  }

  // Check if SBOM signature was created with current keys
  async isSignatureFromCurrentKeys(sbomData) {
    try {
      const keys = this.loadKeys();
      if (!keys) {
        return { isCurrent: false, error: 'No keys found' };
      }

      // Extract signature timestamp
      const signature = this.extractSignatureFromSBOM(sbomData);
      if (!signature) {
        return { isCurrent: false, error: 'No signature found' };
      }

      // For now, we'll assume if keys exist, they're current
      // In a more sophisticated implementation, we could store key fingerprints
      return { isCurrent: true };
    } catch (error) {
      return { isCurrent: false, error: error.message };
    }
  }

  // Clear all stored keys
  clearKeys() {
    try {
      sessionStorage.removeItem('sbom_private_key');
      sessionStorage.removeItem('sbom_public_key');
    } catch (error) {
      console.warn('Failed to clear keys from session storage:', error);
    }
    this.privateKey = null;
    this.publicKey = null;
  }

  // Download public key for sharing
  downloadPublicKey() {
    const keys = this.loadKeys();
    if (!keys) {
      throw new Error('No keys found');
    }
    
    const blob = new Blob([keys.publicKey], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'public.key';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // Download private key (for backup)
  downloadPrivateKey() {
    const keys = this.loadKeys();
    if (!keys) {
      throw new Error('No keys found');
    }
    
    const blob = new Blob([keys.privateKey], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'private.key';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // Generate key pair and save to localStorage (compatibility method)
  async generateAndSaveKeys() {
    try {
      const keyPair = await this.generateKeyPair();
      
      // Keys are already saved in generateKeyPair method
      return keyPair;
    } catch (error) {
      throw error;
    }
  }

  // Remove signature from SBOM for signing
  removeSignatureFromSBOM(sbomData) {
    const sbomCopy = JSON.parse(JSON.stringify(sbomData));
    
    if (sbomCopy.metadata?.properties) {
      sbomCopy.metadata.properties = sbomCopy.metadata.properties.filter(prop => 
        !prop.name.startsWith('signature:')
      );
    }
    
    return sbomCopy;
  }

  // Clean SBOM data by removing Promise objects and other invalid values
  cleanSBOMData(sbomData) {
    const sbomCopy = JSON.parse(JSON.stringify(sbomData));
    
    // Recursively clean the SBOM data
    const cleanObject = (obj) => {
      if (obj === null || obj === undefined) {
        return obj;
      }
      
      if (Array.isArray(obj)) {
        return obj.map(item => cleanObject(item));
      }
      
      if (typeof obj === 'object') {
        const cleaned = {};
        for (const [key, value] of Object.entries(obj)) {
          if (typeof value === 'string' && value.includes('[object Promise]')) {
            // Replace Promise objects with "NA"
            cleaned[key] = 'NA';
          } else {
            cleaned[key] = cleanObject(value);
          }
        }
        return cleaned;
      }
      
      return obj;
    };
    
    return cleanObject(sbomCopy);
  }

  // Create canonical JSON (deterministic ordering for all nested objects)
  canonicalizeJSON(obj) {
    if (obj === null || obj === undefined) {
      return obj;
    }
    
    if (Array.isArray(obj)) {
      return obj.map(item => this.canonicalizeJSON(item));
    }
    
    if (typeof obj === 'object') {
      const sortedKeys = Object.keys(obj).sort();
      const canonicalObj = {};
      for (const key of sortedKeys) {
        canonicalObj[key] = this.canonicalizeJSON(obj[key]);
      }
      return canonicalObj;
    }
    
    return obj;
  }
}

export default StandaloneSignatureService;

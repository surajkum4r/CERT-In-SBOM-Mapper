// Centralized error handling service
class ErrorService {
  constructor() {
    this.errorTypes = {
      NETWORK: 'network',
      VALIDATION: 'validation',
      PARSING: 'parsing',
      API: 'api',
      UNKNOWN: 'unknown'
    };
  }

  // Categorize error types
  categorizeError(error) {
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      return this.errorTypes.NETWORK;
    }
    if (error.name === 'SyntaxError') {
      return this.errorTypes.PARSING;
    }
    if (error.message && error.message.includes('validation')) {
      return this.errorTypes.VALIDATION;
    }
    if (error.status || error.statusCode) {
      return this.errorTypes.API;
    }
    return this.errorTypes.UNKNOWN;
  }

  // Generate user-friendly error messages
  getUserFriendlyMessage(error, context = '') {
    const category = this.categorizeError(error);
    
    switch (category) {
      case this.errorTypes.NETWORK:
        return {
          title: 'Network Error',
          message: 'Unable to connect to the server. Please check your internet connection and try again.',
          action: 'Retry'
        };
      
      case this.errorTypes.PARSING:
        return {
          title: 'Invalid File Format',
          message: 'The uploaded file is not a valid JSON or CycloneDX SBOM format. Please check the file and try again.',
          action: 'Upload Different File'
        };
      
      case this.errorTypes.VALIDATION:
        return {
          title: 'Validation Error',
          message: error.message || 'The provided data is invalid. Please check your input and try again.',
          action: 'Fix Input'
        };
      
      case this.errorTypes.API:
        const status = error.status || error.statusCode;
        if (status === 404) {
          return {
            title: 'Not Found',
            message: 'The requested resource was not found. This might be a temporary issue.',
            action: 'Retry'
          };
        }
        if (status === 429) {
          return {
            title: 'Rate Limited',
            message: 'Too many requests. Please wait a moment and try again.',
            action: 'Wait and Retry'
          };
        }
        if (status >= 500) {
          return {
            title: 'Server Error',
            message: 'The server encountered an error. Please try again later.',
            action: 'Retry Later'
          };
        }
        return {
          title: 'API Error',
          message: `Request failed with status ${status}. Please try again.`,
          action: 'Retry'
        };
      
      default:
        return {
          title: 'Unexpected Error',
          message: context || 'An unexpected error occurred. Please try again or contact support if the problem persists.',
          action: 'Retry'
        };
    }
  }

  // Log error for debugging
  logError(error, context = '', additionalInfo = {}) {
    const errorInfo = {
      timestamp: new Date().toISOString(),
      error: {
        name: error.name,
        message: error.message,
        stack: error.stack
      },
      context,
      additionalInfo,
      userAgent: navigator.userAgent,
      url: window.location.href
    };

    console.error('ErrorService - Logged Error:', errorInfo);

    // In production, you might want to send this to an error tracking service
    if (process.env.NODE_ENV === 'production' && window.reportError) {
      window.reportError(error, { context, additionalInfo });
    }
  }

  // Handle specific SBOM-related errors
  handleSBOMError(error, fileName = '') {
    if (error.message.includes('components')) {
      return {
        title: 'Invalid SBOM Structure',
        message: `The file "${fileName}" is not a valid CycloneDX SBOM. It must contain a 'components' array.`,
        action: 'Check File Format'
      };
    }
    
    if (error.message.includes('JSON')) {
      return {
        title: 'Invalid JSON',
        message: `The file "${fileName}" is not valid JSON. Please ensure it's a properly formatted JSON file.`,
        action: 'Validate JSON'
      };
    }

    return this.getUserFriendlyMessage(error, `Error processing SBOM file: ${fileName}`);
  }

  // Handle API fetch errors
  handleAPIError(error, endpoint = '') {
    this.logError(error, `API call to ${endpoint}`);
    
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      return {
        title: 'Connection Failed',
        message: `Unable to connect to ${endpoint}. Please check your internet connection.`,
        action: 'Retry'
      };
    }

    return this.getUserFriendlyMessage(error, `API error for ${endpoint}`);
  }

  // Create retry mechanism
  async withRetry(operation, maxRetries = 3, delay = 1000) {
    let lastError;
    
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await operation();
      } catch (error) {
        lastError = error;
        this.logError(error, `Retry attempt ${attempt}/${maxRetries}`);
        
        if (attempt < maxRetries) {
          await new Promise(resolve => setTimeout(resolve, delay * attempt));
        }
      }
    }
    
    throw lastError;
  }
}

// Create singleton instance
const errorService = new ErrorService();

export default errorService;

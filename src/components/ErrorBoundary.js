import React from 'react';
import '../styles/components/ErrorBoundary.css';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { 
      hasError: false, 
      error: null, 
      errorInfo: null,
      retryCount: 0 
    };
  }

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    // Log error details
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    
    this.setState({
      error: error,
      errorInfo: errorInfo
    });

    // Log to external service if available
    if (window.reportError) {
      window.reportError(error, errorInfo);
    }
  }

  handleRetry = () => {
    this.setState(prevState => ({
      hasError: false,
      error: null,
      errorInfo: null,
      retryCount: prevState.retryCount + 1
    }));
  };

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      // Custom fallback UI
      return (
        <div className="error-boundary">
          <div className="error-boundary-content">
            <div className="error-icon">⚠️</div>
            <h2 className="error-title">Something went wrong</h2>
            <p className="error-message">
              The application encountered an unexpected error. This might be due to:
            </p>
            <ul className="error-reasons">
              <li>Invalid SBOM file format</li>
              <li>Network connectivity issues</li>
              <li>Browser compatibility problems</li>
              <li>Corrupted data in the application</li>
            </ul>
            
            <div className="error-actions">
              <button 
                onClick={this.handleRetry}
                className="error-btn error-btn-primary"
              >
                Try Again
              </button>
              <button 
                onClick={this.handleReload}
                className="error-btn error-btn-secondary"
              >
                Reload Page
              </button>
            </div>

            {process.env.NODE_ENV === 'development' && (
              <details className="error-details">
                <summary>Technical Details (Development Only)</summary>
                <div className="error-stack">
                  <strong>Error:</strong> {this.state.error?.toString()}
                  <br />
                  <strong>Component Stack:</strong>
                  <pre>{this.state.errorInfo?.componentStack}</pre>
                </div>
              </details>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;

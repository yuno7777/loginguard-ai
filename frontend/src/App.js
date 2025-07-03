import React, { useState, useRef } from 'react';
import './App.css';

const App = () => {
  const [activeTab, setActiveTab] = useState('upload');
  const [uploadedFile, setUploadedFile] = useState(null);
  const [rawLogs, setRawLogs] = useState('');
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const backendUrl = process.env.REACT_APP_BACKEND_URL || 'http://localhost:8001';

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      setUploadedFile(file);
      setError(null);
    }
  };

  const handleDragOver = (event) => {
    event.preventDefault();
  };

  const handleDrop = (event) => {
    event.preventDefault();
    const file = event.dataTransfer.files[0];
    if (file) {
      setUploadedFile(file);
      setError(null);
    }
  };

  const analyzeCSVFile = async () => {
    if (!uploadedFile) {
      setError('Please select a CSV file first');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', uploadedFile);

      const response = await fetch(`${backendUrl}/api/upload-csv`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      setAnalysisResult(result);
    } catch (err) {
      setError(`Error analyzing file: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const analyzeRawLogs = async () => {
    if (!rawLogs.trim()) {
      setError('Please enter some log data first');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('raw_logs', rawLogs);

      const response = await fetch(`${backendUrl}/api/analyze-raw-logs`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      setAnalysisResult(result);
    } catch (err) {
      setError(`Error analyzing logs: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case 'HIGH':
        return 'risk-high';
      case 'MEDIUM':
        return 'risk-medium';
      case 'LOW':
        return 'risk-low';
      default:
        return 'risk-unknown';
    }
  };

  const getRiskIcon = (riskLevel) => {
    switch (riskLevel) {
      case 'HIGH':
        return 'CRITICAL';
      case 'MEDIUM':
        return 'WARNING';
      case 'LOW':
        return 'SAFE';
      default:
        return 'UNKNOWN';
    }
  };

  const sampleCSVData = `username,ip_address,timestamp,location,device,login_status
john_doe,192.168.1.100,2024-01-15 09:15:23,New York,Chrome/Windows,success
jane_smith,10.0.0.55,2024-01-15 14:30:45,London,Firefox/macOS,success
admin_user,203.0.113.45,2024-01-15 23:45:12,Tokyo,Chrome/Linux,failed
john_doe,198.51.100.78,2024-01-16 02:15:30,Moscow,Safari/iOS,success
test_user,192.168.1.100,2024-01-16 08:30:15,New York,Chrome/Windows,failed`;

  const sampleRawData = `2024-01-15 09:15:23|john_doe|192.168.1.100|New York|Chrome/Windows|success
2024-01-15 14:30:45|jane_smith|10.0.0.55|London|Firefox/macOS|success
2024-01-15 23:45:12|admin_user|203.0.113.45|Tokyo|Chrome/Linux|failed
2024-01-16 02:15:30|john_doe|198.51.100.78|Moscow|Safari/iOS|success
2024-01-16 08:30:15|test_user|192.168.1.100|New York|Chrome/Windows|failed`;

  const loadSampleData = () => {
    if (activeTab === 'raw') {
      setRawLogs(sampleRawData);
    } else {
      const blob = new Blob([sampleCSVData], { type: 'text/csv' });
      const file = new File([blob], 'sample_logs.csv', { type: 'text/csv' });
      setUploadedFile(file);
    }
  };

  const resetAnalysis = () => {
    setAnalysisResult(null);
    setError(null);
    setUploadedFile(null);
    setRawLogs('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const LogCard = ({ log, index }) => {
    const [expanded, setExpanded] = useState(false);
    
    return (
      <div className={`log-card ${getRiskColor(log.risk_level)}`}>
        <div className="log-card-header">
          <div className="log-card-info">
            <div className="log-card-title">
              <span className="log-number">#{index + 1}</span>
              <span className="log-username">{log.username}</span>
              <span className={`risk-badge ${getRiskColor(log.risk_level)}`}>
                {getRiskIcon(log.risk_level)}
              </span>
            </div>
            <div className="log-card-details">
              <div className="detail-item">
                <span className="detail-label">IP:</span>
                <span className="detail-value">{log.ip_address}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Location:</span>
                <span className="detail-value">{log.location}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Time:</span>
                <span className="detail-value">{log.timestamp}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Device:</span>
                <span className="detail-value">{log.device}</span>
              </div>
              <div className="detail-item">
                <span className="detail-label">Status:</span>
                <span className={`status-badge ${log.login_status}`}>{log.login_status}</span>
              </div>
            </div>
          </div>
          <button
            onClick={() => setExpanded(!expanded)}
            className="expand-btn"
          >
            {expanded ? 'LESS' : 'MORE'}
          </button>
        </div>
        {expanded && (
          <div className="log-card-expanded">
            {log.risk_factors && log.risk_factors.length > 0 && (
              <div className="risk-factors">
                <h4>Risk Factors:</h4>
                <ul>
                  {log.risk_factors.map((factor, i) => (
                    <li key={i}>{factor}</li>
                  ))}
                </ul>
              </div>
            )}
            {log.explanation && (
              <div className="explanation">
                <h4>Analysis:</h4>
                <p>{log.explanation}</p>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="app">
      {/* Header */}
      <header className="header">
        <div className="header-content">
          <div className="logo">
            <div className="logo-icon">🛡️</div>
            <h1>LoginGuard AI</h1>
          </div>
          <div className="header-subtitle">
            AI-Powered Login Security Analysis
          </div>
        </div>
      </header>

      <main className="main">
        {!analysisResult ? (
          <div className="upload-section">
            {/* Hero Section */}
            <div className="hero">
              <div className="hero-content">
                <h2 className="hero-title">Detect Suspicious Login Activity</h2>
                <p className="hero-subtitle">
                  Upload your login logs and let AI identify potential security threats, 
                  unusual patterns, and provide actionable recommendations.
                </p>
              </div>
              <div className="hero-visual">
                <div className="security-icon">🔐</div>
              </div>
            </div>

            {/* Tab Navigation */}
            <div className="tab-container">
              <div className="tab-nav">
                <button
                  onClick={() => setActiveTab('upload')}
                  className={`tab-btn ${activeTab === 'upload' ? 'active' : ''}`}
                >
                  <span className="tab-icon">FILE</span>
                  Upload CSV
                </button>
                <button
                  onClick={() => setActiveTab('raw')}
                  className={`tab-btn ${activeTab === 'raw' ? 'active' : ''}`}
                >
                  <span className="tab-icon">TEXT</span>
                  Paste Raw Logs
                </button>
              </div>
            </div>

            {/* Upload Content */}
            {activeTab === 'upload' && (
              <div className="upload-card">
                <h3 className="card-title">Upload CSV Log File</h3>
                <p className="card-subtitle">
                  Expected columns: username, ip_address, timestamp, location, device, login_status
                </p>
                
                <div
                  className="dropzone"
                  onDragOver={handleDragOver}
                  onDrop={handleDrop}
                >
                  <div className="dropzone-content">
                    <div className="dropzone-icon">FILE</div>
                    <p className="dropzone-text">
                      Drag and drop your CSV file here
                    </p>
                    <p className="dropzone-subtext">or click to select</p>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".csv"
                      onChange={handleFileUpload}
                      className="file-input"
                    />
                    <button
                      onClick={() => fileInputRef.current.click()}
                      className="select-btn"
                    >
                      Select File
                    </button>
                  </div>
                </div>

                {uploadedFile && (
                  <div className="file-selected">
                    <div className="file-info">
                      <span className="file-icon">READY</span>
                      <span className="file-name">{uploadedFile.name}</span>
                    </div>
                  </div>
                )}

                <div className="action-buttons">
                  <button
                    onClick={analyzeCSVFile}
                    disabled={!uploadedFile || loading}
                    className="analyze-btn primary"
                  >
                    {loading ? (
                      <>
                        <div className="spinner"></div>
                        Analyzing...
                      </>
                    ) : (
                      <>Analyze Logs</>
                    )}
                  </button>
                  <button
                    onClick={loadSampleData}
                    className="sample-btn secondary"
                  >
                    Load Sample Data
                  </button>
                </div>
              </div>
            )}

            {/* Raw Logs Content */}
            {activeTab === 'raw' && (
              <div className="upload-card">
                <h3 className="card-title">Paste Raw Log Data</h3>
                <p className="card-subtitle">
                  Format: timestamp|username|ip_address|location|device|login_status (one per line)
                </p>
                
                <textarea
                  value={rawLogs}
                  onChange={(e) => setRawLogs(e.target.value)}
                  placeholder="Paste your raw log data here..."
                  className="raw-textarea"
                />

                <div className="action-buttons">
                  <button
                    onClick={analyzeRawLogs}
                    disabled={!rawLogs.trim() || loading}
                    className="analyze-btn primary"
                  >
                    {loading ? (
                      <>
                        <div className="spinner"></div>
                        Analyzing...
                      </>
                    ) : (
                      <>Analyze Logs</>
                    )}
                  </button>
                  <button
                    onClick={loadSampleData}
                    className="sample-btn secondary"
                  >
                    Load Sample Data
                  </button>
                </div>
              </div>
            )}

            {/* Error Display */}
            {error && (
              <div className="error-card">
                <div className="error-content">
                  <span className="error-icon">ERROR</span>
                  <span className="error-text">{error}</span>
                </div>
              </div>
            )}
          </div>
        ) : (
          /* Analysis Results */
          <div className="results-section">
            {/* Results Header */}
            <div className="results-header">
              <h2 className="results-title">Analysis Results</h2>
              <button
                onClick={resetAnalysis}
                className="new-analysis-btn"
              >
                New Analysis
              </button>
            </div>

            {/* Overall Risk Summary */}
            <div className={`risk-summary-card ${getRiskColor(analysisResult.overall_risk_score)}`}>
              <div className="risk-summary-header">
                <div className="risk-icon-large">
                  {getRiskIcon(analysisResult.overall_risk_score)}
                </div>
                <div className="risk-summary-info">
                  <h3 className="risk-level">
                    Overall Risk Level: {analysisResult.overall_risk_score}
                  </h3>
                  <p className="risk-description">{analysisResult.risk_summary}</p>
                </div>
              </div>
              
              <div className="risk-stats">
                <div className="stat-item high">
                  <div className="stat-number">{analysisResult.high_risk_logs.length}</div>
                  <div className="stat-label">High Risk</div>
                </div>
                <div className="stat-item medium">
                  <div className="stat-number">{analysisResult.medium_risk_logs.length}</div>
                  <div className="stat-label">Medium Risk</div>
                </div>
                <div className="stat-item low">
                  <div className="stat-number">{analysisResult.low_risk_logs.length}</div>
                  <div className="stat-label">Low Risk</div>
                </div>
              </div>
            </div>

            {/* Recommendations */}
            {analysisResult.recommendations && analysisResult.recommendations.length > 0 && (
              <div className="recommendations-card">
                <h3 className="card-title">
                  <span className="title-icon">RECOMMENDATIONS</span>
                  Security Recommendations
                </h3>
                <ul className="recommendations-list">
                  {analysisResult.recommendations.map((rec, index) => (
                    <li key={index} className="recommendation-item">
                      <span className="rec-bullet">•</span>
                      <span className="rec-text">{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* High Risk Logs */}
            {analysisResult.high_risk_logs.length > 0 && (
              <div className="logs-section">
                <h3 className="section-title">
                  <span className="section-icon">CRITICAL</span>
                  High Risk Logs ({analysisResult.high_risk_logs.length})
                </h3>
                <div className="logs-grid">
                  {analysisResult.high_risk_logs.map((log, index) => (
                    <LogCard key={index} log={log} index={index} />
                  ))}
                </div>
              </div>
            )}

            {/* Medium Risk Logs */}
            {analysisResult.medium_risk_logs.length > 0 && (
              <div className="logs-section">
                <h3 className="section-title">
                  <span className="section-icon">WARNING</span>
                  Medium Risk Logs ({analysisResult.medium_risk_logs.length})
                </h3>
                <div className="logs-grid">
                  {analysisResult.medium_risk_logs.map((log, index) => (
                    <LogCard key={index} log={log} index={index} />
                  ))}
                </div>
              </div>
            )}

            {/* Low Risk Logs */}
            {analysisResult.low_risk_logs.length > 0 && (
              <div className="logs-section">
                <h3 className="section-title">
                  <span className="section-icon">SAFE</span>
                  Low Risk Logs ({analysisResult.low_risk_logs.length})
                </h3>
                <div className="logs-grid">
                  {analysisResult.low_risk_logs.slice(0, 5).map((log, index) => (
                    <LogCard key={index} log={log} index={index} />
                  ))}
                  {analysisResult.low_risk_logs.length > 5 && (
                    <div className="more-logs">
                      <span className="more-logs-text">
                        ... and {analysisResult.low_risk_logs.length - 5} more low risk logs
                      </span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
};

export default App;
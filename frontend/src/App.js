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
        return 'bg-red-100 text-red-800 border-red-300';
      case 'MEDIUM':
        return 'bg-yellow-100 text-yellow-800 border-yellow-300';
      case 'LOW':
        return 'bg-green-100 text-green-800 border-green-300';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-300';
    }
  };

  const getOverallRiskColor = (riskLevel) => {
    switch (riskLevel) {
      case 'HIGH':
        return 'bg-red-50 border-red-200';
      case 'MEDIUM':
        return 'bg-yellow-50 border-yellow-200';
      case 'LOW':
        return 'bg-green-50 border-green-200';
      default:
        return 'bg-gray-50 border-gray-200';
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
      // Create and set sample CSV file
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
      <div className={`border rounded-lg p-4 mb-3 ${getRiskColor(log.risk_level)}`}>
        <div className="flex justify-between items-start">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <span className="font-semibold text-sm">#{index + 1}</span>
              <span className="font-medium">{log.username}</span>
              <span className={`px-2 py-1 rounded text-xs font-medium ${getRiskColor(log.risk_level)}`}>
                {log.risk_level} RISK
              </span>
            </div>
            <div className="text-sm text-gray-600 grid grid-cols-2 gap-2">
              <span><strong>IP:</strong> {log.ip_address}</span>
              <span><strong>Location:</strong> {log.location}</span>
              <span><strong>Time:</strong> {log.timestamp}</span>
              <span><strong>Device:</strong> {log.device}</span>
              <span><strong>Status:</strong> {log.login_status}</span>
            </div>
          </div>
          <button
            onClick={() => setExpanded(!expanded)}
            className="ml-4 text-blue-600 hover:text-blue-800 text-sm font-medium"
          >
            {expanded ? 'Hide' : 'Details'}
          </button>
        </div>
        {expanded && (
          <div className="mt-3 pt-3 border-t border-gray-200">
            {log.risk_factors && log.risk_factors.length > 0 && (
              <div className="mb-2">
                <strong className="text-sm">Risk Factors:</strong>
                <ul className="list-disc list-inside text-sm text-gray-600 mt-1">
                  {log.risk_factors.map((factor, i) => (
                    <li key={i}>{factor}</li>
                  ))}
                </ul>
              </div>
            )}
            {log.explanation && (
              <div>
                <strong className="text-sm">Explanation:</strong>
                <p className="text-sm text-gray-600 mt-1">{log.explanation}</p>
              </div>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                <h1 className="text-2xl font-bold text-gray-900">🛡️ LogSentinel Lite</h1>
              </div>
            </div>
            <div className="text-sm text-gray-600">
              AI-Powered Login Security Analysis
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {!analysisResult ? (
          <div className="space-y-8">
            {/* Hero Section */}
            <div className="text-center">
              <h2 className="text-3xl font-bold text-gray-900 mb-4">
                Detect Suspicious Login Activity
              </h2>
              <p className="text-lg text-gray-600 mb-8">
                Upload your login logs and let AI identify potential security threats, 
                unusual patterns, and provide actionable recommendations.
              </p>
            </div>

            {/* Tab Navigation */}
            <div className="flex justify-center">
              <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg">
                <button
                  onClick={() => setActiveTab('upload')}
                  className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeTab === 'upload'
                      ? 'bg-white text-gray-900 shadow-sm'
                      : 'text-gray-500 hover:text-gray-700'
                  }`}
                >
                  📁 Upload CSV
                </button>
                <button
                  onClick={() => setActiveTab('raw')}
                  className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                    activeTab === 'raw'
                      ? 'bg-white text-gray-900 shadow-sm'
                      : 'text-gray-500 hover:text-gray-700'
                  }`}
                >
                  📝 Paste Raw Logs
                </button>
              </div>
            </div>

            {/* Upload Section */}
            {activeTab === 'upload' && (
              <div className="bg-white rounded-lg shadow-sm p-6">
                <h3 className="text-lg font-semibold mb-4">Upload CSV Log File</h3>
                <p className="text-sm text-gray-600 mb-4">
                  Expected CSV columns: username, ip_address, timestamp, location, device, login_status
                </p>
                
                <div
                  className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center hover:border-gray-400 transition-colors"
                  onDragOver={handleDragOver}
                  onDrop={handleDrop}
                >
                  <div className="space-y-4">
                    <div className="text-6xl">📁</div>
                    <div>
                      <p className="text-gray-600 mb-2">
                        Drag and drop your CSV file here, or click to select
                      </p>
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept=".csv"
                        onChange={handleFileUpload}
                        className="hidden"
                      />
                      <button
                        onClick={() => fileInputRef.current.click()}
                        className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
                      >
                        Select CSV File
                      </button>
                    </div>
                  </div>
                </div>

                {uploadedFile && (
                  <div className="mt-4 p-4 bg-green-50 rounded-lg">
                    <p className="text-green-800">
                      ✅ Selected file: <strong>{uploadedFile.name}</strong>
                    </p>
                  </div>
                )}

                <div className="mt-6 flex gap-4">
                  <button
                    onClick={analyzeCSVFile}
                    disabled={!uploadedFile || loading}
                    className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 disabled:bg-gray-300 transition-colors flex items-center gap-2"
                  >
                    {loading ? (
                      <>
                        <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full"></div>
                        Analyzing...
                      </>
                    ) : (
                      <>🔍 Analyze Logs</>
                    )}
                  </button>
                  <button
                    onClick={loadSampleData}
                    className="bg-gray-600 text-white px-6 py-2 rounded-md hover:bg-gray-700 transition-colors"
                  >
                    📋 Load Sample Data
                  </button>
                </div>
              </div>
            )}

            {/* Raw Logs Section */}
            {activeTab === 'raw' && (
              <div className="bg-white rounded-lg shadow-sm p-6">
                <h3 className="text-lg font-semibold mb-4">Paste Raw Log Data</h3>
                <p className="text-sm text-gray-600 mb-4">
                  Format: timestamp|username|ip_address|location|device|login_status (one per line)
                </p>
                
                <textarea
                  value={rawLogs}
                  onChange={(e) => setRawLogs(e.target.value)}
                  placeholder="Paste your raw log data here..."
                  className="w-full h-64 p-4 border border-gray-300 rounded-md resize-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                />

                <div className="mt-6 flex gap-4">
                  <button
                    onClick={analyzeRawLogs}
                    disabled={!rawLogs.trim() || loading}
                    className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 disabled:bg-gray-300 transition-colors flex items-center gap-2"
                  >
                    {loading ? (
                      <>
                        <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full"></div>
                        Analyzing...
                      </>
                    ) : (
                      <>🔍 Analyze Logs</>
                    )}
                  </button>
                  <button
                    onClick={loadSampleData}
                    className="bg-gray-600 text-white px-6 py-2 rounded-md hover:bg-gray-700 transition-colors"
                  >
                    📋 Load Sample Data
                  </button>
                </div>
              </div>
            )}

            {/* Error Display */}
            {error && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="flex items-center">
                  <span className="text-red-600 mr-2">⚠️</span>
                  <span className="text-red-800">{error}</span>
                </div>
              </div>
            )}
          </div>
        ) : (
          /* Analysis Results */
          <div className="space-y-8">
            {/* Header with Reset Button */}
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-gray-900">Analysis Results</h2>
              <button
                onClick={resetAnalysis}
                className="bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700 transition-colors"
              >
                📝 New Analysis
              </button>
            </div>

            {/* Overall Risk Summary */}
            <div className={`rounded-lg p-6 border-2 ${getOverallRiskColor(analysisResult.overall_risk_score)}`}>
              <div className="flex items-center gap-3 mb-4">
                <span className="text-2xl">
                  {analysisResult.overall_risk_score === 'HIGH' ? '🚨' : 
                   analysisResult.overall_risk_score === 'MEDIUM' ? '⚠️' : '✅'}
                </span>
                <h3 className="text-xl font-semibold">
                  Overall Risk Level: {analysisResult.overall_risk_score}
                </h3>
              </div>
              <p className="text-gray-700 mb-4">{analysisResult.risk_summary}</p>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-center">
                <div className="bg-red-100 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{analysisResult.high_risk_logs.length}</div>
                  <div className="text-sm text-red-600">High Risk</div>
                </div>
                <div className="bg-yellow-100 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-yellow-600">{analysisResult.medium_risk_logs.length}</div>
                  <div className="text-sm text-yellow-600">Medium Risk</div>
                </div>
                <div className="bg-green-100 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">{analysisResult.low_risk_logs.length}</div>
                  <div className="text-sm text-green-600">Low Risk</div>
                </div>
              </div>
            </div>

            {/* Recommendations */}
            {analysisResult.recommendations && analysisResult.recommendations.length > 0 && (
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  💡 Security Recommendations
                </h3>
                <ul className="space-y-2">
                  {analysisResult.recommendations.map((rec, index) => (
                    <li key={index} className="flex items-start gap-2">
                      <span className="text-blue-600 mt-1">•</span>
                      <span className="text-gray-700">{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* High Risk Logs */}
            {analysisResult.high_risk_logs.length > 0 && (
              <div className="bg-white rounded-lg shadow-sm p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  🚨 High Risk Logs ({analysisResult.high_risk_logs.length})
                </h3>
                <div className="space-y-3">
                  {analysisResult.high_risk_logs.map((log, index) => (
                    <LogCard key={index} log={log} index={index} />
                  ))}
                </div>
              </div>
            )}

            {/* Medium Risk Logs */}
            {analysisResult.medium_risk_logs.length > 0 && (
              <div className="bg-white rounded-lg shadow-sm p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  ⚠️ Medium Risk Logs ({analysisResult.medium_risk_logs.length})
                </h3>
                <div className="space-y-3">
                  {analysisResult.medium_risk_logs.map((log, index) => (
                    <LogCard key={index} log={log} index={index} />
                  ))}
                </div>
              </div>
            )}

            {/* Low Risk Logs */}
            {analysisResult.low_risk_logs.length > 0 && (
              <div className="bg-white rounded-lg shadow-sm p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  ✅ Low Risk Logs ({analysisResult.low_risk_logs.length})
                </h3>
                <div className="space-y-3">
                  {analysisResult.low_risk_logs.slice(0, 5).map((log, index) => (
                    <LogCard key={index} log={log} index={index} />
                  ))}
                  {analysisResult.low_risk_logs.length > 5 && (
                    <div className="text-center text-gray-500 py-4">
                      ... and {analysisResult.low_risk_logs.length - 5} more low risk logs
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
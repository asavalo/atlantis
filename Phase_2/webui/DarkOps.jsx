import React, { useState } from 'react';

// Function to convert files to base64 format
const convertToBase64 = (file) => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onloadend = () => resolve(reader.result.split(',')[1]); // Extracting base64 string from URL
    reader.onerror = reject;
  });
};

export default function App() {
  const baseUrl = import.meta?.env?.VITE_CAPI_URL || 'http://localhost:8001';
  const [statusMessage, setStatusMessage] = useState('');
  const [file, setFile] = useState(null);
  const [githubUrl, setGithubUrl] = useState('');
  const [responseMessage, setResponseMessage] = useState('');
  const [isUploading, setIsUploading] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  // Health check function
const checkAPI = async () => {
  try {
    const response = await fetch(`${baseUrl}/health/`);
    const data = await response.json();
    console.log("API Health Response: ", data);  // Log the response for debugging

    if (response.ok) {
      setStatusMessage('API is healthy: ' + data.status);
    } else {
      setStatusMessage('API Error: ' + data.detail || 'Unknown error');
    }
  } catch (error) {
    console.error('Error connecting to the API:', error);  // Log the error for debugging
    setStatusMessage('Error connecting to the API: ' + error.message);
  }
};

  // Upload file handler
  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    setFile(selectedFile);
  };

  // Handle authentication
  const handleAuthChange = (e) => {
    if (e.target.name === 'username') {
      setUsername(e.target.value);
    } else if (e.target.name === 'password') {
      setPassword(e.target.value);
    }
  };

  // Handle submission
  const handleSubmit = async () => {
    if (!file && !githubUrl) {
      setResponseMessage('Please provide a file or a GitHub URL');
      return;
    }

    setIsUploading(true);
    const formData = new FormData();

    // Convert file to base64 and append to formData
    if (file) {
      const base64File = await convertToBase64(file);
      formData.append('data', base64File);
    }
    if (githubUrl) formData.append('github_url', githubUrl);

    // Add basic auth headers
    const authHeader = 'Basic ' + btoa(username + ':' + password);

    try {
      const response = await fetch(`${baseUrl}/submission/gp/`, {
        method: 'POST',
        headers: {
          'Authorization': authHeader,
        },
        body: formData,
      });

      const data = await response.json();
      if (response.ok) {
        setResponseMessage(`Submission successful: ${data.gp_uuid}`);
      } else {
        setResponseMessage(`Error: ${data.detail || 'Unknown error'}`);
      }
    } catch (error) {
      setResponseMessage(`Error: ${error.message}`);
    }
    setIsUploading(false);
  };

  return (
    <div
      style={{
        background: '#0a0f14',
        color: '#d1d5db',
        minHeight: '100vh',
        fontFamily: 'monospace',
        padding: '2rem',
      }}
    >
      <h1
        style={{
          letterSpacing: '0.15em',
          textTransform: 'uppercase',
          color: '#7dd3fc',
        }}
      >
        Atlantis-AIxCC Competition Portal
      </h1>
      <p style={{ marginTop: '0.25rem', color: '#94a3b8' }}>
        A seamless interface for submitting code vulnerability scanning tasks
      </p>
      
      <p
        style={{
          fontSize: '12px',
          color: '#9aa4b2',
          border: '1px solid #1b2836',
          padding: '10px',
          borderRadius: '8px',
        }}
      >
        <strong style={{ color: '#d1d5db' }}>Unofficial Notice:</strong> This is a
        user-developed interface and is not affiliated with or endorsed by
        Atlantis, Team Atlanta, or AIXCC.
      </p>

      {/* API Health Check */}
      <button
        onClick={checkAPI}
        style={{
          padding: '0.75rem',
          backgroundColor: '#7dd3fc',
          color: '#0a0f14',
          borderRadius: '8px',
          border: 'none',
          cursor: 'pointer',
          marginTop: '2rem',
        }}
      >
        Check API Health
      </button>

      {statusMessage && (
        <div
          style={{
            marginTop: '1rem',
            fontSize: '14px',
            color: '#94a3b8',
            border: '1px solid #1b2836',
            padding: '10px',
            borderRadius: '8px',
          }}
        >
          <strong style={{ color: '#d1d5db' }}>API Status:</strong>
          <p>{statusMessage}</p>
        </div>
      )}

      {/* File Upload or GitHub URL */}
      <div style={{ marginTop: '2rem' }}>
        <h3 style={{ color: '#7dd3fc' }}>Submit a Code Vulnerability Scan</h3>

        {/* Basic Authentication Fields */}
        <div style={{ marginTop: '1rem' }}>
          <input
            type="text"
            placeholder="Username"
            name="username"
            value={username}
            onChange={handleAuthChange}
            style={{
              padding: '0.75rem',
              backgroundColor: '#1e293b',
              color: '#d1d5db',
              borderRadius: '8px',
              border: 'none',
              width: '100%',
            }}
          />
        </div>
        <div style={{ marginTop: '1rem' }}>
          <input
            type="password"
            placeholder="Password"
            name="password"
            value={password}
            onChange={handleAuthChange}
            style={{
              padding: '0.75rem',
              backgroundColor: '#1e293b',
              color: '#d1d5db',
              borderRadius: '8px',
              border: 'none',
              width: '100%',
            }}
          />
        </div>

        {/* File Upload */}
        <div style={{ marginTop: '1rem' }}>
          <input
            type="file"
            onChange={handleFileChange}
            style={{
              padding: '0.75rem',
              backgroundColor: '#7dd3fc',
              color: '#0a0f14',
              borderRadius: '8px',
              border: 'none',
            }}
          />
        </div>

        {/* GitHub URL */}
        <div style={{ marginTop: '1rem' }}>
          <input
            type="text"
            placeholder="GitHub Repository URL"
            value={githubUrl}
            onChange={(e) => setGithubUrl(e.target.value)}
            style={{
              padding: '0.75rem',
              backgroundColor: '#1e293b',
              color: '#d1d5db',
              borderRadius: '8px',
              border: 'none',
              width: '100%',
            }}
          />
        </div>

        {/* Submit Button */}
        <button
          onClick={handleSubmit}
          disabled={isUploading}
          style={{
            padding: '0.75rem',
            backgroundColor: '#7dd3fc',
            color: '#0a0f14',
            borderRadius: '8px',
            border: 'none',
            cursor: isUploading ? 'not-allowed' : 'pointer',
            marginTop: '2rem',
          }}
        >
          {isUploading ? 'Uploading...' : 'Submit'}
        </button>

        {/* Response Message */}
        {responseMessage && (
          <div
            style={{
              marginTop: '1rem',
              fontSize: '14px',
              color: '#94a3b8',
              border: '1px solid #1b2836',
              padding: '10px',
              borderRadius: '8px',
            }}
          >
            <strong style={{ color: '#d1d5db' }}>Response:</strong>
            <p>{responseMessage}</p>
          </div>
        )}
      </div>
    </div>
  );
}

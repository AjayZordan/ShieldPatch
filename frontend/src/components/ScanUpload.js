// src/components/ScanUpload.jsx
import React, { useState } from "react";

const API_BASE = process.env.REACT_APP_API_URL || "http://127.0.0.1:5000";

export default function ScanUpload({ onScanComplete }) {
  const [file, setFile] = useState(null);
  const [source, setSource] = useState("web-ui");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleFile = (e) => {
    setFile(e.target.files && e.target.files[0]);
    setResult(null);
    setError(null);
  };

  const upload = async (e) => {
    e && e.preventDefault();
    setError(null);
    setResult(null);

    if (!file) {
      setError("Choose a file first.");
      return;
    }

    const fd = new FormData();
    fd.append("file", file);
    fd.append("source", source);

    try {
      setLoading(true);

      // Attach Authorization token if present
      const token = localStorage.getItem("token");
      const headers = token ? { Authorization: `Bearer ${token}` } : {};

      const res = await fetch(`${API_BASE}/api/scan/file`, {
        method: "POST",
        body: fd,
        headers,
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Scan failed");
      } else {
        setResult(data);
        if (typeof onScanComplete === "function") onScanComplete(data);
      }
    } catch (err) {
      setError(err.message || "Network error");
    } finally {
      setLoading(false);
    }
  };

  const clear = () => {
    setFile(null);
    setResult(null);
    setError(null);
  };

  return (
    <div className="scan-upload-card" style={cardStyle}>
      <h3 style={{ marginTop: 0 }}>Quick file scan</h3>

      <div style={{ marginBottom: 8 }}>
        <input type="file" onChange={handleFile} />
      </div>

      <div style={{ marginBottom: 8 }}>
        <label style={{ marginRight: 8 }}>Source:</label>
        <select value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="web-ui">web-ui</option>
          <option value="dashboard">dashboard</option>
          <option value="manual">manual</option>
        </select>
      </div>

      <div style={{ display: "flex", gap: 8 }}>
        <button onClick={upload} disabled={loading} style={btnStyle}>
          {loading ? "Scanning…" : "Scan file"}
        </button>
        <button onClick={clear} disabled={loading} style={btnSecondaryStyle}>
          Clear
        </button>
      </div>

      {error && (
        <div style={errStyle}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 12 }}>
          <div style={okStyle}>
            <strong>Status:</strong> {result.summary?.status ?? "unknown"}
          </div>

          <pre
            style={{
              maxHeight: 260,
              overflow: "auto",
              background: "#0f1724",
              color: "#e6eef8",
              padding: 10,
              borderRadius: 6,
              marginTop: 8,
              fontSize: 12,
            }}
          >
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

/* --- minimal inline styles so you can paste without CSS files --- */
const cardStyle = {
  padding: 14,
  borderRadius: 8,
  background: "#ffffff",
  boxShadow: "0 1px 3px rgba(0,0,0,0.08)",
  maxWidth: 720,
};

const btnStyle = {
  padding: "8px 14px",
  borderRadius: 6,
  border: "1px solid #0b69ff",
  background: "#0b69ff",
  color: "white",
  cursor: "pointer",
};

const btnSecondaryStyle = {
  padding: "8px 14px",
  borderRadius: 6,
  border: "1px solid #ddd",
  background: "#f5f7fa",
  cursor: "pointer",
};

const errStyle = {
  marginTop: 10,
  color: "#8b1e1e",
  background: "#fee",
  padding: 8,
  borderRadius: 6,
};

const okStyle = {
  marginTop: 10,
  color: "#0a5f00",
  background: "#eefbe9",
  padding: 8,
  borderRadius: 6,
};

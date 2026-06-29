// frontend/src/components/UploadScan.jsx
import React, { useState } from "react";

export default function UploadScan() {
  const [file, setFile] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleFile = (e) => {
    setFile(e.target.files[0]);
    setReport(null);
  };

  const upload = async () => {
    if (!file) return alert("Choose a file first");
    setLoading(true);
    const fd = new FormData();
    fd.append("file", file);
    fd.append("source", "web-ui");

    try {
      const res = await fetch("/api/scan/file", {
        method: "POST",
        body: fd,
      });
      const j = await res.json();
      setReport(j);
    } catch (err) {
      setReport({ error: String(err) });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h3>Upload file for scan</h3>
      <input type="file" onChange={handleFile} />
      <button onClick={upload} disabled={loading}>{loading ? "Scanning..." : "Scan file"}</button>

      {report && (
        <div style={{ whiteSpace: "pre-wrap", marginTop: 12 }}>
          <h4>Scan Result</h4>
          <pre>{JSON.stringify(report, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
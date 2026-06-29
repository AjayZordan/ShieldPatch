// src/pages/PredictRisk.js
// temporary dev hardcode — put this near the top of the file


import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Dashboard.css"; // reuse dashboard styles for consistent look
import RiskBarChart from "../components/RiskBarChart";
import SeverityPie from "../components/SeverityPie";
import PatchRecommendation from "../components/PatchRecommendation";



export default function PredictRisk() {
  const navigate = useNavigate();

  const [query, setQuery] = useState(""); // CVE id or description
  const [cvss, setCvss] = useState(""); // optional numeric field (will be auto-filled if backend infers)
  const [cvssInferred, setCvssInferred] = useState(false); // show badge if backend inferred CVSS
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null); // { predicted_score, id, logged, raw }
  const [error, setError] = useState(null);
  const [patchModalOpen, setPatchModalOpen] = useState(false);
  const [patchQuery, setPatchQuery] = useState("");
  const hostOs = "Ubuntu 22.04"; // or get from scanner / system info if available

  // Normalize API_BASE: remove trailing slashes and a trailing '/api' if present
  let _apiBase = process.env.REACT_APP_API_BASE || "http://127.0.0.1:5000";
  _apiBase = String(_apiBase).replace(/\/+$/, ""); // remove trailing slashes
  if (_apiBase.toLowerCase().endsWith("/api")) {
    _apiBase = _apiBase.slice(0, -4); // remove trailing '/api'
  }
  const API_BASE = _apiBase;
  

  const resetResult = () => {
    setResult(null);
    setError(null);
    setCvssInferred(false);
  };

  const severityFromScore = (score) => {
  if (score === null || score === undefined) return "Unknown";
  const s = Number(score);
  if (isNaN(s)) return "Unknown";
  if (s >= 9) return "Critical";
  if (s >= 7) return "High";
  if (s >= 4) return "Medium";
  return "Low";
};

  const colorFromScore = (score) => {
    const sev = severityFromScore(score);
    if (sev === "Critical") return "#cc0000";
    if (sev === "High") return "#ff4d4d";
    if (sev === "Medium") return "#ffd700";
    if (sev === "Low") return "#4caf50";
    return "#999";
  };

  // small helper to safely read response text (for debugging if JSON parse fails)
  async function safeReadResponseBody(res) {
    try {
      const txt = await res.text();
      return txt;
    } catch (e) {
      return `(unable to read response body: ${String(e)})`;
    }
  }

  const submitPredict = async (ev) => {
    ev && ev.preventDefault();
    resetResult();

    if (!query || query.trim().length === 0) {
      setError("Enter a CVE ID or paste a vulnerability description to predict.");
      return;
    }

    setLoading(true);
    setError(null);
    setCvssInferred(false);

    try {
      const token = localStorage.getItem("token");
      const trimmed = query.trim();
      const isCVE = trimmed.toUpperCase().startsWith("CVE-");
      // Prepare single-object payload (backend accepts dict or array)
      const payload = {};
      if (isCVE) {
        payload.cve_id = trimmed;
        // include description_text too if user pasted extra
        payload.description_text = trimmed;
      } else {
        payload.description_text = trimmed;
      }
      if (cvss !== "" && !isNaN(Number(cvss))) {
        payload.cvss_score = Number(cvss);
      }

      // --- DEBUG: log what we are sending ---
      console.log("PredictRisk: sending payload to backend:", API_BASE + "/api/vulnlookup/predict/batch", payload);

      const res = await fetch(`${API_BASE}/api/vulnlookup/predict/batch`, {
        method: "POST",
        mode: "cors",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(payload),
      });

      console.log("PredictRisk: fetch completed. status:", res.status, "ok:", res.ok);
      const hdrs = {};
      for (const [k, v] of res.headers.entries()) hdrs[k] = v;
      console.log("PredictRisk: response headers:", hdrs);

      let data = null;
      try {
        data = await res.json();
      } catch (jsonErr) {
        const raw = await safeReadResponseBody(res);
        console.error("PredictRisk: failed to parse JSON. raw body:", raw, jsonErr);
        throw new Error("Failed to parse JSON from backend: " + (jsonErr.message || jsonErr) + " - raw: " + raw);
      }

      console.log("PredictRisk: parsed JSON response:", data);

      if (!res.ok) {
        const detail = (data && (data.error || data.detail || data.message)) || "Server error";
        setError(`Prediction failed: ${detail}`);
        setLoading(false);
        return;
      }

      const first = data && data.predictions && data.predictions[0];
      if (!first) {
        setError("Prediction failed: malformed response from server.");
        setLoading(false);
        return;
      }

      const inferredCvss = first.input && (first.input.cvss_score ?? first.input.cvss);
      if ((cvss === "" || cvss === null) && inferredCvss !== undefined && inferredCvss !== null) {
        setCvss(String(inferredCvss));
        setCvssInferred(true);
      } else {
        setCvssInferred(false);
      }

      // Build the new result object
      const newResult = {
        predicted_score: first.predicted ?? first.predicted_score ?? 0,
        logged: first.logged ?? false,
        id: first.log_id ?? first.id ?? null,
        raw: data,
      };

      // Save to state
      setResult(newResult);

      // --- NEW: automatically open patch modal if backend inferred a CVE or user input was CVE ---
      // prefer backend-provided CVE in prediction input; fallback to user input if it looks like a CVE
      const backendCve = first.input && (first.input.cve_id || first.input.CVE || first.input.cve);
      const userCve = isCVE ? trimmed : null;
      const openCve = backendCve || userCve || null;
      if (openCve) {
        setPatchQuery(String(openCve));
        setPatchModalOpen(true);
      }
      // --- end auto-open patch modal ---

    } catch (err) {
      console.error("PredictRisk: network/client error while calling backend:", err);
      setError(`Network or client error: ${err.message || String(err)}`);
    } finally {
      setLoading(false);
    }
  };

  // small visual bar component
  const ScoreBar = ({ score }) => {
    const pct = Math.max(0, Math.min(100, (Number(score) || 0) * 10));
    const color = colorFromScore(pct);
    return (
      <div style={{ width: "100%", background: "#222", borderRadius: 8, padding: 6 }}>
        <div
          style={{
            height: 22,
            width: `${pct}%`,
            background: color,
            borderRadius: 6,
            boxShadow: "0 4px 12px rgba(0,0,0,0.5)",
            transition: "width 500ms ease",
            display: "flex",
            alignItems: "center",
            justifyContent: pct > 10 ? "flex-end" : "flex-start",
            paddingRight: 8,
            color: "#111",
            fontWeight: 700,
          }}
        >
          <span style={{ fontSize: 12 }}>{pct}%</span>
        </div>
      </div>
    );
  };

  // compute display CVSS for chart: prefer user input, fallback to backend inferred cvss_score in the first prediction input
  const getDisplayCvss = () => {
    if (cvss !== "" && !isNaN(Number(cvss))) return Number(cvss);
    const inferred = result?.raw?.predictions?.[0]?.input?.cvss_score;
    if (inferred !== undefined && inferred !== null && !isNaN(Number(inferred))) return Number(inferred);
    return result?.predicted_score ?? null;
  };

  const displayCvss = getDisplayCvss();

  // detect CVE for patch button: prefer backend-inferred CVE, else user input if it looks like CVE
  const detectedCve =
    (result && result.raw && result.raw.predictions && result.raw.predictions[0] && (result.raw.predictions[0].input?.cve_id || result.raw.predictions[0].input?.CVE)) ||
    ((query && query.trim().toUpperCase().startsWith("CVE-")) ? query.trim() : null);

  return (
    <div style={{ padding: 20, maxWidth: 920, margin: "20px auto" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h1 style={{ margin: 0 }}>🔮 ML Risk Prediction</h1>
        <div style={{ display: "flex", gap: 8 }}>
          <button
            className="patch-btn"
            onClick={() => navigate("/dashboard")}
            style={{ background: "#00aaff", color: "#fff" }}
          >
            ← Back
          </button>
        </div>
      </div>

      <p style={{ color: "#ccc", marginTop: 8 }}>
        Paste a CVE ID (like <em>CVE-2023-12345</em>) or a vulnerability description. CVSS score is optional — the backend will enrich
        missing fields automatically.
      </p>

      <form onSubmit={submitPredict} style={{ marginTop: 12, display: "grid", gap: 12 }}>
        <input
          aria-label="CVE or description"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="CVE ID or vulnerability description..."
          style={{
            padding: "12px 14px",
            borderRadius: 8,
            border: "1px solid #333",
            background: "#111",
            color: "#fff",
            fontSize: 15,
            outline: "none",
          }}
        />

        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <input
            value={cvss}
            onChange={(e) => {
              setCvss(e.target.value);
              setCvssInferred(false); // user changed - clear inferred badge
            }}
            placeholder="Optional: CVSS score (e.g. 9.8)"
            style={{
              padding: "10px 12px",
              borderRadius: 8,
              border: "1px solid #333",
              background: "#111",
              color: "#fff",
              width: 200,
            }}
          />

          <button
            type="submit"
            className="scan-btn"
            disabled={loading}
            style={{
              padding: "10px 18px",
              borderRadius: 8,
              fontWeight: 700,
              cursor: "pointer",
            }}
          >
            {loading ? "Predicting..." : "Predict Risk"}
          </button>

          <button
            type="button"
            onClick={() => {
              setQuery("");
              setCvss("");
              resetResult();
            }}
            className="patch-btn"
            style={{ background: "#ee6666", color: "#fff", borderRadius: 8 }}
          >
            Clear
          </button>
        </div>
      </form>

      {error && (
        <div style={{ marginTop: 12, padding: 12, borderRadius: 8, background: "#330000", color: "#ffb3b3" }}>
          {error}
        </div>
      )}

      {result && (
        <div style={{ marginTop: 18, display: "grid", gap: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
            <div>
              <h3 style={{ margin: "4px 0" }}>Prediction result</h3>
              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <div style={{ fontSize: 36, fontWeight: 800 }}>{Number(result.predicted_score).toFixed(1)}</div>
                <div style={{ display: "flex", flexDirection: "column" }}>
                  <div style={{ fontSize: 14, color: "#aaa" }}>Score</div>
                  <div style={{ marginTop: 4, display: "flex", alignItems: "center", gap: 8 }}>
                    <span
                      style={{
                        padding: "6px 10px",
                        borderRadius: 6,
                        background: colorFromScore(result.predicted_score),
                        color: "#111",
                        fontWeight: 700,
                      }}
                    >
                      {severityFromScore(result.predicted_score)}
                    </span>
                    {cvssInferred && (
                      <span
                        title="CVSS was inferred by backend"
                        style={{
                          padding: "6px 8px",
                          borderRadius: 6,
                          background: "#333",
                          color: "#9fdfff",
                          fontSize: 12,
                          border: "1px solid #234",
                        }}
                      >
                        CVSS inferred
                      </span>
                    )}
                  </div>
                </div>
              </div>
            </div>

            <div style={{ minWidth: 220 }}>
              <div style={{ fontSize: 12, color: "#bbb", marginBottom: 6 }}>Model logging</div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <div style={{ fontWeight: 700 }}>{result.logged ? "Saved" : "Not saved"}</div>
                {result.id ? <div style={{ color: "#888" }}>ID: {result.id}</div> : null}
              </div>
            </div>
          </div>

          <div>
            <ScoreBar score={result.predicted_score} />
            <div style={{ marginTop: 20, padding: 16, background: "#0e1220", borderRadius: 10 }}>
              <h4 style={{ margin: "0 0 10px 0", color: "#ccc" }}>Prediction Comparison</h4>
              <RiskBarChart cvss={displayCvss} predicted={result.predicted_score} />
            </div>
          </div>

          {/* Patch recommendation button (opens modal) */}
          {detectedCve && (
            <div style={{ marginTop: 12 }}>
              <button
                onClick={() => {
                  setPatchQuery(typeof detectedCve === "string" ? detectedCve : String(detectedCve));
                  setPatchModalOpen(true);
                }}
                style={{
                  padding: "8px 12px",
                  background: "#39bdf3",
                  color: "#041b27",
                  border: "none",
                  borderRadius: 6,
                  cursor: "pointer",
                  fontWeight: "bold",
                }}
              >
                Show Patch Recommendations
              </button>
            </div>
          )}

          <div>
            <SeverityPie apiBase={API_BASE} />
          </div>

          {/* simple insights (derive a few heuristics client-side) */}
          <div style={{ padding: 12, borderRadius: 8, background: "#0e1220", color: "#ddd" }}>
            <h4 style={{ marginTop: 0 }}>Insights</h4>
            <ul style={{ margin: "8px 0 0 16px" }}>
              <li>
                CVSS is optional — <strong>if you can provide it, the model will usually be more accurate</strong>.
              </li>
              <li>
                If prediction was saved (logged), you can later show it in dashboard history / analytics.
              </li>
              <li>Tip: Prefer pasting the CVE ID when possible — backend can enrich using CVE metadata later.</li>
            </ul>
          </div>

          {/* raw debug block for developer (collapsible) */}
          <details style={{ marginTop: 8, background: "#081018", padding: 10, borderRadius: 6 }}>
            <summary style={{ color: "#9fdfff", cursor: "pointer" }}>Raw response (debug)</summary>
            <pre style={{ whiteSpace: "pre-wrap", color: "#ddd", marginTop: 8 }}>{JSON.stringify(result.raw, null, 2)}</pre>
          </details>
        </div>
      )}

      {/* Patch Recommendation modal */}
      <PatchRecommendation
        open={patchModalOpen}
        initialQuery={patchQuery}
        hostOs={hostOs}
        onClose={() => setPatchModalOpen(false)}
      />
    </div>
  );
}
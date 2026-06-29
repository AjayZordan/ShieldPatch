// src/components/ThreatsWidget.js
import React, { useEffect, useState } from "react";
import "./ThreatsWidget.css";

/**
 * Props:
 *  - initialLimit (number) default 10
 *  - compact (bool) default false
 *
 * This component renders a compact two-column view:
 *  - left: scrollable list of indicators (links + short desc)
 *  - right: preview / small vulnerability table
 *
 * It is designed to be embedded inside the scanner-style panel
 * so it doesn't add any outer rounded box of its own.
 */
export default function ThreatsWidget({ initialLimit = 10, compact = false }) {
  const [limit, setLimit] = useState(initialLimit || 10);
  const [indicators, setIndicators] = useState([]);
  const [count, setCount] = useState(0);
  const [loading, setLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [error, setError] = useState(null);

  const fetchThreats = async (lim = limit) => {
    setLoading(true);
    setError(null);
    try {
      // backend supports query param ?limit=
      const res = await fetch(`http://127.0.0.1:5000/api/threats/?limit=${lim}`);
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`HTTP ${res.status}: ${text}`);
      }
      const data = await res.json();
      setIndicators(data.indicators || []);
      setCount(data.count || (data.indicators || []).length);
      setLastUpdated(new Date());
    } catch (err) {
      console.error("Failed to fetch threats:", err);
      setError(err.message || "Failed to fetch threats");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchThreats(limit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // fetch once on mount

  const onRefresh = () => fetchThreats(limit);

  return (
    <div className="threats-root" style={{ width: "100%" }}>
      <div className="threats-header" style={{ marginBottom: 10 }}>
        <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <strong style={{ fontSize: 18, color: "#eaf6ff" }}>Threat Intelligence</strong>
          <span style={{ fontSize: 13, color: "#9fbfcc" }}>{count} items</span>
          {lastUpdated && (
            <span style={{ fontSize: 12, color: "#7b99a8" }}>
              • updated {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </div>
        <div className="compact-controls">
          <label style={{ color: "#cfeeff", marginRight: 6 }}>Show</label>
          <select
            value={limit}
            onChange={(e) => {
              const v = parseInt(e.target.value, 10) || 10;
              setLimit(v);
            }}
            onBlur={() => fetchThreats(limit)}
            style={{ padding: "6px 8px", borderRadius: 6, background: "#07121a", color: "#dff8ff", border: "1px solid rgba(255,255,255,0.04)" }}
          >
            <option value={5}>5</option>
            <option value={10}>10</option>
            <option value={20}>20</option>
            <option value={50}>50</option>
          </select>
          <button
            onClick={onRefresh}
            style={{
              marginLeft: 8,
              background: "#1b6b8f",
              color: "#ffffff",
              border: "none",
              padding: "8px 10px",
              borderRadius: 8,
              cursor: "pointer",
              fontWeight: 700,
            }}
            title="Refresh threat feeds"
          >
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </div>

      <div className="threat-list-compact" style={{ gap: 18 }}>
        {/* Left column: indicators */}
        <div className="indicator-list" role="list" aria-label="Threat indicators">
          {error && (
            <div style={{ padding: 10, color: "#ffd1d1", fontWeight: 700 }}>
              Error: {error}
            </div>
          )}

          {!error && indicators.length === 0 && !loading && (
            <div style={{ padding: 12, color: "#9fbfcc" }}>
              No indicators available.
            </div>
          )}

          {!error && indicators.map((it) => (
            <div className="threat-item-compact" key={it.id || it.ioc || Math.random()}>
              <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 800, color: "#a7e6ff", marginBottom: 6 }}>
                    {it.source || "Unknown"}
                  </div>
                  <div>
                    {it.ioc ? (
                      <a href={it.ioc} target="_blank" rel="noopener noreferrer">{it.ioc}</a>
                    ) : (
                      <span style={{ color: "#bcdff0" }}>{it.value || "(no ioc)"}</span>
                    )}
                  </div>
                </div>
                <div style={{ minWidth: 110, textAlign: "right", color: "#7b99a8", fontSize: 12 }}>
                  <div style={{ fontSize: 12 }}>{it.type || "unknown"}</div>
                  <div style={{ fontSize: 11 }}>{it.first_seen ? (it.first_seen.replace?.("Z","") || it.first_seen) : ""}</div>
                </div>
              </div>
              {it.description && (
                <div style={{ marginTop: 6, color: "#cfeeff", fontSize: 13 }}>
                  {it.description.length > 180 ? it.description.slice(0, 180) + "…" : it.description}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Right column: preview / summary */}
        <div className="threat-preview-compact" aria-hidden={false}>
          <h4 style={{ color: "#dff8ff", marginTop: 0 }}>Current Vulnerability Scan Results</h4>
          <table>
            <thead>
              <tr>
                <th style={{ width: 50 }}>ID</th>
                <th>Software</th>
                <th style={{ width: 140 }}>CVE</th>
                <th style={{ width: 80 }}>Severity</th>
                <th style={{ width: 60 }}>Risk</th>
              </tr>
            </thead>
            <tbody>
              {/* static sample rows (keeps layout consistent if backend CVE mapping isn't linked) */}
              <tr>
                <td>101</td>
                <td>OpenSSL</td>
                <td>CVE-2024-12345</td>
                <td>High</td>
                <td>97</td>
              </tr>
              <tr>
                <td>102</td>
                <td>ExampleApp v1.2.3</td>
                <td>CVE-2023-54321</td>
                <td>Critical</td>
                <td>74</td>
              </tr>
              <tr>
                <td>103</td>
                <td>LocalDaemon</td>
                <td>-</td>
                <td>Medium</td>
                <td>54</td>
              </tr>
            </tbody>
          </table>

          {/* optional small footer */}
          <div style={{ marginTop: 10, color: "#7b99a8", fontSize: 13 }}>
            Tip: click a link on the left to open full article in a new tab.
          </div>
        </div>
      </div>
    </div>
  );
}
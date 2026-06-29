// src/pages/threatcve.js
import React, { useEffect, useState, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";

/**
 * ThreatCve - dual-mode component:
 *  - Detail mode: if URL param `:cve` is present -> fetch single CVE and show details
 *  - Library mode: if no param -> fetch list (/vulnlookup?limit=...) and show a table of CVEs
 *
 * Keeps your original detail parsing logic intact and adds a safe list view.
 */
export default function ThreatCve() {
  const { cve } = useParams(); // may be undefined for /cve-list
  const navigate = useNavigate();

  const isDetail = !!cve;

  // Detail states
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [item, setItem] = useState(null);
  const [showRaw, setShowRaw] = useState(false);

  // List states (library)
  const [listLoading, setListLoading] = useState(false);
  const [listError, setListError] = useState(null);
  const [cveList, setCveList] = useState([]);
  const [limit, setLimit] = useState(50); // you can change or expose as control later
  const [offset, setOffset] = useState(0);
  const [totalCount, setTotalCount] = useState(null);

  // New UI controls for list
  const [q, setQ] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL"); // ALL | CRITICAL | HIGH | MEDIUM | LOW
  const [sortOrder, setSortOrder] = useState("none"); // none | cvss_desc | cvss_asc
  const searchDebounceRef = useRef(null);

  useEffect(() => {
    if (isDetail) {
      let mounted = true;
      const fetchCve = async () => {
        setLoading(true);
        setError(null);
        setItem(null);
        try {
          const API_BASE = process.env.REACT_APP_API_BASE || "http://127.0.0.1:5000/api";
          const param = decodeURIComponent(cve || "");
          const res = await fetch(`${API_BASE}/vulnlookup?cve=${encodeURIComponent(param)}`);

          if (!mounted) return;

          if (!res.ok) {
            const text = await res.text();
            throw new Error(`Server returned ${res.status}: ${text}`);
          }

          const data = await res.json();

          // << DEBUG HELP: log the raw response so you can inspect it in browser console >>
          // Remove or comment out in production if verbose logging is undesired.
          console.debug("vulnlookup response for", param, data);

          // backend may return { result: {...} } or { results: [...] } or plain object
          let result = data?.result ?? null;

          // If we got an array of results, try to find the exact requested CVE
          if (!result && Array.isArray(data?.results) && data.results.length > 0) {
            // Try to find exact match by common fields (cve_id, CVE, id)
            const normalizedParam = (param || "").toString().toLowerCase();
            const found = data.results.find((r) => {
              const a = (r.cve_id || r.CVE || r.id || "").toString().toLowerCase();
              return a === normalizedParam;
            });
            result = found ?? data.results[0]; // prefer exact match, fallback to first
          }

          // If still not found, maybe backend responded with the item directly
          if (!result && data && typeof data === "object" && (data.cve_id || data.id || data.CVE)) {
            result = data;
          }

          if (!result) {
            setItem(null);
            setError("CVE not found on server.");
          } else {
            // try parse raw_data
            let parsed = null;
            if (result.raw_data) {
              try {
                parsed = typeof result.raw_data === "string" ? JSON.parse(result.raw_data) : result.raw_data;
              } catch (e) {
                parsed = null;
              }
            }

            const description =
              result.description ||
              (parsed && (parsed.cve?.descriptions?.[0]?.value || parsed.descriptions?.[0]?.value)) ||
              (parsed && parsed.cve?.description?.description_data?.[0]?.value) ||
              null;

            const published =
              result.published ||
              (parsed && (parsed.published || parsed.cve?.published || parsed.cve?.publishedDate)) ||
              null;
            const last_modified =
              result.last_modified ||
              (parsed && (parsed.lastModified || parsed.cve?.lastModified || parsed.lastModifiedDate)) ||
              null;

            let cvss =
              result.cvss_score ??
              result.cvss_v3 ??
              (parsed &&
                (parsed.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ??
                  parsed.cve?.metrics?.cvssMetricV3?.[0]?.cvssData?.baseScore)) ??
              null;

            let severity =
              result.severity ||
              (parsed &&
                (parsed.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity ||
                  parsed.cve?.metrics?.cvssMetricV2?.[0]?.baseSeverity)) ||
              null;

            let weaknesses = [];
            if (parsed) {
              if (parsed.cve?.weaknesses) weaknesses = parsed.cve.weaknesses;
              else if (parsed.weaknesses) weaknesses = parsed.weaknesses;
              if (Array.isArray(weaknesses) && weaknesses.length && weaknesses[0].description) {
                weaknesses = weaknesses.flatMap((w) =>
                  (w.description || []).map((d) => (d.value ? d.value : JSON.stringify(d)))
                );
              } else if (Array.isArray(weaknesses)) {
                weaknesses = weaknesses.map((w) => (typeof w === "string" ? w : JSON.stringify(w)));
              }
            }

            let references = [];
            if (parsed) {
              if (parsed.cve?.references) {
                const rd = parsed.cve.references.reference_data || parsed.cve.references;
                if (Array.isArray(rd)) references = rd.map((r) => r.url || JSON.stringify(r));
              } else if (parsed.references) {
                references = Array.isArray(parsed.references)
                  ? parsed.references.map((r) => (r.url ? r.url : JSON.stringify(r)))
                  : [String(parsed.references)];
              } else if (parsed?.cve?.references?.reference_data) {
                references = parsed.cve.references.reference_data.map((r) => r.url);
              }
            }

            setItem({
              ...result,
              parsedRaw: parsed,
              friendly: {
                description,
                published,
                last_modified,
                cvss,
                severity,
                weaknesses,
                references,
              },
            });
          }
        } catch (err) {
          console.error("Failed to load CVE:", err);
          setError(String(err.message || err));
        } finally {
          if (mounted) setLoading(false);
        }
      };

      fetchCve();
      return () => {
        // proper cleanup to avoid stale responses overwriting later requests
        mounted = false;
      };
    } else {
      // library mode: load list
      let mounted = true;
      const fetchList = async (searchQ = q, sev = severityFilter, off = offset) => {
        setListLoading(true);
        setListError(null);
        try {
          const API_BASE = process.env.REACT_APP_API_BASE || "http://127.0.0.1:5000/api";

          // build query params: limit, offset, q (search), severity (only if not ALL)
          const params = new URLSearchParams();
          params.set("limit", String(limit));
          params.set("offset", String(off));
          if (searchQ && searchQ.trim().length) params.set("q", searchQ.trim());
          if (sev && sev !== "ALL") params.set("severity", sev);

          const url = `${API_BASE}/vulnlookup?${params.toString()}`;

          const res = await fetch(url);
          if (!mounted) return;
          if (!res.ok) {
            const text = await res.text();
            throw new Error(`Server returned ${res.status}: ${text}`);
          }
          const data = await res.json();

          // DEBUG: show server payload for list mode
          console.debug("vulnlookup LIST response:", data);

          let results = data.results || [];

          // client-side sorting by CVSS if requested (best-effort numeric)
          if (sortOrder === "cvss_desc" || sortOrder === "cvss_asc") {
            const dir = sortOrder === "cvss_desc" ? -1 : 1;
            results = results.slice().sort((a, b) => {
              const av = Number(a.cvss_score ?? a.cvss_v3 ?? a.cvss ?? a.friendly?.cvss ?? NaN);
              const bv = Number(b.cvss_score ?? b.cvss_v3 ?? b.cvss ?? b.friendly?.cvss ?? NaN);
              // put NaN at the end
              if (isNaN(av) && isNaN(bv)) return 0;
              if (isNaN(av)) return 1;
              if (isNaN(bv)) return -1;
              return dir * (bv - av); // descending when dir=-1
            });
          }

          setCveList(results);
          if (typeof data.count !== "undefined") setTotalCount(data.count);
        } catch (err) {
          console.error("Failed to fetch CVE list:", err);
          setListError(String(err.message || err));
          setCveList([]);
        } finally {
          if (mounted) setListLoading(false);
        }
      };

      // immediate fetch
      fetchList();

      return () => {
        mounted = false;
      };
    }
  }, [cve, isDetail, limit, offset, q, severityFilter, sortOrder]);

  const onBack = () => {
    navigate(-1);
  };

  // helper derive severity text if only cvss present
  const getSeverityText = (row) => {
    if (!row) return "-";
    if (row.severity) return row.severity;
    const s = row.cvss_score ?? row.cvss ?? row.cvss_v3 ?? row.friendly?.cvss;
    if (s === null || s === undefined) return "-";
    const n = Number(s);
    if (isNaN(n)) return "-";
    if (n >= 9.0) return "CRITICAL";
    if (n >= 7.0) return "HIGH";
    if (n >= 4.0) return "MEDIUM";
    return "LOW";
  };

  // Debounced search handler
  const onChangeSearch = (value) => {
    setQ(value);
    if (searchDebounceRef.current) clearTimeout(searchDebounceRef.current);
    // debounce 350ms
    searchDebounceRef.current = setTimeout(() => {
      setOffset(0); // reset to first page when searching
      // effect will re-run because q changed
    }, 350);
  };

  // render list row (small helper)
  const renderList = () => {
    return (
      <div style={{ padding: 20, maxWidth: 1100, margin: "0 auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={onBack} className="patch-btn" style={{ background: "#ee6666", color: "#fff", borderRadius: 8 }}>
              ← Back
            </button>
            <button
              onClick={() => {
                // refresh list
                setLimit(limit);
                setOffset(0);
              }}
              className="patch-btn"
              style={{ background: "#00aaff", color: "#fff", borderRadius: 8 }}
            >
              Refresh
            </button>
          </div>
          <div style={{ color: "#999", fontSize: 13 }}>
            {totalCount !== null ? <>Total: {totalCount}</> : null}
          </div>
        </div>

        <h1 style={{ marginTop: 18 }}>CVE Library</h1>

        {/* SEARCH + FILTER UI */}
        <div style={{ display: "flex", gap: 8, marginTop: 12, alignItems: "center", flexWrap: "wrap" }}>
          <input
            type="search"
            placeholder="Search CVE ID or words in summary (press Enter or wait)..."
            value={q}
            onChange={(e) => onChangeSearch(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") { setOffset(0); } }}
            style={{ flex: 1, padding: "8px 10px", borderRadius: 6, border: "1px solid #333", background: "#061016", color: "#fff" }}
          />

          <select
            value={severityFilter}
            onChange={(e) => { setSeverityFilter(e.target.value); setOffset(0); }}
            style={{ padding: "8px 10px", borderRadius: 6, border: "1px solid #333", background: "#071018", color: "#fff" }}
          >
            <option value="ALL">All severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>

          <select
            value={sortOrder}
            onChange={(e) => setSortOrder(e.target.value)}
            style={{ padding: "8px 10px", borderRadius: 6, border: "1px solid #333", background: "#071018", color: "#fff" }}
          >
            <option value="none">Sort: none</option>
            <option value="cvss_desc">CVSS: High → Low</option>
            <option value="cvss_asc">CVSS: Low → High</option>
          </select>
        </div>

        {listLoading ? (
          <p>Loading CVE library...</p>
        ) : listError ? (
          <div style={{ color: "#ff6666" }}>{listError}</div>
        ) : !cveList || cveList.length === 0 ? (
          <p>No CVEs found.</p>
        ) : (
          <div style={{ marginTop: 12, overflowX: "auto" }}>
            <table className="scan-table" style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th style={{ minWidth: 220 }}>CVE ID</th>
                  <th style={{ minWidth: 120 }}>SEVERITY</th>
                  <th style={{ minWidth: 200 }}>PUBLISHED</th>
                  <th>SUMMARY</th>
                  <th style={{ width: 120 }}></th>
                </tr>
              </thead>
              <tbody>
                {cveList.map((c, i) => {
                  const idToOpen = c.cve_id || c.id;
                  return (
                    <tr
                      key={c.id || c.cve_id || `cve-${i}`}
                      onClick={() => {
                        if (idToOpen) navigate(`/threatcve/${encodeURIComponent(idToOpen)}`);
                      }}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && idToOpen) navigate(`/threatcve/${encodeURIComponent(idToOpen)}`);
                      }}
                      role="button"
                      tabIndex={0}
                      style={{ cursor: "pointer" }}
                      title="Click to open details"
                    >
                      <td style={{ whiteSpace: "nowrap" }}>{c.cve_id || c.id || c.CVE || "-"}</td>
                      <td>
                        <span className="severity-tag" style={{ background: "#333", color: "#fff", padding: "6px 10px", borderRadius: 6 }}>
                          {getSeverityText(c)}
                        </span>
                      </td>
                      <td>
                        {c.published
                          ? (() => {
                              try {
                                const d = new Date(c.published);
                                return isNaN(d.getTime()) ? c.published : d.toLocaleString();
                              } catch (e) {
                                return c.published;
                              }
                            })()
                          : "-"}
                      </td>
                      <td style={{ maxWidth: 480, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                        {c.description || c.summary || "-"}
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <button
                          onClick={(ev) => {
                            ev.stopPropagation(); // prevent double navigation (row + button)
                            if (idToOpen) navigate(`/threatcve/${encodeURIComponent(idToOpen)}`);
                          }}
                          className="patch-btn"
                          style={{ background: "#00aaff", color: "#fff", borderRadius: 6 }}
                        >
                          Explore
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {/* simple pagination controls */}
            <div style={{ marginTop: 12, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ color: "#999" }}>
                Showing {offset + 1} - {Math.min(offset + limit, totalCount ?? cveList.length)} of {totalCount ?? "-"}
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  className="patch-btn"
                  style={{ background: "#333", color: "#fff", borderRadius: 6 }}
                  disabled={offset === 0}
                >
                  Prev
                </button>
                <button
                  onClick={() => setOffset(offset + limit)}
                  className="patch-btn"
                  style={{ background: "#333", color: "#fff", borderRadius: 6 }}
                  disabled={totalCount !== null && offset + limit >= totalCount}
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  // render detail view (kept your original UI almost intact)
  const renderDetail = () => {
    return (
      <div style={{ padding: 20, maxWidth: 1000, margin: "0 auto" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={onBack} className="patch-btn" style={{ background: "#ee6666", color: "#fff", borderRadius: 8 }}>
              ← Back
            </button>
            <button onClick={() => navigate("/cve-list")} className="patch-btn" style={{ background: "#00aaff", color: "#fff", borderRadius: 8 }}>
              CVE Library
            </button>
          </div>

          <div style={{ color: "#999", fontSize: 13 }}>
            {item && item.friendly && item.friendly.published ? <>Published: {new Date(item.friendly.published).toLocaleString()}</> : null}
          </div>
        </div>

        <h1 style={{ marginTop: 18 }}>
          {cve}{" "}
          {item?.friendly?.severity ? (
            <span style={{ fontSize: 14, marginLeft: 10, color: "#fff", background: "#333", padding: "6px 10px", borderRadius: 6 }}>
              {String(item.friendly.severity).toUpperCase()}
            </span>
          ) : null}
        </h1>

        {loading ? (
          <p>Loading CVE details...</p>
        ) : error ? (
          <div style={{ color: "#ff4444", marginTop: 12 }}>{error}</div>
        ) : !item ? (
          <div style={{ marginTop: 12 }}>No details found for {cve}.</div>
        ) : (
          <>
            <div style={{ marginTop: 12 }}>
              <h3 style={{ marginBottom: 6 }}>Summary</h3>
              <p style={{ color: "#ddd", background: "#0b1320", padding: 12, borderRadius: 8 }}>
                {item.friendly.description || item.description || "-"}
              </p>
            </div>

            <div style={{ display: "flex", gap: 12, marginTop: 12, flexWrap: "wrap" }}>
              <div style={{ padding: 12, borderRadius: 8, background: "#071018", minWidth: 160 }}>
                <div style={{ color: "#999", fontSize: 12 }}>CVSS</div>
                <div style={{ fontSize: 20, fontWeight: 700 }}>{item.friendly.cvss ?? "—"}</div>
              </div>

              <div style={{ padding: 12, borderRadius: 8, background: "#071018", minWidth: 160 }}>
                <div style={{ color: "#999", fontSize: 12 }}>Severity</div>
                <div style={{ fontSize: 18, fontWeight: 700 }}>{item.friendly.severity ?? "—"}</div>
              </div>

              <div style={{ padding: 12, borderRadius: 8, background: "#071018", minWidth: 160 }}>
                <div style={{ color: "#999", fontSize: 12 }}>Last Modified</div>
                <div>{item.friendly.last_modified ? new Date(item.friendly.last_modified).toLocaleString() : "—"}</div>
              </div>
            </div>

            {/* Weaknesses */}
            <div style={{ marginTop: 18 }}>
              <h3>Weaknesses (CWEs)</h3>
              {item.friendly.weaknesses && item.friendly.weaknesses.length ? (
                <ul>
                  {item.friendly.weaknesses.map((w, i) => (
                    <li key={i} style={{ color: "#ddd" }}>
                      {typeof w === "string" ? w : JSON.stringify(w)}
                    </li>
                  ))}
                </ul>
              ) : (
                <p style={{ color: "#999" }}>No CWE / weakness data available.</p>
              )}
            </div>

            {/* References */}
            <div style={{ marginTop: 18 }}>
              <h3>References</h3>
              {item.friendly.references && item.friendly.references.length ? (
                <ul>
                  {item.friendly.references.map((r, i) => (
                    <li key={i}>
                      <a href={r} target="_blank" rel="noopener noreferrer" style={{ color: "#00aaff" }}>
                        {r}
                      </a>
                    </li>
                  ))}
                </ul>
              ) : (
                <p style={{ color: "#999" }}>No references available.</p>
              )}
            </div>

            {/* Raw payload toggle */}
            <div style={{ marginTop: 18 }}>
              <button onClick={() => setShowRaw((s) => !s)} className="patch-btn" style={{ background: "#333", color: "#fff", borderRadius: 8 }}>
                {showRaw ? "Hide raw JSON" : "Show raw JSON"}
              </button>

              {showRaw && (
                <pre style={{ marginTop: 12, background: "#06070a", color: "#cfd8dc", padding: 12, borderRadius: 8, overflowX: "auto", maxHeight: 420 }}>
                  {JSON.stringify(item.parsedRaw || item.raw_data || item, null, 2)}
                </pre>
              )}
            </div>
          </>
        )}
      </div>
    );
  };

  return isDetail ? renderDetail() : renderList();
}
// src/pages/Dashboard.js
import React, { useState, useEffect, useRef } from "react";
import "./Dashboard.css";
import ThreatsWidget from "../components/ThreatsWidget";
import "../components/ThreatsWidget.css";
import { useNavigate } from "react-router-dom";
import { fetchVulnSummary } from "../api/threats"; // <-- NEW: import vuln summary fetch
import PatchRecommendation from "../components/PatchRecommendation"; // adjust path if your components folder is different
import SandboxJobs from "../components/SandboxJobs";
import { runSandboxJob } from "../api/sandbox"; // <- NEW: use shared sandbox API helper
import AlertsPanel from "../components/AlertsPanel";

export default function Dashboard() {
  const navigate = useNavigate();
  // Patch modal state
  const [patchModalOpen, setPatchModalOpen] = useState(false);
  const [patchQuery, setPatchQuery] = useState("");
  const hostOs = "Ubuntu 22.04"; // replace with dynamic host info if you have it (e.g., from scanner) 
  const [alertsVisible, setAlertsVisible] = useState(false);
  const [hasAlerts, setHasAlerts] = useState(false);

  // make stats writable so we can inject real numbers when vulnSummary arrives
  const [stats, setStats] = useState([
    {
      title: "Detected Vulnerabilities",
      value: "27",
      color: "#ff4d4d",
      description: "Total open vulnerabilities identified across systems.",
    },
    {
      title: "Patches Applied",
      value: "89%",
      color: "#00d4ff",
      description: "Percentage of systems fully patched and updated.",
    },
    {
      title: "System Health",
      value: "Good",
      color: "#4dff88",
      description: "Overall system stability and uptime status.",
    },
    {
      title: "ML Threat Prediction",
      value: "Low Risk",
      color: "#ffd700",
      description: "Based on machine learning model predictions for exploit risks.",
    },
  ]);

  // --------------------
  // AUTH LOADING + USER
  // --------------------
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");
    // standardize API base here (use inside effect so lint won't complain)
    const API_BASE = (process.env.REACT_APP_API_BASE || "http://localhost:5000").replace(/\/+$/, "");
    console.log("DEBUG API_BASE (auth):", API_BASE);

    if (!token) {
      navigate("/login");
      return;
    }

    const fetchMe = async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (!res.ok) {
          localStorage.removeItem("token");
          localStorage.removeItem("user");
          navigate("/login");
          return;
        }

        const data = await res.json();
        setUser(data);
        localStorage.setItem("user", JSON.stringify(data));
      } catch (err) {
        localStorage.removeItem("token");
        localStorage.removeItem("user");
        navigate("/login");
      } finally {
        setAuthLoading(false);
      }
    };

    fetchMe();
  }, [navigate]);

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    navigate("/login");
  };

  // --------------------
  // ORIGINAL STATES
  // --------------------
  const [scanResults, setScanResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [scannerVisible, setScannerVisible] = useState(false);
  const [threatVisible, setThreatVisible] = useState(false);
  // NEW: history panel state
  const [historyVisible, setHistoryVisible] = useState(false);

  // NEW: CVE listing panel state
  const [cveVisible, setCveVisible] = useState(false);
  const [cveLoading, setCveLoading] = useState(false);
  const [cveList, setCveList] = useState([]);

  // RESTORED: history loading state so JSX stops breaking (only change)
  const [historyLoading, setHistoryLoading] = useState(false);

  const [discovery, setDiscovery] = useState([]);
  const [agentOnline, setAgentOnline] = useState(false);
  const [lastHeartbeat, setLastHeartbeat] = useState(null);

  const [fileName, setFileName] = useState("");
  const [fileScanMsg, setFileScanMsg] = useState("");
  const [fileProgress, setFileProgress] = useState(0);

  const fileInputRef = useRef(null);
  const xhrRef = useRef(null);

  const [osInfo, setOsInfo] = useState("");
  const [time, setTime] = useState(new Date());

  // NEW: vulnerability summary from backend (fetched silently)
  const [, setVulnSummary] = useState(null);

  // ---- NEW: Sandbox job states & helpers ----
  const [sandboxVisible, setSandboxVisible] = useState(false);
  const [jobHistory, setJobHistory] = useState([]);
  const [jobLoading, setJobLoading] = useState(false);
  const [jobPage, setJobPage] = useState(1);
  const [jobPerPage, setJobPerPage] = useState(50);
  const [jobMessage, setJobMessage] = useState("");

  const API_BASE = process.env.REACT_APP_API_BASE || "http://127.0.0.1:5000/api";

  const getUserIdHeader = () => {
    // prefer authenticated user object, fallback to X-User-ID in localStorage or null
    if (user && user.id) return user.id;
    try {
      const saved = JSON.parse(localStorage.getItem("user") || "{}");
      return saved && saved.id ? saved.id : null;
    } catch {
      return null;
    }
  };

  const fetchJobHistory = async ({ page = 1, per_page = jobPerPage, user_id = null } = {}) => {
    setJobLoading(true);
    setJobMessage("");
    try {
      const params = new URLSearchParams();
      params.set("page", page);
      params.set("per_page", per_page);
      if (user_id) params.set("user_id", user_id);

      const headers = {};
      const uid = user_id || getUserIdHeader();
      if (uid) headers["X-User-ID"] = String(uid);

      const res = await fetch(`${API_BASE}/sandbox/job_history?${params.toString()}`, { headers });
      if (!res.ok) {
        setJobMessage(`Failed to fetch job history: ${res.status}`);
        setJobHistory([]);
        return;
      }
      const data = await res.json();
      setJobHistory(data.jobs || []);
      setJobPage(data.page || page);
      setJobPerPage(data.per_page || per_page);
    } catch (err) {
      console.error("fetchJobHistory error:", err);
      setJobMessage("Unable to fetch job history.");
      setJobHistory([]);
    } finally {
      setJobLoading(false);
    }
  };

  const handleRunJob = async (jobPayload = {}) => {
    // jobPayload can include host_data_dir, workdir, script, snapshot_after, keep_container, job_name, user_id
    setJobMessage("Starting sandbox job...");
    try {
      const headers = { "Content-Type": "application/json" };
      const token = localStorage.getItem("token");
      if (token) headers["Authorization"] = `Bearer ${token}`;
      // set user header for auditing if available
      const uid = getUserIdHeader();
      if (uid) headers["X-User-ID"] = String(uid);

      console.log("DEBUG: handleRunJob payload:", jobPayload);
      const res = await fetch(`${API_BASE}/sandbox/run_job`, {
        method: "POST",
        headers,
        body: JSON.stringify(jobPayload),
      });
      const text = await res.text().catch(() => null);
      let data;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        console.warn("handleRunJob: response not valid JSON:", text);
        data = null;
      }

      console.log("DEBUG: handleRunJob response status:", res.status, "parsed:", data);

      if (res.ok && data && data.success) {
        setJobMessage("Job completed (check history for snapshot/log).");
        // refresh history to pick up new record
        await fetchJobHistory({ page: jobPage, per_page: jobPerPage, user_id: uid });
      } else {
        setJobMessage(`Job failed: ${data?.error || data?.detail || res.status}`);
      }
      return data;
    } catch (err) {
      console.error("handleRunJob error:", err);
      setJobMessage("Sandbox job request failed.");
      return { success: false, error: String(err) };
    }
  };

  // -----------------------------------------
  // SANDBOX: run patch, download log, restore snapshot
  // -----------------------------------------
  const handleRunPatch = async (scriptPath, workdir = "/sandbox/data/testapp", jobName = "patch-job") => {
    setMessage("⏳ Submitting patch job to sandbox...");
    try {
      // Build payload for backend sandbox
      const userObj = localStorage.getItem("user");
      const userId = userObj ? (JSON.parse(userObj).id || JSON.parse(userObj).user_id || JSON.parse(userObj).userId) : (user && (user.id || user.user_id || user.userId)) || null;

      const payload = {
        host_data_dir: "/Users/ajaykumar/Desktop/ShieldPatch/sandbox/data", // change if you use a different host path
        container_name: `sandbox_job_${jobName}_${Date.now().toString(36).slice(-6)}`,
        workdir: workdir,
        script: scriptPath,
        snapshot_after: true,
        keep_container: false,
        timeout_secs: 120,
        user_id: userId,
        job_name: jobName
      };

      console.log("DEBUG: runPatch payload ->", payload);

      // Use shared API helper (adds centralised base URL). This helper returns parsed JSON.
      const data = await runSandboxJob(payload).catch((e) => {
        console.error("runSandboxJob helper error:", e);
        return null;
      });

      if (!data) {
        // fallback: show message and return failure object
        setMessage("❌ Sandbox job failed (no response).");
        console.warn("runSandboxJob returned null/undefined.");
        return { ok: false, data: null };
      }

      // backend uses 'success' or 'apply_ok' fields
      if (data.success || data.apply_ok) {
        setMessage(`✅ Sandbox job completed — ${data.snapshot_tag ? "snapshot created" : "no snapshot"}`);
        // refresh job history to pick up new snapshot/log row
        await fetchJobHistory({ page: jobPage, per_page: jobPerPage, user_id: userId });

        // update UI scanResults if the job applied a patch (best-effort)
        if (data.apply_ok) {
          const match = (jobName || "").match(/CVE-\d{4}-\d+/i);
const cve = match ? match[0].toLowerCase() : null;

if (cve) {
  const existing = JSON.parse(localStorage.getItem("patched_cves") || "[]");

  if (!existing.includes(cve)) {
    localStorage.setItem(
      "patched_cves",
      JSON.stringify([...existing, cve])
    );
  }
}
          setScanResults((prev) =>
            prev.map((v) => {
              if ((v.cve && (jobName.includes(v.cve) || scriptPath.includes(v.cve))) || (v.id && String(v.id) === String(jobName))) {
                return { ...v, patchAvailable: false, severity: "Patched", riskScore: 0 };
              }
              return v;
            })
          );
        }

        console.log("run_job response:", data);
        return { ok: true, data };
      } else {
        setMessage(`❌ Sandbox job failed: ${data.error || data.detail || JSON.stringify(data)}`);
        console.error("Sandbox run_job returned failure:", data);
        return { ok: false, data };
      }
    } catch (err) {
      console.error("handleRunPatch error:", err);
      setMessage(`❌ Error submitting sandbox job: ${err.message || err}`);
      return { ok: false, error: err };
    }
  };

  const handleDownloadJobLog = async (jobId, filename) => {
    setJobMessage("Downloading job log...");
    try {
      const token = localStorage.getItem("token");
      const headers = {};
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const res = await fetch(`${API_BASE}/sandbox/job_log/${jobId}/download`, { headers });
      if (!res.ok) {
        setJobMessage(`Failed to download log: ${res.status}`);
        return;
      }
      const text = await res.text();
      // create blob and download
      const blob = new Blob([text], { type: "text/plain" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename || `job-${jobId}.log`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      setJobMessage("Job log downloaded.");
    } catch (err) {
      console.error("download log error:", err);
      setJobMessage("Failed to download job log.");
    }
  };

  const handleRestoreSnapshot = async (imageTag) => {
    setJobMessage("Requesting restore from snapshot...");
    try {
      const token = localStorage.getItem("token");
      const uid = getUserIdHeader();
      const res = await fetch(`${API_BASE}/sandbox/restore_from_image`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ image_tag: imageTag, user_id: uid }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setJobMessage(`Restore request failed: ${data?.error || res.status}`);
        return { ok: false, data };
      }
      setJobMessage("Restore requested — check sandbox status.");
      // optionally refresh history
      await fetchJobHistory({ page: jobPage, per_page: jobPerPage, user_id: uid });
      return { ok: true, data };
    } catch (err) {
      console.error("restore error:", err);
      setJobMessage("Restore request failed.");
      return { ok: false, error: err };
    }
  };

  // -----------------------------------------

  // Fetch vuln summary on mount (non-intrusive: doesn't change UI)
  useEffect(() => {
    let mounted = true;
    const loadSummary = async () => {
      try {
        const data = await fetchVulnSummary();
        if (!mounted) return;
        setVulnSummary(data);
        // update the first stat card with real total if available
        if (data && typeof data.total_cves !== "undefined") {
          setStats((prev) => {
            const copy = [...prev];
            copy[0] = {
              ...copy[0],
              value: String(data.total_cves),
            };
            return copy;
          });
        }
        // For now log it so you can confirm it's coming through
        console.log("Vuln summary loaded:", data);
      } catch (err) {
        console.error("Failed to load vuln summary:", err);
      }
    };
    loadSummary();
    return () => {
      mounted = false;
    };
  }, []);

  // Fetch CVE list when user opens CVE panel (non-blocking)
    // Fetch CVE list when user opens CVE panel (non-blocking)
  const fetchCveList = async (limit = 50) => {
    setCveLoading(true);
    try {
      const API_BASE = process.env.REACT_APP_API_BASE || "http://127.0.0.1:5000/api";
      const res = await fetch(`${API_BASE}/vulnlookup?limit=${limit}`);
      if (!res.ok) {
        setCveList([]);
        return;
      }
      const data = await res.json();
      // data.results expected as array of vulnerabilities
      const rawList = data.results || [];

      // NORMALIZE each CVE item so UI fields are consistent
      const normalize = (raw) => {
        // Attempt to parse nested raw_data if present
        let parsed = null;
        if (raw.raw_data) {
          try {
            parsed = typeof raw.raw_data === "string" ? JSON.parse(raw.raw_data) : raw.raw_data;
          } catch (e) {
            parsed = null;
          }
        }

        // Several possible field names in different backends - coalesce them
        const cve_id = raw.cve_id || raw.CVE || raw.id || raw.name || null;

        const description =
          raw.description ||
          raw.summary ||
          (parsed && (parsed.description || parsed.cve?.descriptions?.[0]?.value || parsed.cve?.description?.description_data?.[0]?.value)) ||
          null;

        const published =
          raw.published ||
          raw.published_at ||
          (parsed && (parsed.published || parsed.cve?.published || parsed.cve?.publishedDate)) ||
          null;

        // cvss may appear under cvss_score, cvss, cvss_v3, or nested under parsed metrics
        const cvss =
          raw.cvss_score ??
          raw.cvss ??
          raw.cvss_v3 ??
          (parsed &&
            (parsed.cve?.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ??
              parsed.cve?.metrics?.cvssMetricV3?.[0]?.cvssData?.baseScore)) ??
          null;

        // severity may be explicit or inferred from cvss
        const severity = raw.severity || raw.sev || null;

        return {
          // include original so detail page can still use everything
          ...raw,
          cve_id,
          description,
          published,
          cvss_score: cvss,
          severity,
        };
      };

      const normalized = rawList.map(normalize);

      setCveList(normalized);
    } catch (err) {
      console.error("Failed to fetch CVE listing:", err);
      setCveList([]);
    } finally {
      setCveLoading(false);
    }
  };

  
  // Detect OS
  useEffect(() => {
    const platform = window.navigator.platform.toLowerCase();
    if (platform.includes("mac")) setOsInfo("macOS");
    else if (platform.includes("win")) setOsInfo("Windows");
    else if (platform.includes("linux")) setOsInfo("Linux");
    else setOsInfo("Unknown OS");
  }, []);

  // Clock
  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  // Poll agent status
  useEffect(() => {
    let mounted = true;

    const checkHealth = async () => {
      try {
        const res = await fetch("http://127.0.0.1:5000/api/agent/status");

        if (!mounted) return;

        if (res.status === 200) {
          const data = await res.json();
          if (data.agent) {
            setAgentOnline(data.agent.status === "online");
            if (data.agent.last_seen) {
              setLastHeartbeat(new Date(data.agent.last_seen));
            }
          }
        } else {
          setAgentOnline(false);
        }
      } catch {
        if (mounted) setAgentOnline(false);
      }
    };

    checkHealth();
    const timer = setInterval(checkHealth, 5000);

    return () => {
      mounted = false;
      clearInterval(timer);
    };
  }, []);

  const findVulnForPackage = (pkg) => {
    if (!pkg || !scanResults.length) return null;
    const name = (pkg.name || "").toLowerCase();

    for (const v of scanResults) {
      const s = (v.software || "").toLowerCase();
      if (s.includes(name) || name.includes(s)) return v;
    }
    return null;
  };

  const handleScan = async () => {
    setLoading(true);
    setMessage("🔍 Scanning your system for vulnerabilities...");

    try {
      const res = await fetch("http://127.0.0.1:5000/api/scan");

      if (!res.ok) {
        setMessage(`⚠️ Scan endpoint returned ${res.status}`);
        setLoading(false);
        return;
      }

      const data = await res.json();

      if (data) {
        setScanResults(data.results || []);
        setDiscovery(data.discovery?.packages || []);
        setMessage("✅ Scan complete! Results and discovered software updated.");
      } else {
        setMessage("⚠️ No useful data received from backend.");
      }
    } catch (err) {
      console.error(err);
      setMessage("❌ Unable to connect to backend.");
    } finally {
      setLoading(false);
    }
  };

  // eslint-disable-next-line no-unused-vars
  const handlePatch = async (id) => {
    try {
      const res = await fetch(`http://127.0.0.1:5000/api/patch/${id}`, {
        method: "POST",
      });

      const data = await res.json();
      console.log("FULL SCAN RESPONSE:", data);

      if (data.success) {
        setMessage("🩹 Vulnerability patched successfully!");

        setScanResults((prev) =>
          prev.map((v) =>
            v.id === id
              ? { ...v, severity: "Patched", patchAvailable: false, riskScore: 0 }
              : v
          )
        );
      } else {
        setMessage("⚠️ Failed to patch vulnerability.");
      }
    } catch (err) {
      console.error(err);
      setMessage("⚠️ Error patching vulnerability.");
    }
  };

  // -----------------------------
  // File upload helpers (unchanged)
  // -----------------------------
  const uploadFileToServer = (file) => {
    if (!file) return;

    setFileName(file.name);
    setFileProgress(0);
    setFileScanMsg("Uploading and scanning file...");
    setMessage("");

    const xhr = new XMLHttpRequest();
    xhrRef.current = xhr;

    xhr.open("POST", "http://127.0.0.1:5000/api/scan/file", true);

    const token = localStorage.getItem("token");
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);

    xhr.upload.onprogress = (ev) => {
      if (ev.lengthComputable) {
        const percent = Math.round((ev.loaded / ev.total) * 100);
        setFileProgress(percent);
      }
    };

    xhr.onload = () => {
      setFileProgress(100);
      xhrRef.current = null;

      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const res = JSON.parse(xhr.responseText);
          if (res.ok) {
            const summary = res.summary || {};
            const raw = res.raw || {};

            const st = (summary.status || "").toUpperCase();

            if (st === "OK" || st === "CLEAN") {
              setFileScanMsg("✅ File is clean — no threats detected.");
            } else if (st === "FOUND" || st === "INFECTED" || st === "SUSPICIOUS") {
              setFileScanMsg(`⚠️ Threat found: ${summary.match || "Unknown"}`);
            } else {
              setFileScanMsg("Scan completed — see details below.");
            }

            const newEntry = {
              id: `file-${Date.now()}`,
              software: file.name,
              cve: summary.match || null,
              description: summary.path || JSON.stringify(raw),
              severity: st === "OK" ? "Clean" : "Malicious",
              color: st === "OK" ? "#4caf50" : "#ff4d4d",
              riskScore: st === "OK" ? 0 : 90,
              patchAvailable: false,
            };

            // Add to UI and history
            setScanResults((prev) => [newEntry, ...prev]);
          } else {
            setFileScanMsg(res.error || "Scan failed (no details).");
          }
        } catch (err) {
          setFileScanMsg("⚠️ Unexpected server response (check console).");
        }
      } else {
        setFileScanMsg(`⚠️ Upload/scan failed: ${xhr.status}`);
      }
    };

    xhr.onerror = () => {
      setFileScanMsg("⚠️ Network error during upload.");
      xhrRef.current = null;
    };

    const form = new FormData();
    form.append("file", file);
    form.append("source", "web-ui");
    xhr.send(form);
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    uploadFileToServer(file);
  };

  const cancelUpload = () => {
    if (xhrRef.current) {
      xhrRef.current.abort();
      setFileScanMsg("Upload cancelled by user.");
      setFileProgress(0);
      xhrRef.current = null;
    }
  };

  // -----------------------------
  // HISTORY: show recent scan history
  // -----------------------------
  const refreshHistory = async () => {
    setHistoryLoading(true);
    try {
      // if you created the backend endpoint, uncomment the fetch call:
      // await fetchHistoryFromServer();
      // For now we simply re-read the current scanResults state (it's already up to date).
    } finally {
      setHistoryLoading(false);
    }
  };

  // small helper to derive severity text if only cvss_score is present
  const getSeverityText = (row) => {
    if (row.severity) return row.severity;
    const s = row.cvss_score;
    if (s === null || s === undefined) return "-";
    const n = Number(s);
    if (isNaN(n)) return "-";
    if (n >= 9.0) return "CRITICAL";
    if (n >= 7.0) return "HIGH";
    if (n >= 4.0) return "MEDIUM";
    return "LOW";
  };

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <h1 className="dashboard-title">🛡️ ShieldPatch Security Dashboard</h1>
        <div className="header-info">
          <p>
            OS: <strong>{osInfo}</strong> |{" "}
            {time.toLocaleDateString()} {time.toLocaleTimeString()}
          </p>
          <p
            style={{
              color: agentOnline ? "#4caf50" : "#ff5252",
              margin: "6px 0",
            }}
          >
            Agent: <strong>{agentOnline ? "ONLINE" : "OFFLINE"}</strong>
            {lastHeartbeat
              ? ` • Last heartbeat: ${lastHeartbeat.toLocaleTimeString()}`
              : ""}
          </p>

          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            {authLoading ? null : user ? (
              <div style={{ color: "#ccc", fontSize: 14 }}>
                Signed in as{" "}
                <strong style={{ color: "#00d4ff" }}>
                  {user.username || user.email}
                </strong>
              </div>
            ) : null}

            <button className="logout-btn" onClick={handleLogout}>
              Logout
            </button>
          </div>
        </div>
      </header>

      {/* ===== Buttons for widgets & scanner ===== */}
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          gap: 12,
          marginTop: 12,
        }}
      >
        <button
          onClick={() => setThreatVisible((s) => !s)}
          className="threat-toggle"
          style={{
            background: threatVisible ? "#0f3b57" : "#153041",
            color: "#fff",
            borderRadius: 8,
            padding: "10px 18px",
            boxShadow: "0 6px 18px rgba(0,0,0,0.5)",
            border: "none",
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          🔎 Threat Intelligence
        </button>

        <button
          onClick={() => setScannerVisible((s) => !s)}
          className="scanner-toggle"
          style={{
            background: scannerVisible ? "#bff1ff" : "#88efff",
            color: "#06222b",
            borderRadius: 8,
            padding: "10px 18px",
            boxShadow: "0 6px 18px rgba(0,0,0,0.5)",
            border: "none",
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          {scannerVisible
            ? "🔽 Hide Vulnerability Scanner"
            : "🧠 Show Vulnerability Scanner"}
        </button>

        {/* ===== NEW: History Button (matches style of Threat Intelligence) ===== */}
        <button
          onClick={() => {
            // If opening, you could fetch from server here
            if (!historyVisible) {
              // optional: fetchHistoryFromServer();
            }
            setHistoryVisible((s) => !s);
            // ensure scanner panel is not collapsed unintentionally
          }}
          className="history-toggle"
          style={{
            background: historyVisible ? "#0f3b57" : "#153041",
            color: "#fff",
            borderRadius: 8,
            padding: "10px 18px",
            boxShadow: "0 6px 18px rgba(0,0,0,0.5)",
            border: "none",
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          📜 History
        </button>

        {/* ===== NEW: CVE Listing Button (next to History) ===== */}
        <button
          onClick={async () => {
            // toggle and fetch when opening
            const willOpen = !cveVisible;
            setCveVisible(willOpen);
            if (willOpen && cveList.length === 0) {
              await fetchCveList(50);
            }
          }}
          className="cve-toggle"
          style={{
            background: cveVisible ? "#0f3b57" : "#153041",
            color: "#fff",
            borderRadius: 8,
            padding: "10px 18px",
            boxShadow: "0 6px 18px rgba(0,0,0,0.5)",
            border: "none",
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          🧾 CVE Listing
        </button>

        {/* ⭐ NEW: ML RISK PREDICTION BUTTON */}
        <button
          onClick={() => navigate("/predict-risk")}
          className="cve-toggle"
          style={{
            background: "#00aaff",
            color: "#fff",
            borderRadius: 8,
            padding: "10px 18px",
            boxShadow: "0 6px 18px rgba(0,0,0,0.5)",
            border: "none",
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          🧠 ML Risk Prediction
        </button>

        {/* ===== NEW: Sandbox Jobs Toggle Button ===== */}
        <button
          onClick={async () => {
            const willOpen = !sandboxVisible;
            setSandboxVisible(willOpen);
            if (willOpen) {
              // fetch history for the current user only
              const uid = getUserIdHeader();
              await fetchJobHistory({ page: 1, per_page: jobPerPage, user_id: uid });
            }
          }}
          className="cve-toggle"
          style={{
            background: sandboxVisible ? "#00aaff" : "#0b5f7a",
            color: "#fff",
            borderRadius: 8,
            padding: "10px 18px",
            boxShadow: "0 6px 18px rgba(0,0,0,0.5)",
            border: "none",
            cursor: "pointer",
            fontWeight: 700,
          }}
        >
          🧪 Sandbox Jobs
        </button>

        <button
  onClick={() => setAlertsVisible((s) => !s)}
  style={{
    background: hasAlerts ? "#ff4d4d" : "#153041",
    color: "#fff",
    borderRadius: 8,
    padding: "10px 18px",
    boxShadow: hasAlerts
      ? "0 0 15px #ff4d4d"
      : "0 6px 18px rgba(0,0,0,0.5)",
    border: "none",
    cursor: "pointer",
    fontWeight: 700,
  }}
>
  🚨 Alerts
</button>
      </div>

      {/* ===== Stats ===== */}
      <div className="stats-grid" style={{ marginTop: 24 }}>
        {stats.map((item, index) => (
          <div
            key={index}
            className="stat-card"
            style={{
              border: `1px solid ${item.color}`,
              boxShadow: `0 0 15px ${item.color}55`,
            }}
          >
            <h2 className="stat-title" style={{ color: item.color }}>
              {item.title}
            </h2>
            <h3 className="stat-value">{item.value}</h3>
            <p className="stat-desc">{item.description}</p>
          </div>
        ))}
      </div>
      

      {/* ===== Threat Intelligence Panel ===== */}
      <div style={{ marginTop: 18, display: "flex", justifyContent: "center" }}>
        {threatVisible && (
          <div className="scanner-section threats-panel">
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <h2
                style={{
                  margin: "6px 0",
                  display: "flex",
                  alignItems: "center",
                  gap: 8,
                }}
              >
                🔍 Threat Intelligence
              </h2>
              <button
                onClick={() => setThreatVisible(false)}
                className="patch-btn"
                style={{
                  background: "#ee6666",
                  color: "#fff",
                  borderRadius: 8,
                }}
              >
                Close
              </button>
            </div>

            <div style={{ marginTop: 12 }}>
              <ThreatsWidget initialLimit={10} compact={true} />
            </div>
          </div>
        )}
      </div>

      {/* ===== CVE Listing Panel (NEW) - SHOWS ONLY ID, SEVERITY, SUMMARY ===== */}
      <div style={{ marginTop: 18, display: "flex", justifyContent: "center" }}>
        {cveVisible && (
          <div
            className="scanner-section threats-panel"
            style={{ maxWidth: 1100, width: "100%" }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2 style={{ margin: "6px 0", display: "flex", alignItems: "center", gap: 8 }}>
                🧾 CVE Listing
              </h2>
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={() => {
                    setCveVisible(false);
                  }}
                  className="patch-btn"
                  style={{ background: "#ee6666", color: "#fff", borderRadius: 8 }}
                >
                  Close
                </button>

                {/* Explore button (go to full library) */}
                <button
                  onClick={() => navigate("/cve-list")}
                  className="patch-btn"
                  style={{ background: "#00aaff", color: "#fff", borderRadius: 8 }}
                >
                  Explore CVE Threat Library
                </button>
              </div>
            </div>

            <div style={{ marginTop: 12 }}>
              {cveLoading ? (
                <p>Loading CVEs...</p>
              ) : cveList && cveList.length ? (
                <div style={{ overflowX: "auto" }}>
                  <table className="scan-table" style={{ width: "100%" }}>
                    <thead>
                      <tr>
                        <th style={{ minWidth: 220 }}>CVE ID</th>
                        <th style={{ minWidth: 120 }}>SEVERITY</th>
                        <th>SUMMARY</th>
                      </tr>
                    </thead>
                    <tbody>
                      {cveList.map((c, i) => (
                        <tr
                          key={c.id || c.cve_id || `cve-${i}`}
                          style={{ cursor: "pointer" }}
                          onClick={() => {
                            if (c.cve_id) {
                              navigate(`/threatcve/${encodeURIComponent(c.cve_id)}`);
                            } else if (c.id) {
                              navigate(`/threatcve/${c.id}`);
                            }
                          }}
                          title="Click to open details"
                        >
                          <td style={{ whiteSpace: "nowrap", fontWeight: 600 }}>{c.cve_id || c.id || c.CVE || "-"}</td>

                          <td>
                            <span className="severity-tag" style={{ background: "#333", color: "#fff", padding: "6px 10px", borderRadius: 6 }}>
                              {getSeverityText(c)}
                            </span>
                          </td>

                          <td style={{ maxWidth: 480, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                            {c.description || c.summary || "-"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p>No CVE records available.</p>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ===== Vulnerability Scanner ===== */}
      <div style={{ marginTop: "60px", textAlign: "center" }}>
        {scannerVisible && (
          <div className="scanner-section">
            <h2>🛡️ ShieldPatch Vulnerability Scanner</h2>

            <button onClick={handleScan} disabled={loading} className="scan-btn">
              {loading ? "Scanning..." : "🔍 Start System Scan"}
            </button>

            {message && <p className="progress-text">{message}</p>}

            <label
              className="upload-btn"
              style={{
                cursor: "pointer",
                display: "inline-block",
                marginTop: 12,
              }}
            >
              📂 Upload File for Scan
              <input
                ref={fileInputRef}
                type="file"
                accept=".exe,.apk,.py,.js,.txt"
                onChange={handleFileChange}
                style={{ display: "none" }}
              />
            </label>

            {fileName && <p style={{ color: "#ccc" }}>File: {fileName}</p>}

            {fileProgress > 0 && (
              <div className="progress-container">
                <div
                  className="progress-bar"
                  style={{ width: `${fileProgress}%` }}
                ></div>
              </div>
            )}

            {fileScanMsg && <p className="progress-text">{fileScanMsg}</p>}

            {xhrRef.current && (
              <button
                onClick={cancelUpload}
                className="patch-btn"
                style={{ marginTop: 8 }}
              >
                ✖ Cancel Upload
              </button>
            )}

            {scanResults.length > 0 && (
              <div style={{ marginTop: "30px", overflowX: "auto" }}>
                <table className="scan-table">
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Software</th>
                      <th>CVE</th>
                      <th>Description</th>
                      <th>Severity</th>
                      <th>Risk</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResults.map((v) => (
                      <tr key={v.id}>
                        <td>{v.id}</td>
                        <td>{v.software}</td>
                        <td>{v.cve}</td>
                        <td>{v.description}</td>
                        <td>
                          <span
                            className="severity-tag"
                            style={{ background: v.color }}
                          >
                            {v.severity}
                          </span>
                        </td>
                        <td>{v.riskScore}</td>
                        <td>
                          {v.patchAvailable ? (
                            <button
                              onClick={async () => {
                                const scriptPath = v.patch_script || `./apply_patch_${(v.cve || v.id || v.name)}.sh`;
                                const jobName = `patch-${(v.cve || v.id || v.name)}`.replace(/\s+/g, "_");

                                setMessage("Submitting patch job...");
                                const result = await handleRunPatch(scriptPath, "/sandbox/data/testapp", jobName);

                                // Optional: still open the modal AFTER job runs
                                if (result && result.ok) {
  // ✅ UPDATE UI → mark this vuln as patched
  setScanResults(prev =>
    prev.map(item =>
      item.id === v.id
        ? { ...item, patchAvailable: false, severity: "Patched", riskScore: 0 }
        : item
    )
  );

  setPatchQuery(v.cve || v.id || v.name || "");
  setPatchModalOpen(true);
}
                              }}
                            >
                              Patch Now
                            </button>
                          ) : (
                            <span style={{ color: "#4caf50" }}>✔ Patched</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {discovery.length > 0 && (
              <div style={{ marginTop: "40px", overflowX: "auto" }}>
                <h3 style={{ color: "#00d4ff", marginBottom: 12 }}>
                  Discovered Software
                </h3>
                <table className="scan-table">
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Version</th>
                      <th>Path</th>
                      <th>Vulnerable</th>
                      <th>Linked CVE</th>
                      <th>Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {discovery.map((pkg, i) => {
                      const vuln = findVulnForPackage(pkg);
                      return (
                        <tr key={i}>
                          <td>{pkg.name || pkg.bundle_identifier}</td>
                          <td>{pkg.version}</td>
                          <td>{pkg.path}</td>
                          <td>
                            {vuln ? (
                              <span
                                className="severity-tag"
                                style={{ background: "#ff4d4d" }}
                              >
                                Yes
                              </span>
                            ) : (
                              <span style={{ color: "#4caf50" }}>No</span>
                            )}
                          </td>
                          <td>{vuln ? vuln.cve : "-"}</td>
                          <td>{vuln ? vuln.riskScore : "-"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ===== NEW: History Panel (appears after scanner area) ===== */}
      <div style={{ marginTop: 22, display: "flex", justifyContent: "center" }}>
        {historyVisible && (
          <div className="scanner-section threats-panel" style={{ maxWidth: 1100, width: "100%" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2 style={{ margin: "6px 0", display: "flex", alignItems: "center", gap: 8 }}>
                📜 Scan History
              </h2>

              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={() => {
                    refreshHistory();
                  }}
                  className="patch-btn"
                  style={{ background: "#00aaff", color: "#fff", borderRadius: 8 }}
                >
                  Refresh
                </button>

                <button
                  onClick={() => setHistoryVisible(false)}
                  className="patch-btn"
                  style={{ background: "#ee6666", color: "#fff", borderRadius: 8 }}
                >
                  Close
                </button>
              </div>
            </div>

            <div style={{ marginTop: 12 }}>
              {historyLoading ? (
                <p>Loading history...</p>
              ) : scanResults && scanResults.length ? (
                <div style={{ overflowX: "auto" }}>
                  <table className="scan-table" style={{ width: "100%" }}>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>User</th>
                        <th>Filename / Software</th>
                        <th>CVE</th>
                        <th>Summary / Description</th>
                        <th>Severity</th>
                        <th>Risk</th>
                        <th>Source</th>
                        <th>When</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanResults.map((r, i) => (
                        <tr key={r.id || `r-${i}`}>
                          <td>{r.id}</td>
                          <td>{r.user_id ?? (user?.username || "-")}</td>
                          <td>{r.filename || r.software}</td>
                          <td>{r.cve || "-"}</td>
                          <td style={{ maxWidth: 280, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                            {r.summary || r.description || "-"}
                          </td>
                          <td>
                            <span className="severity-tag" style={{ background: r.color || (r.severity === "Clean" ? "#4caf50" : "#ff4d4d") }}>
                              {r.severity || "-"}
                            </span>
                          </td>
                          <td>{r.risk_score ?? r.riskScore ?? "-"}</td>
                          <td>{r.source || "-"}</td>
                          <td>{r.created_at ? new Date(r.created_at).toLocaleString() : "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p>No scan history available yet.</p>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ===== NEW: Sandbox Jobs Panel ===== */}
      <div style={{ marginTop: 22, display: "flex", justifyContent: "center" }}>
        {sandboxVisible && (
          <div className="scanner-section threats-panel" style={{ maxWidth: 1100, width: "100%" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h2 style={{ margin: "6px 0", display: "flex", alignItems: "center", gap: 8 }}>
                🧪 Sandbox Jobs
              </h2>

              <div style={{ display: "flex", gap: 8 }}>
                <button
                  onClick={() => fetchJobHistory({ page: 1, per_page: jobPerPage, user_id: getUserIdHeader() })}
                  className="patch-btn"
                  style={{ background: "#00aaff", color: "#fff", borderRadius: 8 }}
                >
                  Refresh Jobs
                </button>

                <button
                  onClick={() => setSandboxVisible(false)}
                  className="patch-btn"
                  style={{ background: "#ee6666", color: "#fff", borderRadius: 8 }}
                >
                  Close
                </button>
              </div>
            </div>

            <div style={{ marginTop: 12 }}>
              {/* Show the SandboxJobs component (keeps it isolated) */}
              <SandboxJobs
                onRunJob={handleRunJob}
                onDownloadLog={handleDownloadJobLog}
                onRestoreSnapshot={handleRestoreSnapshot}
                jobHistory={jobHistory}
                loading={jobLoading}
                fetchJobHistory={fetchJobHistory}
                message={jobMessage}
                currentUserId={getUserIdHeader()}
              />

              {/* lightweight fallback listing if SandboxJobs component not present or for quick preview */}
              {!SandboxJobs && (
                <>
                  <p>No SandboxJobs UI component found — showing raw job list:</p>
                  {jobLoading ? <p>Loading...</p> : (
                    <div style={{ overflowX: "auto" }}>
                      <table className="scan-table" style={{ width: "100%" }}>
                        <thead>
                          <tr>
                            <th>ID</th><th>Job</th><th>Image Tag</th><th>Container</th><th>Success</th><th>When</th><th>Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {jobHistory.map((j) => (
                            <tr key={j.id}>
                              <td>{j.id}</td>
                              <td>{j.job_name}</td>
                              <td style={{ maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis" }}>{j.image_tag}</td>
                              <td>{j.container_name}</td>
                              <td>{j.succeeded ? "Yes" : "No"}</td>
                              <td>{j.created_at ? new Date(j.created_at).toLocaleString() : "-"}</td>
                              <td style={{ display: "flex", gap: 8 }}>
                                <button onClick={() => handleDownloadJobLog(j.id, `job-${j.id}-${j.job_name || "job"}.log`)}>Download Log</button>
                                {j.snapshot_tag ? (
                                  <button onClick={() => handleRestoreSnapshot(j.snapshot_tag)}>Restore Snapshot</button>
                                ) : null}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>

      {/* ===== Alerts Panel (Toggle) ===== */}
<div style={{ marginTop: 22, display: "flex", justifyContent: "center" }}>
  {alertsVisible && (
    <div className="scanner-section threats-panel" style={{ maxWidth: 600, width: "100%" }}>
      
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h2>🚨 Alerts</h2>

        <button
          onClick={() => setAlertsVisible(false)}
          className="patch-btn"
          style={{ background: "#ee6666", color: "#fff", borderRadius: 8 }}
        >
          Close
        </button>
      </div>

      <div style={{ marginTop: 12 }}>
        <AlertsPanel setHasAlerts={setHasAlerts} />
      </div>

    </div>
  )}
</div>

      {/* ===== Activity ===== */}
      <div className="activity-section">
        <h2>🔍 Recent Security Activity</h2>
        <ul>
          <li>⚠️ SQL Injection attempt blocked on Admin Panel (IP: 192.168.2.47)</li>
          <li>🩹 Patch KB5023442 applied successfully on 6 systems.</li>
          <li>🤖 ML Model flagged potential ransomware pattern — Low severity.</li>
          <li>🔐 User login anomaly detected and blocked from foreign IP.</li>
        </ul>
      </div>
      {/* Patch Recommendation Modal — paste this near the root return of the component */}
          <PatchRecommendation
            open={patchModalOpen}
            initialQuery={patchQuery}
            hostOs={hostOs}
            onClose={() => setPatchModalOpen(false)}
            />
    </div>
  );
}
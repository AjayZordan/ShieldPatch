// frontend/src/components/PatchRecommendation.js
import React, { useState, useEffect, useCallback } from "react";
import { recommendPatch } from "../api/patches";

export default function PatchRecommendation({ open, initialQuery = "", hostOs = "", onClose = () => {} }) {
  const [visible, setVisible] = useState(open);
  const [query, setQuery] = useState(initialQuery);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState("");

  // per-result run state: { [p.id]: { running:bool, ok:bool, msg:string } }
  const [runStatus, setRunStatus] = useState({});

  const [jobModal, setJobModal] = useState({
  open: false,
  jobId: null,
  snapshotTag: null,
});
const [patchResult, setPatchResult] = useState(null);

  // 🔥 FIX: Wrap fetchRecommendations in useCallback so React does NOT warn.
  const fetchRecommendations = useCallback(
    async (q) => {
      if (!q) return;
      setLoading(true);
      setError("");
      setResults([]);
      try {
        const data = await recommendPatch(q, hostOs);
        setResults(data || []);
      } catch (err) {
        setError(err.message || "Failed to fetch");
      } finally {
        setLoading(false);
      }
    },
    [hostOs] // dependencies
  );

function classifyPatchResult(res) {
  if (res?.patch_status === "PATCH_APPLIED") {
    return "PATCH_SUCCESS";
  }

  if (res?.patch_status === "PATCH_FAILED_ROLLED_BACK") {
    return "PATCH_FAILED_ROLLED_BACK";
  }

  if (res?.dry_run === true) {
    return "BLOCKED_DRY_RUN";
  }

  return "PATCH_BLOCKED";
}

  // 🔥 FIX: Now we can safely include fetchRecommendations in dependencies
  useEffect(() => {
    setVisible(open);
    setQuery(initialQuery);
    if (open && initialQuery) fetchRecommendations(initialQuery);
  }, [open, initialQuery, fetchRecommendations]);

  function handleClose() {
    setVisible(false);
    onClose();
  }

  if (!visible) return null;

  // Helper: update runStatus for a specific id
  const setResultRunStatus = (id, status) => {
    setRunStatus((prev) => ({ ...prev, [id]: { ...(prev[id] || {}), ...status } }));
  };

  // Run patch by calling sandbox run_job endpoint
  const handleApplyPatch = async (p) => {
    // prevent double-run
    const id = p.id || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    if (runStatus[id]?.running) return;
    setResultRunStatus(id, { running: true, ok: false, msg: "Submitting job..." });

    try {
      // build payload
      const API_BASE = process.env.REACT_APP_API_BASE || "http://127.0.0.1:5000";
      // host_data_dir should map to the sandbox/data on the host - adjust as needed in your environment
      const hostDataDir = process.env.REACT_APP_SANDBOX_HOST_PATH || "/Users/ajaykumar/Desktop/ShieldPatch/sandbox/data";
      const workdir = p.workdir || "/sandbox/data/testapp"; // suggestion: results may include a recommended workdir
      const script = "./apply_patch.sh";
      const jobName = `ui_patch_${(p.cve || p.id || p.title || "patch").toString().replace(/\s+/g, "_")}`;

      const token = localStorage.getItem("token");
      const userObj = localStorage.getItem("user");
      const userId = userObj ? (JSON.parse(userObj).id || JSON.parse(userObj).user_id || JSON.parse(userObj).userId) : null;

      const body = {
        host_data_dir: hostDataDir,
        container_name: `sandbox_job_${jobName}_${Date.now().toString(36).slice(-6)}`,
        workdir,
        script,
        dry_run: Boolean(p.dry_run === true),
        snapshot_after: Boolean(p.snapshot_after !== false), // default true unless explicit false
        keep_container: false,
        timeout_secs: 120,
        job_name: jobName,
        user_id: userId,
      };

      setResultRunStatus(id, { running: true, ok: false, msg: "Calling sandbox..." });

      const res = await fetch(`${API_BASE}/sandbox/run_job`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
      });

      let data = null;
      try {
        data = await res.json();
      } catch {
        data = null;
      }

      if (!res.ok) {
        const msg = data?.error || data?.detail || `HTTP ${res.status}`;
        setResultRunStatus(id, { running: false, ok: false, msg: `Failed: ${msg}` });
        return { ok: false, data };
      }

      // success path
      const success = Boolean(data?.success || data?.apply_ok);
      const tag = data?.snapshot_tag || data?.image_tag || null;
      const outMsg = success ? `Success${tag ? ` (snapshot: ${tag})` : ""}` : `Failed: ${data?.error || data?.apply_stderr || "unknown"}`;
      setResultRunStatus(id, { running: false, ok: success, msg: outMsg });

      // Optional: if apply_stdout present, attach to p (client-side only)
      // Update the results array so UI reflects status
      setResults((prev) => prev.map((r) => {
        if ((r.id && r.id === p.id) || (!r.id && r.title === p.title)) {
          return { ...r, last_run: { ok: success, snapshot_tag: tag, stdout: data?.apply_stdout, stderr: data?.apply_stderr } };
        }
        return r;
      }));

      return { ok: success, data };
    } catch (err) {
      setResultRunStatus(id, { running: false, ok: false, msg: `Error: ${err.message || err}` });
      return { ok: false, error: err };
    }
  };

  return (
    <div style={overlay}>
      <div style={modal}>
        <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
          <h3 style={{color:"#dff6ff"}}>Patch Recommendation</h3>
          <button onClick={handleClose} style={closeBtn}>X</button>
        </div>

        <div style={{marginBottom:10}}>
          <input 
            value={query} 
            onChange={e=>setQuery(e.target.value)} 
            placeholder="CVE or product" 
            style={{
              width:"70%",
              padding:8,
              background:"#0d1b24",
              border:"1px solid #234",
              borderRadius:6,
              color:"#dff6ff"
            }} 
          />
          <button 
            onClick={()=>fetchRecommendations(query)} 
            style={{
              marginLeft:8,
              padding:"8px 12px",
              background:"#39bdf3",
              color:"#041b27",
              border:"none",
              borderRadius:6,
              cursor:"pointer",
              fontWeight:"bold"
            }}
          >
            Search
          </button>
        </div>

        {loading && <div style={{color:"#9fb7c6"}}>Loading…</div>}
        {error && <div style={{color:"#ff7b7b"}}>{error}</div>}

        <div style={{maxHeight:"50vh",overflow:"auto"}}>
          {!loading && results.length===0 && <div style={{color:"#9fb7c6"}}>No recommendations</div>}
          {results.map(p => {
            const id = p.id || `${p.title || "r"}-${p.fixed_in || "x"}`;
            const st = runStatus[id] || {};
            return (
              <div key={id} style={card}>
                <div style={{display:"flex",justifyContent:"space-between"}}>
                  <div>
                    <strong style={{color:"#f2fbff"}}>{p.title}</strong>
                    <div style={{fontSize:13,color:"#a7c7d9"}}>
                      {p.vendor} — Fixed in: {p.fixed_in || "N/A"}
                    </div>
                  </div>
                  <div style={{textAlign:"right",color:"#9fcde3"}}>
                    <div style={{fontSize:12}}>{p.verified ? "Verified" : "Unverified"}</div>
                    <div style={{fontSize:12}}>
                      {p.confidence ? `Confidence: ${(p.confidence*100).toFixed(0)}%` : ""}
                    </div>
                  </div>
                </div>

                <div style={{marginTop:8}}>
                  <a 
                    href={p.source_url} 
                    target="_blank" 
                    rel="noreferrer"
                    style={{color:"#4dc9ff", fontWeight:"bold"}}
                  >
                    Vendor advisory
                  </a>
                </div>

                <div style={{marginTop:8}}>
                  <pre style={cmdBox}>{p.apply_cmd}</pre>
                  <div style={{fontSize:13,color:"#aacbda"}}>{p.notes}</div>
                </div>

                <div style={{marginTop:8,display:"flex",gap:8,alignItems:"center"}}>
                  <button 
                    onClick={()=>navigator.clipboard?.writeText(p.apply_cmd)}
                    style={actionBtn}
                  >
                    Copy commands
                  </button>
                  <button
  onClick={async () => {
  setResultRunStatus(id, { running: true, ok: false, msg: "Dry-run queued..." });

  const res = await handleApplyPatch({
    ...p,
    dry_run: true,
    snapshot_after: false,
  });

  setPatchResult({
    type: "BLOCKED_DRY_RUN",
    data: res?.data || {},
  });

  setJobModal({
    open: true,
    jobId: res?.data?.job_id || null,
    snapshotTag: null,
    status: "BLOCKED_DRY_RUN",

    
  });

}}
  style={actionBtnSecondary}
  disabled={st.running}
>
  Dry-run
</button>

{jobModal.status === "BLOCKED_DRY_RUN" && (
  <>
    <h3 style={{ color: "#ffd27d" }}>Patch Blocked (Dry-Run)</h3>
    <p>This was a simulation only. No files were changed.</p>

    <button
      style={actionBtnSecondary}
      onClick={() => {
        setJobModal({ open: false });
        setPatchResult(null);
      }}
    >
      Close
    </button>
  </>
)}

                  {/* ===== NEW: Apply Patch button ===== */}
                  <div style={{marginLeft: "auto", display: "flex", gap: 8, alignItems: "center"}}>
                    <button
                      onClick={async () => {
                        setResultRunStatus(id, { running: true, ok: false, msg: "Queued..." });
                        const res = await handleApplyPatch(p);
const backendData = res?.data || {};

const resultType = classifyPatchResult(backendData);

setPatchResult({
  type: resultType,
  data: backendData,
});

setJobModal({
  open: true,
  jobId: backendData.job_id || null,
  snapshotTag: backendData.snapshot_tag || null,
  status:
    resultType === "PATCH_SUCCESS"
      ? "PATCH_APPLIED"
      : resultType === "PATCH_FAILED_ROLLED_BACK"
      ? "PATCH_FAILED_ROLLED_BACK"
      : resultType === "BLOCKED_DRY_RUN"
      ? "BLOCKED_DRY_RUN"
      : "PATCH_BLOCKED",
});
                      }}
                      style={{
                        background: "#28c76f",
                        color: "#041b27",
                        padding: "8px 12px",
                        borderRadius: 6,
                        border: "none",
                        cursor: st.running ? "wait" : "pointer",
                        fontWeight: "bold",
                        opacity: st.running ? 0.7 : 1
                      }}
                      disabled={st.running}
                    >
                      {st.running ? "Running…" : "Apply Patch"}
                    </button>

                    {/* run status text */}
                    <div style={{ fontSize: 12, color: st.ok ? "#8ef0a3" : "#ffd0c0" }}>
                      {st.msg || (p.last_run ? (p.last_run.ok ? "Last run: OK" : "Last run: Failed") : "")}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        <div style={{textAlign:"right",marginTop:10}}>
          <button 
            onClick={handleClose} 
            style={{
              padding:"8px 16px",
              background:"#39bdf3",
              color:"#041b27",
              border:"none",
              borderRadius:6,
              cursor:"pointer",
              fontWeight:"bold"
            }}
          >
            Close
          </button>
        </div>
      </div>
      {jobModal.open && (
  <div style={overlay}>
    <div style={{ ...modal, width: 420 }}>

      {/* ✅ CASE 1: PATCH SUCCESS */}
      {jobModal.status === "PATCH_APPLIED" && (
  <>
    <h3 style={{ color: "#dff6ff" }}>Patch Applied Successfully</h3>

    <p><strong>Job ID:</strong> {jobModal.jobId}</p>

    {jobModal.snapshotTag && (
      <p><strong>Snapshot:</strong> {jobModal.snapshotTag}</p>
    )}

    <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
      <button
  style={actionBtn}
  onClick={() => {
  if (!jobModal.jobId) {
    alert("No logs available for this operation.");
    return;
  }

  window.open(
    `http://127.0.0.1:5000/api/sandbox/job_log/${jobModal.jobId}`,
    "_blank"
  );
}}
>
  View Logs
</button>

      <button
        style={actionBtnSecondary}
        onClick={() => {
          setJobModal({ open: false });
          setPatchResult(null);
        }}
      >
        Close
      </button>
    </div>
  </>
)}

      {/* ⚠️ CASE 2: PATCH FAILED → ROLLBACK DONE */}
      {jobModal.status === "PATCH_FAILED_ROLLED_BACK" && (
        <>
          <h3 style={{ color: "#f39c12" }}>⚠ Patch Failed – Rolled Back</h3>

          <p>
            The patch could not be applied safely.  
            The system was automatically restored to the previous stable state.
          </p>

          <p style={{ fontSize: 13 }}>
            <strong>Rollback Backup:</strong>
          </p>
          <code style={{ fontSize: 12 }}>
            {patchResult.data?.rollback_backup_path}
          </code>

          <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
            <button
  style={actionBtn}
onClick={() => {
  if (!jobModal.jobId) {
    alert("No logs available for this operation.");
    return;
  }

  window.open(
    `http://127.0.0.1:5000/api/sandbox/job_log/${jobModal.jobId}`,
    "_blank"
  );
}}
>
  View Error Logs
</button>

            <button
              style={actionBtnSecondary}
              onClick={() => {
                setJobModal({ open: false });
                setPatchResult(null);
              }}
            >
              Close
            </button>
          </div>
        </>
      )}

      {jobModal.status === "BLOCKED_DRY_RUN" && (
  <>
    <h3 style={{ color: "#ffd27d" }}>Dry Run Completed</h3>

    <p>
      This was a simulation only.  
      No files were modified.
    </p>

    {jobModal.jobId && (
      <p><strong>Job ID:</strong> {jobModal.jobId}</p>
    )}

    <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
      <button
        style={actionBtn}
        onClick={() => {
  if (!jobModal.jobId) {
    alert("No logs available for this operation.");
    return;
  }

  window.open(
    `http://127.0.0.1:5000/api/sandbox/job_log/${jobModal.jobId}`,
    "_blank"
  );
}}
      >
        View Logs
      </button>

      <button
        style={actionBtnSecondary}
        onClick={() => setJobModal({ open: false })}
      >
        Close
      </button>
    </div>
  </>
)}

      {/* ⛔ CASE 3: PATCH BLOCKED */}
      {jobModal.status === "PATCH_BLOCKED" && (
        <>
          <h3 style={{ color: "#e74c3c" }}>⛔ Patch Blocked</h3>

          <p>
            This patch cannot be applied automatically.  
            Manual review or vendor update is required.
          </p>

          <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
            <button
  style={actionBtn}
  onClick={() => {
  if (!jobModal.jobId) {
    alert("No logs available for this operation.");
    return;
  }

  window.open(
    `http://127.0.0.1:5000/api/sandbox/job_log/${jobModal.jobId}`,
    "_blank"
  );
}}
>
  View Details
</button>

            <button
              style={actionBtnSecondary}
              onClick={() => {
                setJobModal({ open: false });
                setPatchResult(null);
              }}
            >
              Close
            </button>
          </div>
        </>
      )}

    </div>
  </div>
)}
    </div>
  );
}

/* STYLES */

const overlay = {
  position:"fixed",
  top:0,
  left:0,
  right:0,
  bottom:0,
  background:"rgba(2,8,15,0.75)",
  backdropFilter:"blur(4px)",
  display:"flex",
  alignItems:"center",
  justifyContent:"center",
  zIndex:9999
};

const modal = {
  width:760,
  background:"linear-gradient(180deg, #081018 0%, #0b1724 100%)",
  padding:20,
  borderRadius:14,
  boxShadow:"0 12px 40px rgba(0,0,0,0.55)",
  border:"1px solid rgba(255,255,255,0.08)",
  color:"#e6f7ff"
};

const closeBtn = {
  background:"transparent",
  border:"1px solid rgba(255,255,255,0.15)",
  cursor:"pointer",
  color:"#cceeff",
  padding:"4px 8px",
  borderRadius:6,
  fontSize:14
};

const card = {
  border:"1px solid rgba(255,255,255,0.06)",
  padding:12,
  borderRadius:8,
  marginBottom:14,
  background:"rgba(255,255,255,0.03)"
};

const cmdBox = {
  background:"rgba(0,0,0,0.3)",
  padding:10,
  borderRadius:6,
  overflowX:"auto",
  fontFamily:"monospace",
  color:"#dff6ff",
  fontSize:13,
  border:"1px solid rgba(255,255,255,0.05)"
};

const actionBtn = {
  background:"#39bdf3",
  color:"#041b27",
  padding:"8px 12px",
  borderRadius:6,
  border:"none",
  cursor:"pointer",
  fontWeight:"bold"
};

const actionBtnSecondary = {
  background:"transparent",
  color:"#cceaff",
  padding:"8px 12px",
  borderRadius:6,
  border:"1px solid rgba(255,255,255,0.15)",
  cursor:"pointer"
};
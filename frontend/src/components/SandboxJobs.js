// src/components/SandboxJobs.js
import React, { useEffect, useState } from "react";
import { fetchJobHistory, fetchFullJobLog, downloadJobLog, runSandboxJob } from "../api/sandbox";
// Note: runSandboxJob is imported from ../api/sandbox as fallback if Dashboard doesn't pass a runner.

export default function SandboxJobs({
  userId = null,
  perPage = 10,
  previewChars = 200,
  onRunJob = null, // optional prop: Dashboard can pass its own runner
}) {
  const [jobs, setJobs] = useState([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [totalCount, setTotalCount] = useState(null);

  const [modalOpen, setModalOpen] = useState(false);
  const [modalLog, setModalLog] = useState(null);
  const [modalLoading, setModalLoading] = useState(false);

  // runState maps jobId -> { loading: bool, success: bool|null, message: string|null }
  const [runState, setRunState] = useState({});

  async function loadJobs(p = 1) {
    setLoading(true);
    setErr(null);
    try {
      const resp = await fetchJobHistory({ page: p, per_page: perPage, preview_chars: previewChars});
      if (!resp || !resp.success) throw new Error(resp?.error || "Failed to load jobs");
      setJobs(resp.jobs || []);
      setTotalCount(resp.count ?? (resp.jobs ? resp.jobs.length : 0));
      setPage(resp.page || p);
    } catch (e) {
      setErr(e.message || String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadJobs(1);
    // eslint-disable-next-line
  }, [userId, perPage]);

  async function openLog(id) {
    setModalOpen(true);
    setModalLog(null);
    setModalLoading(true);
    try {
      const resp = await fetchFullJobLog(id);
      if (!resp || !resp.success) throw new Error(resp?.error || "Failed to fetch log");
      setModalLog(resp);
    } catch (e) {
      setModalLog({ error: e.message || String(e) });
    } finally {
      setModalLoading(false);
    }
  }

  async function handleDownload(id, filename) {
    try {
      const resp = await downloadJobLog(id);
      // downloadJobLog may return either a Blob (old behaviour) or { success: true, blob }
      let blob = null;
      if (!resp) throw new Error("No response from download API");
      if (resp instanceof Blob) {
        blob = resp;
      } else if (resp.success && resp.blob) {
        blob = resp.blob;
      } else if (resp.success === false) {
        throw new Error(resp.error || "Download failed");
      } else {
        // try to handle if resp has raw text
        if (resp.raw instanceof Blob) blob = resp.raw;
        else throw new Error("Unsupported download response shape");
      }

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename || `job-${id}.log`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      alert("Download failed: " + (e?.message || e));
    }
  }

  // Run a job (either call the provided onRunJob prop, or fallback to runSandboxJob)
  async function handleRunExistingJob(job) {
    const jid = job.id;
    setRunState((s) => ({ ...s, [jid]: { loading: true, success: null, message: "Starting..." } }));
    try {
      const payload = {
        // prefer host_path from job record, else default to local path used in backend dev
        host_data_dir: job.host_path || "/Users/ajaykumar/Desktop/ShieldPatch/sandbox/data",
        container_name: `sandbox_job_rerun_${jid}_${Date.now().toString(36).slice(-6)}`,
        workdir: job.workdir || "/sandbox/data/testapp",
        script: job.script || "./apply_patch.sh",
        snapshot_after: true,
        keep_container: false,
        timeout_secs: 120,
        user_id: userId || job.user_id || null,
        job_name: `rerun-${jid}`
      };

      let result;
      if (typeof onRunJob === "function") {
        // Dashboard can provide its own runner (it already does in your Dashboard)
        result = await onRunJob(payload);
      } else {
        // fallback to our API helper
        result = await runSandboxJob(payload);
      }

      // result handling: both runners return object; treat success by shape
      const ok = result && (result.success || result.ok || result.apply_ok);
      setRunState((s) => ({ ...s, [jid]: { loading: false, success: Boolean(ok), message: ok ? "Job finished" : (result?.error || "Job failed") } }));
      // refresh jobs to pick up new snapshot / record
      loadJobs(page);
    } catch (e) {
      setRunState((s) => ({ ...s, [jid]: { loading: false, success: false, message: e?.message || String(e) } }));
      // don't crash UI - show message
    }
  }

  // convenience: show run status message under each job
  const renderRunStatus = (j) => {
    const st = runState[j.id];
    if (!st) return null;
    if (st.loading) return <div style={{ fontSize: 12, color: "#9fb5d9" }}>Running…</div>;
    if (st.success === true) return <div style={{ fontSize: 12, color: "#7ee787" }}>{st.message || "Success"}</div>;
    if (st.success === false) return <div style={{ fontSize: 12, color: "#ff8b8b" }}>{st.message || "Failed"}</div>;
    return null;
  };

  return (
    <div className="sandbox-jobs-card" style={{ border: "1px solid #2c2c2c", padding: 14, borderRadius: 8, background: "#0f1720", color: "#e6eef8" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
        <h3 style={{ margin: 0 }}>Recent Sandbox Jobs</h3>
        <div>
          <button onClick={() => loadJobs(1)} style={{ marginRight: 8 }}>Refresh</button>
        </div>
      </div>

      {loading ? (
        <div>Loading…</div>
      ) : err ? (
        <div style={{ color: "#ff8080" }}>Error: {err}</div>
      ) : jobs.length === 0 ? (
        <div>No jobs found.</div>
      ) : (
        <>
          <div style={{ display: "grid", gap: 10 }}>
            {jobs.map((j) => (
              <div key={j.id} style={{ padding: 10, borderRadius: 6, background: "#041027", border: "1px solid rgba(255,255,255,0.03)" }}>
                <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "flex-start" }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 600 }}>{j.job_name || "job" } <small style={{ color: "#9fb5d9" }}>#{j.id}</small></div>
                    <div style={{ color: "#9fb5d9", fontSize: 12 }}>{j.image_tag}</div>
                    <div style={{ marginTop: 6, fontSize: 13, color: "#d6e7ff", whiteSpace: "pre-wrap" }}>
                      {(j.stdout_preview || j.stderr_preview || "").slice(0, previewChars)}
                      {((j.stdout_preview || "") + (j.stderr_preview || "")).length > previewChars ? " …" : ""}
                    </div>
                  </div>

                  <div style={{ textAlign: "right", minWidth: 170 }}>
                    <div style={{ marginBottom: 8 }}>
                      <strong style={{ color: j.succeeded ? "#7ee787" : "#ff8b8b" }}>{j.succeeded ? "Succeeded" : "Failed"}</strong>
                    </div>
                    <div style={{ fontSize: 12, color: "#9fb5d9" }}>{j.created_at ? new Date(j.created_at).toLocaleString() : "-"}</div>

                    <div style={{ marginTop: 8, display: "flex", gap: 6, justifyContent: "flex-end" }}>
                      <button onClick={() => openLog(j.id)} title="View full log">View</button>
                      <button onClick={() => handleDownload(j.id, `job-${j.id}-${(j.job_name||"job")}.log`)} title="Download log">Download</button>

                      {/* Run button: allow rerun or reapply */}
                      <button
                        onClick={() => handleRunExistingJob(j)}
                        title="Run this job again (recreate container & run script)"
                        disabled={runState[j.id]?.loading}
                        style={{ marginLeft: 6 }}
                      >
                        {runState[j.id]?.loading ? "Running…" : "Run Job"}
                      </button>
                    </div>

                    {/* run status message */}
                    <div style={{ marginTop: 8 }}>
                      {renderRunStatus(j)}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12 }}>
            <div style={{ color: "#9fb5d9" }}>
              {totalCount != null ? `Total: ${totalCount}` : ""}
            </div>

            <div style={{ display: "flex", gap: 6 }}>
              <button onClick={() => loadJobs(Math.max(1, page - 1))} disabled={page <= 1}>Prev</button>
              <div style={{ padding: "6px 10px", background: "#022135", borderRadius: 6 }}>{page}</div>
              <button onClick={() => loadJobs(page + 1)} disabled={jobs.length < perPage}>Next</button>
            </div>
          </div>
        </>
      )}

      {/* Modal */}
      {modalOpen && (
        <div style={{
          position: "fixed", inset: 0, display: "flex", alignItems: "center", justifyContent: "center",
          background: "rgba(0,0,0,0.6)", zIndex: 9999
        }}>
          <div style={{ width: "min(95%,1000px)", maxHeight: "85vh", overflow: "auto", background: "#071326", padding: 18, borderRadius: 8, color: "#e6eef8" }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
              <strong>Job Log</strong>
              <div>
                <button onClick={() => setModalOpen(false)} style={{ marginLeft: 8 }}>Close</button>
              </div>
            </div>

            {modalLoading ? <div>Loading log…</div> : modalLog?.error ? (
              <div style={{ color: "#ff8b8b" }}>Error: {modalLog.error}</div>
            ) : (
              <>
                <div style={{ fontSize: 13, color: "#9fb5d9", marginBottom: 8 }}>
                  Job: {modalLog.job_name} — ID: {modalLog.id} — {modalLog.created_at ? new Date(modalLog.created_at).toLocaleString() : "-"}
                </div>

                <div style={{ whiteSpace: "pre-wrap", fontFamily: "monospace", background: "#00111a", padding: 10, borderRadius: 6, maxHeight: "55vh", overflow: "auto" }}>
                  {modalLog.stdout || ""}
                  {modalLog.stderr ? ("\n\n--- STDERR ---\n" + modalLog.stderr) : ""}
                </div>

                <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
                  <button onClick={() => {
                    handleDownload(modalLog.id, `job-${modalLog.id}-${(modalLog.job_name||"job")}.log`);
                  }}>Download</button>
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
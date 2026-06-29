// src/api/sandbox.js
// Robust sandbox API helper — normalizes base URL, returns consistent results, and logs debug info.

const RAW_API_BASE = process.env.REACT_APP_API_BASE || "http://127.0.0.1:5000";

/**
 * Normalize base:
 * - remove trailing slashes
 * - if the value ends with '/api', strip that so we can safely append '/api/...'
 */
function normalizeBase(raw) {
  if (!raw || typeof raw !== "string") return "http://127.0.0.1:5000";
  let v = raw.trim();
  v = v.replace(/\/+$/, ""); // drop trailing slashes
  if (v.toLowerCase().endsWith("/api")) {
    v = v.slice(0, -4);
    v = v.replace(/\/+$/, "");
  }
  return v;
}

const API_BASE = normalizeBase(RAW_API_BASE);

/** Helper to build headers including token and X-User-ID if available in localStorage. */
function buildHeaders(extra = {}) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json",
    ...extra,
  };

  try {
    const token = localStorage.getItem("token");
    if (token) headers["Authorization"] = `Bearer ${token}`;
  } catch (e) {
    // ignore if localStorage not available
  }

  try {
    const u = localStorage.getItem("user");
    if (u) {
      const parsed = JSON.parse(u);
      const uid = parsed?.id ?? parsed?.user_id ?? parsed?.userId;
      if (uid) headers["X-User-ID"] = String(uid);
    }
  } catch (e) {
    // ignore parse errors
  }

  return headers;
}

/**
 * Safe JSON/text parser helper
 */
async function safeParseResponse(res) {
  const ct = (res.headers.get("content-type") || "").toLowerCase();
  try {
    if (ct.includes("application/json")) {
      return await res.json();
    }
    const txt = await res.text();
    // try parse if it looks like json
    try {
      return JSON.parse(txt);
    } catch {
      return { raw: txt };
    }
  } catch (e) {
    return { raw_error: String(e) };
  }
}

/**
 * runSandboxJob(payload) -> posts to backend /api/sandbox/run_job
 * Returns a consistent object: on success `{ success: true, ... }`; on failure `{ success: false, error: "...", status?: N, detail?: ... }`
 * It will never throw (helps UI avoid uncaught exceptions). Use console.debug to inspect.
 */
export async function runSandboxJob(payload = {}) {
  const url = `${API_BASE}/api/sandbox/run_job`;
  console.debug("[sandbox.runSandboxJob] POST ->", url, "payload:", payload);

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: buildHeaders(),
      body: JSON.stringify(payload),
    });

    const parsed = await safeParseResponse(res);
    console.debug("[sandbox.runSandboxJob] response status:", res.status, "parsed:", parsed);

    if (res.ok) {
      // Accept either explicit success, apply_ok, or just return parsed body
      if (parsed && (parsed.success || parsed.apply_ok || parsed.ok)) {
        return { success: true, ...parsed };
      }
      // If backend returns something but no explicit success flag, return it and mark success
      return { success: true, ...parsed };
    } else {
      // non-2xx
      const errMsg = parsed?.error || parsed?.detail || (typeof parsed === "string" ? parsed : parsed?.raw) || `Status ${res.status}`;
      console.warn("[sandbox.runSandboxJob] non-ok response:", res.status, errMsg);
      return { success: false, status: res.status, error: String(errMsg), detail: parsed };
    }
  } catch (err) {
    console.error("[sandbox.runSandboxJob] network/exception:", err);
    return { success: false, error: String(err), detail: null };
  }
}

/**
 * fetchJobHistory({ page, per_page, preview_chars, user_id, since, succeeded, job_name })
 * Returns { success: true, ... } or { success: false, error: "...", status?: N }
 */
export async function fetchJobHistory({
  page = 1,
  per_page = 10,
  preview_chars = 200,
  user_id = undefined,
  since = undefined,
  succeeded = undefined,
  job_name = undefined,
} = {}) {
  try {
    const url = new URL(`${API_BASE}/api/sandbox/job_history`);
    url.searchParams.append("page", page);
    url.searchParams.append("per_page", per_page);
    url.searchParams.append("preview_chars", preview_chars);
    if (user_id !== undefined && user_id !== null) url.searchParams.append("user_id", user_id);
    if (since) url.searchParams.append("since", since);
    if (typeof succeeded !== "undefined" && succeeded !== null) url.searchParams.append("succeeded", succeeded);
    if (job_name) url.searchParams.append("job_name", job_name);

    console.debug("[sandbox.fetchJobHistory] GET ->", url.toString());

    const res = await fetch(url.toString(), {
      method: "GET",
      headers: buildHeaders({ Accept: "application/json" }),
    });

    const parsed = await safeParseResponse(res);
    console.debug("[sandbox.fetchJobHistory] status:", res.status, "parsed:", parsed);

    if (!res.ok) {
      const txt = parsed || `Status ${res.status}`;
      return { success: false, status: res.status, error: String(txt), detail: parsed };
    }

    return { success: true, ...parsed };
  } catch (err) {
    console.error("[sandbox.fetchJobHistory] error:", err);
    return { success: false, error: String(err) };
  }
}

/**
 * fetchFullJobLog(id) -> returns { success: true, ... } or { success: false, error: "..." }
 */
export async function fetchFullJobLog(id) {
  if (!id) return { success: false, error: "id required" };
  try {
    const url = `${API_BASE}/api/sandbox/job_log/${id}`;
    console.debug("[sandbox.fetchFullJobLog] GET ->", url);
    const res = await fetch(url, {
      method: "GET",
      headers: buildHeaders({ Accept: "application/json" }),
    });
    const parsed = await safeParseResponse(res);
    if (!res.ok) {
      return { success: false, status: res.status, error: parsed || `Status ${res.status}` };
    }
    return { success: true, ...parsed };
  } catch (err) {
    console.error("[sandbox.fetchFullJobLog] error:", err);
    return { success: false, error: String(err) };
  }
}

/**
 * downloadJobLog(id) -> returns { success: true, blob } or { success: false, error }
 */
export async function downloadJobLog(id) {
  if (!id) return { success: false, error: "id required" };
  try {
    const url = `${API_BASE}/api/sandbox/job_log/${id}/download`;
    console.debug("[sandbox.downloadJobLog] GET ->", url);
    const res = await fetch(url, {
      method: "GET",
      headers: buildHeaders({ Accept: "text/plain" }),
    });

    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      console.warn("[sandbox.downloadJobLog] failed:", res.status, txt);
      return { success: false, status: res.status, error: txt || `Status ${res.status}` };
    }

    const blob = await res.blob();
    return { success: true, blob };
  } catch (err) {
    console.error("[sandbox.downloadJobLog] error:", err);
    return { success: false, error: String(err) };
  }
}
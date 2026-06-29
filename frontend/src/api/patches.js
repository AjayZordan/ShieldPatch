// frontend/src/api/patches.js
// Robust patch API helper: avoid double "/api" when REACT_APP_API_BASE may already include "/api"

const RAW_API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:5000";

/** Normalize base so we can safely append /api/whatever without duplicating /api */
function normalizeBase(raw) {
  if (!raw || typeof raw !== "string") return "http://localhost:5000";
  let v = raw.trim();
  v = v.replace(/\/+$/, ""); // drop trailing slashes
  // if the base already ends with '/api', remove it so we can add '/api/...' exactly once
  if (v.toLowerCase().endsWith("/api")) {
    v = v.slice(0, -4).replace(/\/+$/, "");
  }
  return v;
}

const API_ROOT = normalizeBase(RAW_API_BASE); // e.g. "http://localhost:5000"
const API_PREFIX = `${API_ROOT}/api`; // safe single /api prefix

export async function recommendPatch(query, host_os) {
  const params = new URLSearchParams();
  if (query) params.append("query", query);
  if (host_os) params.append("host_os", host_os);

  const url = `${API_PREFIX}/patches/recommend?${params.toString()}`;

  const res = await fetch(url, {
    method: "GET",
    headers: { Accept: "application/json" },
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`API Error ${res.status}: ${txt}`);
  }
  return res.json();
}

// Re-export sandbox helpers from canonical sandbox module if you want to call them from here
export { runSandboxJob, fetchJobHistory, fetchFullJobLog, downloadJobLog } from "./sandbox";
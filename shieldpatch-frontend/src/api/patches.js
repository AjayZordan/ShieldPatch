// src/api/patches.js
// Keep patch recommendation logic here, but delegate sandbox helpers to the canonical sandbox module.

const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:5000"; // root

export async function recommendPatch(query, host_os) {
  const params = new URLSearchParams();
  if (query) params.append("query", query);
  if (host_os) params.append("host_os", host_os);
  const res = await fetch(`${API_BASE}/patches/recommend?${params.toString()}`, {
    method: "GET",
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`API Error ${res.status}: ${txt}`);
  }
  return res.json();
}

// Re-export sandbox helpers from the single source-of-truth module.
// This avoids duplicate implementations and base-URL inconsistencies.
export { runSandboxJob, fetchJobHistory, fetchFullJobLog, downloadJobLog } from "./sandbox";
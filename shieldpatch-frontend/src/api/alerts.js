const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:5000";

export async function fetchAlerts() {
  const res = await fetch(`${API_BASE}/alerts`);
  if (!res.ok) throw new Error("Failed to fetch alerts");
  return res.json();
}
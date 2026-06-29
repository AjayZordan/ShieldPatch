// src/api/threats.js
import axios from "axios";

const API_BASE = process.env.REACT_APP_API_BASE || "http://127.0.0.1:5000/api";

/**
 * Existing function you had — kept intact.
 */
export async function fetchThreats(limit = 20) {
  try {
    const res = await axios.get(`${API_BASE}/threats/?limit=${limit}`, {
      headers: { "Content-Type": "application/json" },
      timeout: 10000,
    });
    return res.data;
  } catch (err) {
    console.error("Error fetching threats:", err);
    throw err;
  }
}

/**
 * Fetch summary used by dashboard (/vulnlookup/summary)
 * Returns null on failure (non-fatal for UI).
 */
export async function fetchVulnSummary() {
  try {
    const res = await axios.get(`${API_BASE}/vulnlookup/summary`, {
      headers: { "Content-Type": "application/json" },
      timeout: 10000,
    });
    return res.data;
  } catch (err) {
    console.error("Error fetching vuln summary:", err);
    return null;
  }
}

/**
 * Generic list fetch for vulnerabilities.
 * Accepts an object of query params, e.g. { limit: 50, offset: 0, q: 'apache' }
 * Returns the backend JSON as-is.
 */
export async function fetchVulns(params = {}) {
  try {
    const qs = new URLSearchParams(params).toString();
    const url = qs ? `${API_BASE}/vulnlookup/?${qs}` : `${API_BASE}/vulnlookup/`;
    const res = await axios.get(url, {
      headers: { "Content-Type": "application/json" },
      timeout: 15000,
    });
    return res.data;
  } catch (err) {
    console.error("Error fetching vulns:", err);
    throw err;
  }
}

/**
 * Backwards-compatible alias: some files import fetchCves — keep them working.
 */
export const fetchCves = fetchVulns;

/**
 * Convenience: fetch a single CVE detail by CVE id (calls ?cve=XXXX).
 * Example: fetchVulnByCve('CVE-2025-13567')
 */
export async function fetchVulnByCve(cveId) {
  if (!cveId) throw new Error("cveId required");
  try {
    const res = await axios.get(
      `${API_BASE}/vulnlookup/?cve=${encodeURIComponent(cveId)}`,
      { headers: { "Content-Type": "application/json" }, timeout: 10000 }
    );
    return res.data;
  } catch (err) {
    console.error("Error fetching vuln by CVE:", err);
    throw err;
  }
}
import React, { useEffect, useState, useCallback } from "react";
import { fetchAlerts } from "../api/alerts";
import "./alerts.css";

export default function AlertsPanel({ setHasAlerts }) {
  const [alerts, setAlerts] = useState([]);

  const removeDuplicates = (alertsList) => {
  const seen = new Set();

  return alertsList.filter(a => {
    const key = a.message;

    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

  const filterPatchedAlerts = (alertsList) => {
  const patched = JSON.parse(localStorage.getItem("patched_cves") || "[]");

  return alertsList.filter(a => {
  const msg = (a.message || "").toLowerCase();

  // ❌ remove "patch applied" alerts completely
  if (msg.includes("patch applied successfully")) return false;

  // ❌ remove patched CVEs
  return !patched.some(cve => msg.includes(cve.toLowerCase()));
});
};

  const loadAlerts = useCallback(async () => {
  try {
    const data = await fetchAlerts();

    const alertsData = data.alerts || [];

    let filtered = filterPatchedAlerts(alertsData);

    // ✅ remove duplicates
    filtered = removeDuplicates(filtered);

    setAlerts(filtered);

    if (setHasAlerts) {
      setHasAlerts(filtered.length > 0);
    }

  } catch (err) {
    console.error(err);
  }
}, [setHasAlerts]);

  useEffect(() => {
    loadAlerts();
    const interval = setInterval(loadAlerts, 5000);
    return () => clearInterval(interval);
  }, [loadAlerts]); // ✅ FIXED

  return (
    <div className="alerts-panel">
      <h3>🚨 Alerts</h3>

      {alerts.length === 0 ? (
        <p>No alerts</p>
      ) : (
        alerts.map((a) => (
          <div key={a.id} className={`alert-item ${a.severity}`}>
            <p>{a.message}</p>
            <span>{new Date(a.created_at).toLocaleString()}</span>
          </div>
        ))
      )}

    </div>
  );
}
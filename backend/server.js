const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// 🧩 Mock vulnerability data
let vulnerabilities = [
  {
    id: 1,
    software: "Google Chrome",
    cve: "CVE-2024-5532",
    severity: "Critical",
    description: "Heap buffer overflow in V8 JavaScript engine.",
    patchAvailable: true,
  },
  {
    id: 2,
    software: "Adobe Reader",
    cve: "CVE-2023-2019",
    severity: "High",
    description: "Privilege escalation via malformed PDF file.",
    patchAvailable: false,
  },
  {
    id: 3,
    software: "Windows 10",
    cve: "CVE-2023-4567",
    severity: "Medium",
    description: "SMB protocol leak allowing limited data exposure.",
    patchAvailable: true,
  },
  {
    id: 4,
    software: "Zoom",
    cve: "CVE-2023-7755",
    severity: "Low",
    description: "Information disclosure in user metadata.",
    patchAvailable: false,
  },
];

// 🎯 Function to assign a risk score (1–100)
const calculateRiskScore = (severity) => {
  const map = {
    Critical: 95,
    High: 80,
    Medium: 60,
    Low: 30,
  };
  return map[severity] || 50;
};

// 🎨 Function to assign color codes (for frontend)
const getSeverityColor = (severity) => {
  const colors = {
    Critical: "#ff3b3b",
    High: "#ff8c00",
    Medium: "#ffc107",
    Low: "#4caf50",
  };
  return colors[severity] || "#ccc";
};

// 🧠 API endpoint to simulate scan
app.get("/api/scan", (req, res) => {
  console.log("🔍 Running vulnerability scan with risk scoring...");
  const enriched = vulnerabilities.map((v) => ({
    ...v,
    riskScore: calculateRiskScore(v.severity),
    color: getSeverityColor(v.severity),
  }));

  res.json({
    success: true,
    timestamp: new Date(),
    results: enriched,
  });
});

// 🧰 API to patch (fix) a vulnerability by ID
app.post("/api/patch/:id", (req, res) => {
  const id = parseInt(req.params.id);
  const index = vulnerabilities.findIndex((v) => v.id === id);

  if (index === -1) {
    return res.status(404).json({ success: false, message: "Vulnerability not found" });
  }

  vulnerabilities[index].patchAvailable = false;
  vulnerabilities[index].severity = "Patched";
  console.log(`🩹 Vulnerability ${id} marked as patched`);

  res.json({ success: true, message: "Vulnerability patched successfully", updated: vulnerabilities[index] });
});

// Root endpoint
app.get("/", (req, res) => {
  res.send("✅ ShieldPatch backend running with risk scoring and patch system!");
});

// Start server
const PORT = 5001;
app.listen(PORT, () => console.log(`🚀 ShieldPatch Scanner active at http://localhost:${PORT}`));
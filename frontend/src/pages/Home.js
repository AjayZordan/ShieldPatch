import React, { useState } from "react";
import Chatbot from "../components/chatbot";
import vulnImg from "../assets/Vulnerability Detection.png";
import patchImg from "../assets/Patch Automation.webp";
import mlImg from "../assets/ML Risk Prediction.webp";
import webImg from "../assets/Web Application Security.png";
import dashImg from "../assets/Dashboard Insights.webp";

export default function Home() {
  const [selectedFeature, setSelectedFeature] = useState(null);

  const features = [
    {
      title: "Vulnerability Detection",
      description:
        "Identify security weaknesses in your applications and systems before attackers do.",
      details:
        "Our vulnerability detection system uses advanced scanning and pattern analysis to uncover potential exploits and weaknesses in your infrastructure. It supports continuous monitoring, prioritization of risks, and real-time alerts to keep your systems resilient.",
      img: vulnImg,
    },
    {
      title: "Patch Automation",
      description:
        "Automated patching with rollback support to keep your systems always secure.",
      details:
        "Patch automation ensures your systems remain up-to-date without manual intervention. With rollback capabilities and test-safe deployment, we minimize downtime and eliminate vulnerabilities caused by outdated software.",
      img: patchImg,
    },
    {
      title: "ML Risk Prediction",
      description:
        "Machine learning powered risk scoring and exploit prediction for smarter defense.",
      details:
        "Our ML model learns from thousands of threat patterns, predicting potential breaches before they occur. It assigns a dynamic risk score and recommends proactive defense measures.",
      img: mlImg,
    },
    {
      title: "Web Application Security",
      description:
        "Secure your web apps against SQL injection, XSS, and other modern threats.",
      details:
        "We analyze and defend your web applications using OWASP Top 10 principles, intrusion detection, and runtime anomaly protection, ensuring strong web security posture.",
      img: webImg,
    },
    {
      title: "Dashboard Insights",
      description:
        "Visualize security trends and patching status with a modern, interactive dashboard.",
      details:
        "The ShieldPatch dashboard offers visual insights into vulnerabilities, patching trends, and attack surfaces, helping you make data-driven security decisions.",
      img: dashImg,
    },
  ];

  return (
    <div
      style={{
        background: "var(--bg)",
        color: "var(--text)",
        minHeight: "100vh",
        flex: 1,
      }}
    >
      <main style={{ padding: "60px 30px" }}>
        <h1
          style={{
            textAlign: "center",
            marginBottom: "60px",
            fontSize: "40px",
            textShadow: "0px 0px 15px var(--accent)",
            color: "var(--text)",
          }}
        >
          Welcome to <span style={{ color: "var(--accent)" }}>ShieldPatch</span>{" "}
          🛡️
        </h1>

        {features.map((f, index) => (
          <section
            key={index}
            onClick={() => setSelectedFeature(f)}
            style={{
              display: "flex",
              flexDirection: index % 2 === 0 ? "row" : "row-reverse",
              alignItems: "center",
              marginBottom: "60px",
              background: "var(--surface)",
              padding: "25px",
              borderRadius: "14px",
              boxShadow: "var(--card-shadow)",
              transition: "all 0.3s",
              cursor: "pointer",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = "scale(1.03)";
              // subtle stronger shadow on hover
              e.currentTarget.style.boxShadow = "0px 10px 30px rgba(0,0,0,0.35)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = "scale(1)";
              e.currentTarget.style.boxShadow = "var(--card-shadow)";
            }}
          >
            <img
              src={f.img}
              alt={f.title}
              style={{
                width: "320px",
                height: "210px",
                borderRadius: "12px",
                objectFit: "cover",
                border: "2px solid var(--panel)",
              }}
            />
            <div style={{ flex: 1, padding: "20px" }}>
              <h2
                style={{
                  marginBottom: "12px",
                  fontSize: "26px",
                  color: "var(--accent)",
                }}
              >
                {f.title}
              </h2>
              <p
                style={{
                  fontSize: "16px",
                  lineHeight: "1.6",
                  color: "var(--muted)",
                }}
              >
                {f.description}
              </p>
            </div>
          </section>
        ))}
      </main>

      <Chatbot />

      {/* Modal Popup */}
      {selectedFeature && (
        <div
          onClick={() => setSelectedFeature(null)}
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100vw",
            height: "100vh",
            background: "rgba(0, 0, 0, 0.7)",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            zIndex: 1000,
            backdropFilter: "blur(5px)",
          }}
        >
          <div
            onClick={(e) => e.stopPropagation()}
            style={{
              background: "var(--surface)",
              color: "var(--text)",
              padding: "30px",
              borderRadius: "14px",
              maxWidth: "600px",
              textAlign: "center",
              boxShadow: "0px 0px 25px rgba(0,0,0,0.35)",
              animation: "fadeIn 0.3s ease",
            }}
          >
            <h2 style={{ color: "var(--accent)" }}>{selectedFeature.title}</h2>
            <img
              src={selectedFeature.img}
              alt={selectedFeature.title}
              style={{
                width: "100%",
                height: "220px",
                borderRadius: "10px",
                objectFit: "cover",
                margin: "15px 0",
                border: "1px solid var(--panel)",
              }}
            />
            <p style={{ fontSize: "16px", lineHeight: "1.6", color: "var(--muted)" }}>
              {selectedFeature.details}
            </p>
            <button
              onClick={() => setSelectedFeature(null)}
              style={{
                marginTop: "20px",
                background: "var(--accent)",
                border: "none",
                padding: "10px 20px",
                borderRadius: "8px",
                color: "var(--text)",
                fontWeight: "700",
                cursor: "pointer",
              }}
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
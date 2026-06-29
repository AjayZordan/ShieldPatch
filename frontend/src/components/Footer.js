// src/components/Footer.js
import React from "react";
import { useLocation } from "react-router-dom";

export default function Footer() {
  const location = useLocation();
  const fixedPages = ["/login", "/register"]; // only these pages have fixed footer
  const isFixed = fixedPages.includes(location.pathname);

  return (
    <footer
      style={{
        background: "var(--surface, #1e1e2f)",
        color: "var(--text, white)",
        textAlign: "center",
        padding: "15px",
        position: isFixed ? "fixed" : "relative",
        bottom: isFixed ? 0 : "auto",
        width: "100%",
        marginTop: isFixed ? 0 : "auto",
      }}
    >
      <p>© {new Date().getFullYear()} ShieldPatch. All rights reserved.</p>
      
    </footer>
  );
}
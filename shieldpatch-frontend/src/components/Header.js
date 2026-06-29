import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import logo from "../assets/logo.png";

export default function Header() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [theme, setTheme] = useState("dark");

  // Apply theme CSS to <html>
  const applyTheme = (t) => {
    document.documentElement.setAttribute("data-theme", t);
  };

  // Load saved theme
  useEffect(() => {
    const saved = localStorage.getItem("theme");
    const initial = saved === "light" ? "light" : "dark";
    setTheme(initial);
    applyTheme(initial);
  }, []);

  const toggleTheme = () => {
    const next = theme === "light" ? "dark" : "light";
    setTheme(next);
    localStorage.setItem("theme", next);
    applyTheme(next);
  };

  return (
    <header
      style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "10px 30px",
        background: "var(--surface)",
        color: "var(--text)",
        position: "sticky",
        top: 0,
        zIndex: 1000,
        boxShadow: "0px 2px 8px rgba(0,0,0,0.3)",
      }}
    >
      {/* Logo */}
      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <img
          src={logo}
          alt="ShieldPatch Logo"
          style={{ width: "80px", objectFit: "contain" }}
        />
      </div>

      {/* Center Title */}
      <div style={{ textAlign: "center" }}>
        <Link to="/" style={{ textDecoration: "none", color: "var(--text)" }}>
          <h1 style={{ margin: 0, fontSize: "24px", fontWeight: "bold" }}>
            ShieldPatch
          </h1>
        </Link>
        <p
          style={{
            margin: 0,
            fontSize: "14px",
            fontStyle: "italic",
            color: "var(--muted)",
          }}
        >
          Predict • Protect • Prevail
        </p>
      </div>

      {/* Right Side Menu */}
      <div style={{ position: "relative" }}>
        <button
          onClick={() => setMenuOpen(!menuOpen)}
          style={{
            fontSize: "28px",
            background: "transparent",
            border: "none",
            color: "var(--text)",
            cursor: "pointer",
          }}
        >
          ☰
        </button>

        {menuOpen && (
          <div
            style={{
              position: "absolute",
              right: 0,
              top: "50px",
              background: "var(--surface)",
              color: "var(--text)",
              borderRadius: "8px",
              padding: "10px",
              boxShadow: "0px 4px 6px rgba(0,0,0,0.3)",
              minWidth: "180px",
            }}
          >
            <Link
              to="/login"
              style={{ display: "block", padding: "8px", color: "var(--text)", textDecoration: "none" }}
              onClick={() => setMenuOpen(false)}
            >
              Login
            </Link>

            <Link
              to="/register"
              style={{ display: "block", padding: "8px", color: "var(--text)", textDecoration: "none" }}
              onClick={() => setMenuOpen(false)}
            >
              Register
            </Link>

            <hr style={{ borderColor: "var(--panel)" }} />

            {/* THEME SWITCHER INSIDE MENU */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ fontSize: 13 }}>
                <strong>Theme</strong>
                <div style={{ color: "var(--muted)", fontSize: 12 }}>
                  {theme === "light" ? "Light mode" : "Dark mode"}
                </div>
              </div>

              <button
                onClick={toggleTheme}
                style={{
                  padding: "6px 10px",
                  borderRadius: 8,
                  border: "none",
                  cursor: "pointer",
                  background: theme === "light" ? "#eee" : "var(--accent)",
                  color: theme === "light" ? "#000" : "#fff",
                }}
              >
                {theme === "light" ? "🌞" : "🌙"}
              </button>
            </div>
          </div>
        )}
      </div>
    </header>
  );
}
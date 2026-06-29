import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";

export default function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [theme, setTheme] = useState("dark"); // "dark" or "light"

  // apply theme to document root
  const applyTheme = (t) => {
    try {
      document.documentElement.setAttribute("data-theme", t);
    } catch (e) {
      // silent fail for SSR or odd environments
    }
  };

  useEffect(() => {
    // load theme from localStorage if present
    const saved = (localStorage.getItem("theme") || "").toLowerCase();
    const initial = saved === "light" ? "light" : "dark";
    setTheme(initial);
    applyTheme(initial);
  }, []);

  const toggleTheme = () => {
    const next = theme === "light" ? "dark" : "light";
    setTheme(next);
    try {
      localStorage.setItem("theme", next);
    } catch (e) {}
    applyTheme(next);
  };

  // close menu when clicking a nav link
  const handleNavClick = () => setMenuOpen(false);

  /* ---------------------------
     iOS-style switch component
     - Accessible (role="switch", aria-checked)
     - Clickable and keyboard operable (Space/Enter)
     - Uses inline styles so you don't need extra CSS files
     --------------------------- */
  function IOSSwitch({ checked, onChange, size = 40 }) {
    const width = Math.round(size * 1.8);
    const height = size;
    const knobSize = Math.round(size * 0.86);
    const knobTranslate = width - knobSize - 4; // padding of 2px each side

    const outerStyle = {
      width: width,
      height: height,
      borderRadius: height / 2,
      background: checked ? "var(--accent, #00d4ff)" : "rgba(255,255,255,0.12)",
      display: "inline-flex",
      alignItems: "center",
      padding: 2,
      boxSizing: "border-box",
      cursor: "pointer",
      transition: "background 180ms ease",
      boxShadow: checked ? "0 4px 12px rgba(0,160,255,0.18)" : "inset 0 1px 0 rgba(255,255,255,0.02)",
      border: "1px solid rgba(0,0,0,0.12)",
    };

    const knobStyle = {
      width: knobSize,
      height: knobSize,
      borderRadius: "50%",
      background: checked ? "#fff" : "#fff",
      transform: `translateX(${checked ? knobTranslate : 0}px)`,
      transition: "transform 180ms cubic-bezier(.2,.8,.2,1)",
      boxShadow: "0 4px 10px rgba(2,6,23,0.35)",
      display: "inline-block",
    };

    const handleKey = (e) => {
      if (e.key === " " || e.key === "Enter") {
        e.preventDefault();
        onChange && onChange(!checked);
      }
    };

    return (
      <div
        role="switch"
        aria-checked={checked}
        tabIndex={0}
        onKeyDown={handleKey}
        onClick={() => onChange && onChange(!checked)}
        style={outerStyle}
        title={checked ? "Dark mode" : "Light mode"}
      >
        <span style={knobStyle} />
      </div>
    );
  }

  return (
    <nav
      style={{
        padding: "10px",
        background: "var(--surface, #222)",
        color: "var(--text, white)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <button
          onClick={() => setMenuOpen(!menuOpen)}
          aria-expanded={menuOpen}
          aria-label="Toggle menu"
          style={{
            fontSize: 18,
            background: "transparent",
            border: "none",
            color: "inherit",
            cursor: "pointer",
          }}
        >
          ☰
        </button>

        <Link to="/" style={{ color: "inherit", textDecoration: "none", fontWeight: 700 }}>
          ShieldPatch
        </Link>
      </div>

      {/* right-side small area (keeps header compact) */}
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        {/* iOS-style mini switch (quick access) */}
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 13, color: "var(--muted, #9fb3c8)" }}>Light</span>

          <IOSSwitch
            checked={theme === "dark"}
            onChange={() => {
              // Note: internal state uses "light"/"dark", IOSSwitch uses boolean (checked means dark)
              toggleTheme();
            }}
            size={20}
          />

          <span style={{ fontSize: 13, color: "var(--muted, #9fb3c8)" }}>Dark</span>
        </div>
      </div>

      {/* dropdown/menu */}
      {menuOpen && (
        <div
          style={{
            position: "absolute",
            top: 56,
            left: 12,
            background: "var(--surface, #222)",
            color: "var(--text, white)",
            borderRadius: 8,
            padding: 12,
            boxShadow: "0 6px 20px rgba(0,0,0,0.4)",
            zIndex: 9999,
            minWidth: 160,
            display: "flex",
            flexDirection: "column",
            gap: 10,
          }}
        >
          <Link
            to="/login"
            onClick={handleNavClick}
            style={{ color: "inherit", textDecoration: "none", padding: "6px 4px" }}
          >
            Login
          </Link>

          <Link
            to="/register"
            onClick={handleNavClick}
            style={{ color: "inherit", textDecoration: "none", padding: "6px 4px" }}
          >
            Register
          </Link>

          <div
            style={{
              height: 1,
              background: "rgba(255,255,255,0.04)",
              margin: "6px 0",
            }}
          />

          {/* Theme toggle inside the menu (matches your request to add in hamburger) */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", flexDirection: "column" }}>
              <span style={{ fontSize: 13, fontWeight: 600 }}>Theme</span>
              <small style={{ color: "var(--muted, #9fb3c8)" }}>{theme === "light" ? "Light mode" : "Dark mode"}</small>
            </div>

            {/* larger iOS-style switch inside menu */}
            <IOSSwitch
              checked={theme === "dark"}
              onChange={() => {
                toggleTheme();
                // keep menu open so user can see effect
              }}
              size={28}
            />
          </div>
        </div>
      )}
    </nav>
  );
}
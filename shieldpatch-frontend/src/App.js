// src/App.js
import React, { useState, useEffect, createContext } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from "react-router-dom";
import Header from "./components/Header";
import Footer from "./components/Footer";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Dashboard from "./pages/Dashboard";
import Chatbot from "./components/chatbot"; // adjust path if different
import ThreatCve from "./pages/threatcve"; // <-- ADDED: route for CVE listing page
import PredictRisk from "./pages/PredictRisk";

// Theme context exported so Navbar or any component can consume it
export const ThemeContext = createContext({
  theme: "dark",
  toggleTheme: () => {},
  setTheme: () => {},
});

// <<< ADDED: small auth wrapper to protect routes (keeps everything else intact) >>>
function RequireAuth({ children }) {
  const location = useLocation();
  const token = localStorage.getItem("token");
  if (!token) {
    // Redirect to login, preserve the location so you can redirect back after login if you want
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  return children;
}
// <<< end added >>>

function App() {
  // Theme state: 'dark' or 'light'
  const [theme, setTheme] = useState(() => {
    try {
      const stored = localStorage.getItem("theme");
      return stored === "light" ? "light" : "dark";
    } catch (e) {
      return "dark";
    }
  });

  // Apply theme to document root and persist
  useEffect(() => {
    try {
      document.documentElement.setAttribute("data-theme", theme);
      localStorage.setItem("theme", theme);
    } catch (e) {
      // ignore (some environments may not permit)
    }
  }, [theme]);

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"));

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme, setTheme }}>
      <Router>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            minHeight: "100vh",
            position: "relative",
          }}
        >
          {/* Common Header */}
          <Header />

          {/* Page content */}
          <div style={{ flex: 1 }}>
            <Routes>
              <Route path="/" element={<Home />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/threatcve/:cve" element={<ThreatCve />} />
              <Route path="/predict-risk" element={<PredictRisk />} />
              {/* Protected dashboard route */}
              <Route
                path="/dashboard"
                element={
                  <RequireAuth>
                    <Dashboard />
                  </RequireAuth>
                }
              />

              {/* Protected CVE listing route (new) */}
              <Route
                path="/cve-list"
                element={
                  <RequireAuth>
                    <ThreatCve />
                  </RequireAuth>
                }
              />
            </Routes>
          </div>

          {/* Common Footer */}
          <Footer />

          {/* 🟢 Floating Chatbot (always visible) */}
          <div
            style={{
              position: "fixed",
              bottom: "30px",
              right: "30px",
              zIndex: 9999,
            }}
          >
            <Chatbot />
          </div>
        </div>
      </Router>
    </ThemeContext.Provider>
  );
}

export default App;
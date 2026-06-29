import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

function Login() {
  const navigate = useNavigate();
  const [usernameOrEmail, setUsernameOrEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  // backend base (adjust via REACT_APP_API_BASE if set)
  const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:5000/api";

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const payload = {
        email: usernameOrEmail,
        password,
      };

      const resp = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await resp.json();

      if (!resp.ok) {
        const msg = data?.message || "Login failed";
        setError(msg);
        setLoading(false);
        return;
      }

      if (data.token) {
        localStorage.setItem("token", data.token);
        if (data.user) localStorage.setItem("user", JSON.stringify(data.user));
        navigate("/dashboard");
      } else {
        setError("Login succeeded but token missing from response.");
      }
    } catch (err) {
      setError("Network or server error. Please try again.");
      console.error("Login error:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        background: "var(--bg)",
        color: "var(--text)",
        height: "100vh",
        display: "flex",
        flexDirection: "column",
        justifyContent: "center",
        alignItems: "center",
      }}
    >
      <h2
        style={{
          marginBottom: "20px",
          fontSize: "32px",
          color: "var(--accent)",
          textShadow: "0 0 10px var(--accent)",
        }}
      >
        Login to ShieldPatch
      </h2>

      <form
        onSubmit={handleSubmit}
        style={{
          background: "var(--surface)",
          padding: "40px",
          borderRadius: "15px",
          boxShadow: "var(--card-shadow)",
          width: "300px",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
        }}
      >
        <input
          value={usernameOrEmail}
          onChange={(e) => setUsernameOrEmail(e.target.value)}
          type="text"
          placeholder="Email"
          style={{
            width: "100%",
            padding: "10px",
            marginBottom: "15px",
            borderRadius: "8px",
            border: `1px solid rgba(255,255,255,0.04)`,
            background: "var(--panel)",
            color: "var(--text)",
            outline: "none",
            fontSize: "16px",
          }}
        />
        <input
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          type="password"
          placeholder="Password"
          style={{
            width: "100%",
            padding: "10px",
            marginBottom: "20px",
            borderRadius: "8px",
            border: `1px solid rgba(255,255,255,0.04)`,
            background: "var(--panel)",
            color: "var(--text)",
            outline: "none",
            fontSize: "16px",
          }}
        />

        {error && (
          <div
            style={{
              width: "100%",
              marginBottom: "10px",
              color: "var(--danger)",
              fontSize: "14px",
              textAlign: "left",
            }}
          >
            {error}
          </div>
        )}

        <button
          disabled={loading}
          type="submit"
          style={{
            width: "100%",
            padding: "10px",
            background: "linear-gradient(90deg, var(--accent), #2196f3)",
            border: "none",
            borderRadius: "8px",
            color: "var(--text)",
            fontSize: "16px",
            cursor: loading ? "not-allowed" : "pointer",
            transition: "transform 0.3s, box-shadow 0.3s",
            opacity: loading ? 0.8 : 1,
          }}
          onMouseEnter={(e) => {
            if (!loading) {
              e.currentTarget.style.transform = "scale(1.05)";
              e.currentTarget.style.boxShadow = `0 0 15px ${getComputedStyle(document.documentElement).getPropertyValue('--accent') || '#00bcd4'}`;
            }
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = "scale(1)";
            e.currentTarget.style.boxShadow = "none";
          }}
        >
          {loading ? "Logging in..." : "Login"}
        </button>
      </form>

      <p style={{ marginTop: "20px", color: "var(--muted)" }}>
        Don’t have an account?{" "}
        <Link
          to="/register"
          style={{
            color: "var(--accent)",
            textDecoration: "none",
            fontWeight: "bold",
          }}
        >
          Register
        </Link>
      </p>

      <p style={{ marginTop: "15px" }}>
        <Link
          to="/"
          style={{
            color: "var(--muted)",
            textDecoration: "none",
            fontSize: "14px",
          }}
        >
          ← Back to Home
        </Link>
      </p>
    </div>
  );
}

export default Login;
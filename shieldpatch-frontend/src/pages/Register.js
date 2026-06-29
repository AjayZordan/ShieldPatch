import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

function Register() {
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:5000/api";

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const payload = { username, email, password };

      const resp = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await resp.json();

      if (!resp.ok) {
        setError(data?.message || "Registration failed");
        setLoading(false);
        return;
      }

      localStorage.setItem("token", data.token);
      if (data.user) localStorage.setItem("user", JSON.stringify(data.user));

      navigate("/dashboard");
    } catch (err) {
      console.error(err);
      setError("Network or server error. Please try again.");
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
        justifyContent: "center",
        alignItems: "center",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          background: "var(--surface)",
          border: `1px solid rgba(255,255,255,0.04)`,
          borderRadius: "16px",
          padding: "40px",
          width: "350px",
          textAlign: "center",
          boxShadow: "var(--card-shadow)",
          backdropFilter: "blur(10px)",
        }}
      >
        <h2 style={{ marginBottom: "20px", color: "var(--accent)" }}>Register</h2>

        <form onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            style={{
              width: "100%",
              padding: "10px",
              margin: "10px 0",
              borderRadius: "8px",
              border: "none",
              background: "var(--panel)",
              color: "var(--text)",
            }}
          />
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            style={{
              width: "100%",
              padding: "10px",
              margin: "10px 0",
              borderRadius: "8px",
              border: "none",
              background: "var(--panel)",
              color: "var(--text)",
            }}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={{
              width: "100%",
              padding: "10px",
              margin: "10px 0",
              borderRadius: "8px",
              border: "none",
              background: "var(--panel)",
              color: "var(--text)",
            }}
          />

          {error && (
            <div
              style={{
                color: "var(--danger)",
                marginTop: "5px",
                fontSize: "14px",
                textAlign: "left",
              }}
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              width: "100%",
              padding: "10px",
              background: "linear-gradient(90deg, #007bff, var(--accent))",
              border: "none",
              borderRadius: "8px",
              color: "var(--text)",
              fontWeight: "bold",
              cursor: loading ? "not-allowed" : "pointer",
              marginTop: "10px",
              transition: "all 0.3s",
              opacity: loading ? 0.7 : 1,
            }}
            onMouseEnter={(e) =>
              (e.currentTarget.style.boxShadow =
                "0 0 15px rgba(0,212,255,0.5)")
            }
            onMouseLeave={(e) => (e.currentTarget.style.boxShadow = "none")}
          >
            {loading ? "Registering..." : "Register"}
          </button>
        </form>

        <p style={{ marginTop: "15px", color: "var(--muted)" }}>
          Already have an account?{" "}
          <Link to="/login" style={{ color: "var(--accent)" }}>
            Login
          </Link>
        </p>
      </div>
    </div>
  );
}

export default Register;
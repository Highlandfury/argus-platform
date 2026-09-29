"use client";

import { useState } from "react";

interface Problem {
  detail?: string;
  code?: string;
}

export default function LoginPage() {
  const [orgSlug, setOrgSlug] = useState("dev");
  const [email, setEmail] = useState("admin@dev.local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ org_slug: orgSlug, email, password }),
      });
      if (res.ok) {
        window.location.href = "/";
        return;
      }
      let detail = "Login failed";
      try {
        const problem = (await res.json()) as Problem;
        if (problem.detail) detail = problem.detail;
      } catch {
        /* non-JSON error body */
      }
      setError(detail);
      setBusy(false);
    } catch {
      setError("Network error — is the API reachable?");
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <div className="panel auth-card">
        <h1 style={{ marginTop: 0 }}>Argus</h1>
        <p className="muted">Sign in to the network observability platform.</p>
        <form onSubmit={onSubmit}>
          <label htmlFor="org_slug">Organization</label>
          <input
            id="org_slug"
            data-testid="login-org"
            value={orgSlug}
            onChange={(e) => setOrgSlug(e.target.value)}
            autoComplete="organization"
          />
          <label htmlFor="email">Email</label>
          <input
            id="email"
            data-testid="login-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="username"
          />
          <label htmlFor="password">Password</label>
          <input
            id="password"
            data-testid="login-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
          <button type="submit" disabled={busy} data-testid="login-submit">
            {busy ? "Signing in…" : "Sign in"}
          </button>
          {error ? (
            <p className="error" data-testid="login-error">
              {error}
            </p>
          ) : null}
        </form>
      </div>
    </div>
  );
}

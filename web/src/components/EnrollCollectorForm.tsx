"use client";

import { useState } from "react";

import { readCSRF } from "@/lib/api";

interface Site {
  id: string;
  name: string;
}

// EnrollCollectorForm mints a one-time, site-bound enrollment credential. The
// raw token is shown exactly once (the API stores only its SHA-256).
export default function EnrollCollectorForm({ sites }: { sites: Site[] }) {
  const [siteID, setSiteID] = useState(sites[0]?.id ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setToken(null);
    setBusy(true);
    try {
      const res = await fetch("/api/v1/enrollments", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
          "Idempotency-Key": crypto.randomUUID(),
        },
        body: JSON.stringify({ site_id: siteID, ttl_seconds: 86400 }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        setError(body?.detail ?? `enrollment failed (status ${res.status})`);
        return;
      }
      const body = (await res.json()) as { token: string; expires_at: string };
      setToken(body.token);
      setExpiresAt(body.expires_at);
    } catch {
      setError("network error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel">
      <h2 style={{ marginTop: 0 }}>Create enrollment</h2>
      <p className="muted">
        One-time credential for a new collector. It is shown once, binds to the
        selected site, and expires after 24 hours.
      </p>
      {sites.length === 0 ? (
        <p className="muted">No sites available to bind an enrollment.</p>
      ) : (
        <form onSubmit={submit}>
          <label htmlFor="enroll-site">Site</label>
          <select
            id="enroll-site"
            value={siteID}
            onChange={(e) => setSiteID(e.target.value)}
            data-testid="enroll-site"
          >
            {sites.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
          <button
            type="submit"
            disabled={busy}
            data-testid="enroll-submit"
            className="btn-sm"
          >
            {busy ? "Creating…" : "Create token"}
          </button>
        </form>
      )}
      {error && (
        <p className="error" data-testid="enroll-error">
          {error}
        </p>
      )}
      {token && (
        <div>
          <p className="muted" style={{ marginBottom: 4 }}>
            Enrollment token (shown once; expires{" "}
            {new Date(expiresAt).toLocaleString()}). Provide it to the collector
            as <code>ARGUS_ENROLL_TOKEN</code>:
          </p>
          <code className="token" data-testid="enrollment-token">
            {token}
          </code>
        </div>
      )}
    </div>
  );
}

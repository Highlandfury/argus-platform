"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { readCSRF } from "@/lib/api";

// RotateCredential replaces a credential's secret. The new secret is submitted
// once and never rendered back; the previous envelope is replaced atomically
// server-side.
export default function RotateCredential({
  credentialID,
  name,
}: {
  credentialID: string;
  name: string;
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [secret, setSecret] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function rotate(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setMessage("");
    setBusy(true);
    try {
      const res = await fetch(`/api/v1/credentials/${credentialID}/rotate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify({ secret }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        setError(body?.detail ?? `rotate failed (status ${res.status})`);
        return;
      }
      setMessage("Rotated. The new secret is stored write-only and is not shown.");
      setOpen(false);
      router.refresh();
    } catch {
      setError("network error");
    } finally {
      setSecret("");
      setBusy(false);
    }
  }

  return (
    <div>
      {!open ? (
        <button
          type="button"
          className="btn-sm btn-ghost"
          onClick={() => {
            setOpen(true);
            setMessage("");
            setError("");
          }}
          data-testid={`credential-rotate-open-${name}`}
        >
          Rotate
        </button>
      ) : (
        <form onSubmit={rotate} data-testid={`credential-rotate-form-${name}`}>
          <input
            type="password"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="new secret"
            autoComplete="new-password"
            data-testid={`credential-rotate-secret-${name}`}
          />
          <div className="btn-row">
            <button
              type="submit"
              className="btn-sm"
              disabled={busy || secret === ""}
              data-testid={`credential-rotate-submit-${name}`}
            >
              {busy ? "Rotating…" : "Rotate"}
            </button>
            <button
              type="button"
              className="btn-sm btn-ghost"
              onClick={() => {
                setOpen(false);
                setSecret("");
              }}
              data-testid={`credential-rotate-cancel-${name}`}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
      {message && (
        <p className="muted" data-testid={`credential-rotate-result-${name}`}>
          {message}
        </p>
      )}
      {error && (
        <p className="error" data-testid={`credential-rotate-error-${name}`}>
          {error}
        </p>
      )}
    </div>
  );
}

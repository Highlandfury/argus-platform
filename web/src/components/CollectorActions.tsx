"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { readCSRF } from "@/lib/api";

// CollectorActions exposes the admin control-plane actions on a collector
// detail page: policy resync (pushes a new signed policy to the live stream)
// and revocation (terminal; the server disconnects the collector).
export default function CollectorActions({
  collectorID,
  status,
}: {
  collectorID: string;
  status: string;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function call(path: string, label: string) {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const res = await fetch(`/api/v1/collectors/${collectorID}${path}`, {
        method: "POST",
        headers: { "X-CSRF-Token": readCSRF() },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        setError(body?.detail ?? `${label} failed (status ${res.status})`);
        return;
      }
      if (path.endsWith("/policy:resync")) {
        const body = (await res.json()) as { policy_version: number };
        setMessage(`Policy v${body.policy_version} issued.`);
      } else {
        setMessage("Collector revoked.");
      }
      router.refresh();
    } catch {
      setError("network error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="btn-row">
        <button
          className="btn-sm btn-ghost"
          disabled={busy || status === "revoked"}
          onClick={() => call("/policy:resync", "resync")}
          data-testid="collector-resync"
        >
          Resync policy
        </button>
        <button
          className="btn-sm btn-danger"
          disabled={busy || status === "revoked"}
          onClick={() => {
            if (window.confirm("Revoke this collector? This is terminal.")) {
              void call("/revoke", "revoke");
            }
          }}
          data-testid="collector-revoke"
        >
          Revoke
        </button>
      </div>
      {message && <p className="muted" data-testid="collector-action-result">{message}</p>}
      {error && (
        <p className="error" data-testid="collector-action-error">
          {error}
        </p>
      )}
    </div>
  );
}

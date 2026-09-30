"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { readCSRF } from "@/lib/api";

// CreateCredentialForm submits a secret exactly once; the API seals it and
// returns metadata only. The secret is cleared from component state as soon as
// the request completes and is never rendered back.
export default function CreateCredentialForm() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [kind, setKind] = useState("snmp_v2c");
  const [secret, setSecret] = useState("");
  const [metadata, setMetadata] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setMessage("");
    let parsedMetadata: unknown = undefined;
    if (metadata.trim() !== "") {
      try {
        parsedMetadata = JSON.parse(metadata);
      } catch {
        setError("metadata must be valid JSON (an object)");
        return;
      }
      if (
        typeof parsedMetadata !== "object" ||
        parsedMetadata === null ||
        Array.isArray(parsedMetadata)
      ) {
        setError("metadata must be a JSON object");
        return;
      }
    }
    setBusy(true);
    try {
      const res = await fetch("/api/v1/credentials", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify({
          name,
          kind,
          secret,
          ...(parsedMetadata !== undefined ? { metadata: parsedMetadata } : {}),
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        setError(body?.detail ?? `create failed (status ${res.status})`);
        return;
      }
      const body = (await res.json()) as { name: string };
      setMessage(
        `Credential ${body.name} created. The secret was stored write-only and is not shown.`,
      );
      setName("");
      setSecret("");
      setMetadata("");
      router.refresh();
    } catch {
      setError("network error");
    } finally {
      setSecret("");
      setBusy(false);
    }
  }

  return (
    <div className="panel">
      <h2 style={{ marginTop: 0 }}>Create credential</h2>
      <p className="muted">
        The secret is submitted once, sealed with envelope encryption, and can
        never be read back — not by any role, including admins.
      </p>
      <form onSubmit={submit}>
        <label htmlFor="credential-name">Name</label>
        <input
          id="credential-name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          data-testid="credential-name"
          maxLength={200}
        />
        <label htmlFor="credential-kind">Kind</label>
        <select
          id="credential-kind"
          value={kind}
          onChange={(e) => setKind(e.target.value)}
          data-testid="credential-kind"
        >
          <option value="snmp_v2c">snmp_v2c</option>
          <option value="snmp_v3">snmp_v3</option>
          <option value="ssh_paramiko">ssh_paramiko</option>
        </select>
        <label htmlFor="credential-secret">Secret (write-only)</label>
        <input
          id="credential-secret"
          type="password"
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          data-testid="credential-secret"
          autoComplete="new-password"
        />
        <label htmlFor="credential-metadata">
          Metadata (JSON object, optional)
        </label>
        <input
          id="credential-metadata"
          value={metadata}
          onChange={(e) => setMetadata(e.target.value)}
          data-testid="credential-metadata"
          placeholder='{"username":"ops"}'
        />
        <button
          type="submit"
          disabled={busy}
          data-testid="credential-submit"
          className="btn-sm"
        >
          {busy ? "Creating…" : "Create credential"}
        </button>
      </form>
      {message && (
        <p className="muted" data-testid="credential-create-result">
          {message}
        </p>
      )}
      {error && (
        <p className="error" data-testid="credential-create-error">
          {error}
        </p>
      )}
    </div>
  );
}

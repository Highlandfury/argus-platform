"use client";

import { useState } from "react";

import { readCSRF } from "@/lib/api";

// Canonical device taxonomy (docs/05 FR-INV-001); the API stores kind as a
// free text key until the Phase 3 device_types taxonomy lands, so the form
// constrains manual adds to the canonical set.
const DEVICE_KINDS = [
  "router",
  "switch",
  "firewall",
  "ap",
  "server",
  "printer",
  "camera",
  "nvr",
  "ups",
  "phone",
  "pos",
  "iot",
  "workstation",
  "unknown",
];

interface Site {
  id: string;
  name: string;
}

interface ProblemFieldError {
  field?: string;
  code?: string;
  message?: string;
}

// AddDeviceForm performs the manual device add (M7-S3 POST /v1/devices) with
// the session + CSRF pair. Server-side validation is the source of truth:
// problem+json field errors are rendered per field, and a 403 is surfaced as
// the forbidden state instead of a generic failure.
export default function AddDeviceForm({
  sites,
  onCreated,
}: {
  sites: Site[];
  onCreated?: () => void;
}) {
  const [name, setName] = useState("");
  const [siteID, setSiteID] = useState(sites[0]?.id ?? "");
  const [kind, setKind] = useState("switch");
  const [mgmtIP, setMgmtIP] = useState("");
  const [serial, setSerial] = useState("");
  const [sysObjectID, setSysObjectID] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState<ProblemFieldError[]>([]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setMessage("");
    setFieldErrors([]);
    setBusy(true);
    try {
      const body: Record<string, string> = {
        site_id: siteID,
        name: name.trim(),
        kind,
      };
      if (mgmtIP.trim() !== "") body.mgmt_ip = mgmtIP.trim();
      if (serial.trim() !== "") body.serial = serial.trim();
      if (sysObjectID.trim() !== "") body.sys_object_id = sysObjectID.trim();
      const res = await fetch("/api/v1/devices", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const problem = (await res.json().catch(() => null)) as {
          detail?: string;
          errors?: ProblemFieldError[];
        } | null;
        setFieldErrors(Array.isArray(problem?.errors) ? problem.errors : []);
        setError(problem?.detail ?? `add failed (status ${res.status})`);
        return;
      }
      const created = (await res.json()) as { name?: string };
      setMessage(`Device ${created.name ?? name.trim()} added.`);
      setName("");
      setMgmtIP("");
      setSerial("");
      setSysObjectID("");
      onCreated?.();
    } catch {
      setError("network error");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel">
      <h2 style={{ marginTop: 0 }}>Add device</h2>
      <p className="muted">
        Registers a device manually in the selected site. Manual devices feed
        ICMP/SNMP polling and are matched by serial, sysObjectID, and
        management IP.
      </p>
      {sites.length === 0 ? (
        <p className="muted" data-testid="device-create-no-sites">
          No sites available to add a device to.
        </p>
      ) : (
        <form onSubmit={submit}>
          <label htmlFor="device-name">Name</label>
          <input
            id="device-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            data-testid="device-name"
            maxLength={200}
            required
          />
          <label htmlFor="device-site">Site</label>
          <select
            id="device-site"
            value={siteID}
            onChange={(e) => setSiteID(e.target.value)}
            data-testid="device-site"
          >
            {sites.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
          <label htmlFor="device-kind">Kind</label>
          <select
            id="device-kind"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
            data-testid="device-kind"
          >
            {DEVICE_KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
          <label htmlFor="device-mgmt-ip">Management IP (optional)</label>
          <input
            id="device-mgmt-ip"
            value={mgmtIP}
            onChange={(e) => setMgmtIP(e.target.value)}
            data-testid="device-mgmt-ip"
            placeholder="10.0.0.1"
          />
          <label htmlFor="device-serial">Serial (optional)</label>
          <input
            id="device-serial"
            value={serial}
            onChange={(e) => setSerial(e.target.value)}
            data-testid="device-serial"
          />
          <label htmlFor="device-sys-object-id">sysObjectID (optional)</label>
          <input
            id="device-sys-object-id"
            value={sysObjectID}
            onChange={(e) => setSysObjectID(e.target.value)}
            data-testid="device-sys-object-id"
            placeholder="1.3.6.1.4.1.9"
          />
          <button
            type="submit"
            disabled={busy}
            data-testid="device-submit"
            className="btn-sm"
          >
            {busy ? "Adding…" : "Add device"}
          </button>
        </form>
      )}
      {message && (
        <p className="muted" data-testid="device-create-result">
          {message}
        </p>
      )}
      {error && (
        <p className="error" data-testid="device-create-error">
          {error}
        </p>
      )}
      {fieldErrors.length > 0 && (
        <ul className="error" data-testid="device-create-field-errors">
          {fieldErrors.map((fe, i) => (
            <li key={`${fe.field ?? "field"}-${i}`}>
              {fe.field ? `${fe.field}: ` : ""}
              {fe.message ?? "invalid value"}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

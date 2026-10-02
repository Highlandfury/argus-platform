"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { problemDetail, readCSRF } from "@/lib/api";

import type { Device } from "./DeviceDetail";

// Canonical device taxonomy (docs/05 FR-INV-001); the API stores kind as free
// text, so the form constrains edits to the same canonical set the add form
// uses. A device whose current kind is not in the set keeps its value via the
// extra option below.
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

interface ProblemFieldError {
  field?: string;
  code?: string;
  message?: string;
}

// DeviceAdminPanel is the M10-S3a device edit/delete surface. Edit PATCHes
// /v1/devices/{id} (session + CSRF; problem+json field errors rendered per
// field, 403 surfaced verbatim). Delete is a two-step confirm and soft-deletes
// through DELETE /v1/devices/{id}; on success the caller navigates back to the
// inventory list, which no longer shows the device.
export default function DeviceAdminPanel({
  device,
  canWrite,
  onUpdated,
}: {
  device: Device;
  canWrite: boolean;
  onUpdated?: (updated: Device) => void;
}) {
  const router = useRouter();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(device.name);
  const [kind, setKind] = useState(device.kind);
  const [mgmtIP, setMgmtIP] = useState(device.mgmt_ip ?? "");
  const [serial, setSerial] = useState(device.serial ?? "");
  const [sysObjectID, setSysObjectID] = useState(device.sys_object_id ?? "");
  const [critical, setCritical] = useState(device.critical);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState<ProblemFieldError[]>([]);
  const [confirming, setConfirming] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  // Keep the form in sync with refreshed server data (a successful save also
  // runs router.refresh(); the form is closed by then).
  useEffect(() => {
    setName(device.name);
    setKind(device.kind);
    setMgmtIP(device.mgmt_ip ?? "");
    setSerial(device.serial ?? "");
    setSysObjectID(device.sys_object_id ?? "");
    setCritical(device.critical);
  }, [device]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setMessage("");
    setFieldErrors([]);
    setBusy(true);
    try {
      // Nullable fields are sent explicitly (empty input -> null) so clearing
      // a management IP/serial/sysObjectID is possible; omitted fields would
      // be unchanged (PATCH semantics).
      const body = {
        name: name.trim(),
        kind,
        critical,
        mgmt_ip: mgmtIP.trim() === "" ? null : mgmtIP.trim(),
        serial: serial.trim() === "" ? null : serial.trim(),
        sys_object_id:
          sysObjectID.trim() === "" ? null : sysObjectID.trim(),
      };
      const res = await fetch(`/api/v1/devices/${device.id}`, {
        method: "PATCH",
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
        setError(problem?.detail ?? `update failed (status ${res.status})`);
        return;
      }
      const updated = (await res.json()) as Device;
      setMessage("Device updated.");
      setEditing(false);
      onUpdated?.(updated);
      router.refresh();
    } catch {
      setError("network error");
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setDeleteError("");
    setDeleteBusy(true);
    try {
      const res = await fetch(`/api/v1/devices/${device.id}`, {
        method: "DELETE",
        headers: { "X-CSRF-Token": readCSRF() },
      });
      if (!res.ok) {
        setDeleteError(
          await problemDetail(res, `delete failed (status ${res.status})`),
        );
        return;
      }
      router.push("/devices");
      router.refresh();
    } catch {
      setDeleteError("network error");
    } finally {
      setDeleteBusy(false);
    }
  }

  if (!canWrite) {
    return (
      <p className="muted" data-testid="device-admin-readonly">
        Editing and deleting devices requires the admin role (
        <code>device.write</code>).
      </p>
    );
  }

  return (
    <div data-testid="device-admin-panel">
      {message && (
        <p className="muted" data-testid="device-edit-result">
          {message}
        </p>
      )}
      {!editing ? (
        <div className="btn-row">
          <button
            type="button"
            className="btn-sm btn-ghost"
            data-testid="device-edit-open"
            onClick={() => {
              setEditing(true);
              setMessage("");
              setError("");
              setFieldErrors([]);
            }}
          >
            Edit device
          </button>
          {!confirming ? (
            <button
              type="button"
              className="btn-sm btn-danger"
              data-testid="device-delete-open"
              onClick={() => {
                setConfirming(true);
                setDeleteError("");
              }}
            >
              Delete device
            </button>
          ) : (
            <span
              className="btn-row"
              data-testid="device-delete-confirm-step"
              style={{ alignItems: "center" }}
            >
              <span className="muted">
                Soft-delete this device and hide it from inventory?
              </span>
              <button
                type="button"
                className="btn-sm btn-danger"
                data-testid="device-delete-confirm"
                disabled={deleteBusy}
                onClick={() => void remove()}
              >
                {deleteBusy ? "Deleting…" : "Confirm delete"}
              </button>
              <button
                type="button"
                className="btn-sm btn-ghost"
                data-testid="device-delete-cancel"
                onClick={() => setConfirming(false)}
              >
                Cancel
              </button>
            </span>
          )}
        </div>
      ) : (
        <form onSubmit={submit} data-testid="device-edit-form">
          <label htmlFor="device-edit-name">Name</label>
          <input
            id="device-edit-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            data-testid="device-edit-name"
            maxLength={200}
            required
          />
          <label htmlFor="device-edit-kind">Kind</label>
          <select
            id="device-edit-kind"
            value={kind}
            onChange={(e) => setKind(e.target.value)}
            data-testid="device-edit-kind"
          >
            {!DEVICE_KINDS.includes(kind) && (
              <option value={kind}>{kind}</option>
            )}
            {DEVICE_KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
          <label htmlFor="device-edit-mgmt-ip">
            Management IP (blank clears)
          </label>
          <input
            id="device-edit-mgmt-ip"
            value={mgmtIP}
            onChange={(e) => setMgmtIP(e.target.value)}
            data-testid="device-edit-mgmt-ip"
            placeholder="10.0.0.1"
          />
          <label htmlFor="device-edit-serial">Serial (blank clears)</label>
          <input
            id="device-edit-serial"
            value={serial}
            onChange={(e) => setSerial(e.target.value)}
            data-testid="device-edit-serial"
          />
          <label htmlFor="device-edit-sys-object-id">
            sysObjectID (blank clears)
          </label>
          <input
            id="device-edit-sys-object-id"
            value={sysObjectID}
            onChange={(e) => setSysObjectID(e.target.value)}
            data-testid="device-edit-sys-object-id"
            placeholder="1.3.6.1.4.1.9"
          />
          <label
            htmlFor="device-edit-critical"
            style={{ display: "flex", alignItems: "center", gap: 8 }}
          >
            <input
              id="device-edit-critical"
              type="checkbox"
              checked={critical}
              onChange={(e) => setCritical(e.target.checked)}
              data-testid="device-edit-critical"
              style={{ width: "auto" }}
            />
            Critical device (faster failure backoff)
          </label>
          <div className="btn-row">
            <button
              type="submit"
              className="btn-sm"
              disabled={busy}
              data-testid="device-edit-submit"
            >
              {busy ? "Saving…" : "Save changes"}
            </button>
            <button
              type="button"
              className="btn-sm btn-ghost"
              disabled={busy}
              data-testid="device-edit-cancel"
              onClick={() => {
                setEditing(false);
                setError("");
                setFieldErrors([]);
              }}
            >
              Cancel
            </button>
          </div>
          {error && (
            <p className="error" data-testid="device-edit-error">
              {error}
            </p>
          )}
          {fieldErrors.length > 0 && (
            <ul className="error" data-testid="device-edit-field-errors">
              {fieldErrors.map((fe, i) => (
                <li key={`${fe.field ?? "field"}-${i}`}>
                  {fe.field ? `${fe.field}: ` : ""}
                  {fe.message ?? "invalid value"}
                </li>
              ))}
            </ul>
          )}
        </form>
      )}
      {deleteError && (
        <p className="error" data-testid="device-delete-error">
          {deleteError}
        </p>
      )}
    </div>
  );
}

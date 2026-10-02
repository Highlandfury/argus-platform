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

// Server-allowed identity types (device_identity_history CHECK + the create
// endpoint's identities[] validation). Identity windows are recorded in
// device_identity_history; serial/sysObjectID/mgmt IP are additionally stored
// on the device row by the same request.
const IDENTITY_TYPES = [
  "serial",
  "chassis_id",
  "sys_object_id",
  "mac",
  "hostname",
  "mgmt_ip",
];

interface IdentityRow {
  type: string;
  value: string;
}

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
  const [identities, setIdentities] = useState<IdentityRow[]>([]);
  const [critical, setCritical] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState<ProblemFieldError[]>([]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setMessage("");
    setFieldErrors([]);
    // Client validation: every identity row must carry a value before the
    // request is sent (the server still validates type/value formats and
    // returns indexed problem field errors when a value is invalid).
    for (let i = 0; i < identities.length; i += 1) {
      if (identities[i].value.trim() === "") {
        setError(`identity row ${i + 1} (${identities[i].type}) needs a value`);
        return;
      }
    }
    setBusy(true);
    try {
      const body: Record<string, unknown> = {
        site_id: siteID,
        name: name.trim(),
        kind,
        critical,
      };
      if (mgmtIP.trim() !== "") body.mgmt_ip = mgmtIP.trim();
      if (serial.trim() !== "") body.serial = serial.trim();
      if (sysObjectID.trim() !== "") body.sys_object_id = sysObjectID.trim();
      if (identities.length > 0) {
        body.identities = identities.map((row) => ({
          type: row.type,
          value: row.value.trim(),
        }));
      }
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
      setIdentities([]);
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
          <fieldset
            data-testid="device-identities"
            style={{ marginTop: 8, border: "1px solid #2a2f3a", padding: 8 }}
          >
            <legend>Identity attributes (optional)</legend>
            <p className="muted" style={{ marginTop: 0 }}>
              Extra identity windows recorded at add time (source=manual), e.g.
              MAC, hostname or chassis ID. The server also records
              serial/sysObjectID/management IP from their fields above; identity
              values are unique across live devices in the organization.
            </p>
            {identities.map((row, i) => (
              <div
                key={i}
                className="btn-row"
                style={{ alignItems: "center", gap: 8, marginBottom: 8 }}
              >
                <select
                  aria-label={`Identity ${i + 1} type`}
                  value={row.type}
                  onChange={(e) =>
                    setIdentities((rows) =>
                      rows.map((current, idx) =>
                        idx === i ? { ...current, type: e.target.value } : current,
                      ),
                    )
                  }
                  data-testid={`device-identity-type-${i}`}
                  style={{ width: "auto" }}
                >
                  {IDENTITY_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
                <input
                  aria-label={`Identity ${i + 1} value`}
                  value={row.value}
                  onChange={(e) =>
                    setIdentities((rows) =>
                      rows.map((current, idx) =>
                        idx === i ? { ...current, value: e.target.value } : current,
                      ),
                    )
                  }
                  placeholder={row.type === "mac" ? "aa:bb:cc:dd:ee:ff" : "value"}
                  data-testid={`device-identity-value-${i}`}
                  style={{ width: "auto" }}
                />
                <button
                  type="button"
                  className="btn-sm btn-ghost"
                  data-testid={`device-identity-remove-${i}`}
                  onClick={() =>
                    setIdentities((rows) => rows.filter((_, idx) => idx !== i))
                  }
                >
                  Remove
                </button>
              </div>
            ))}
            <button
              type="button"
              className="btn-sm btn-ghost"
              data-testid="device-identity-add"
              onClick={() =>
                setIdentities((rows) => [...rows, { type: "mac", value: "" }])
              }
            >
              Add identity
            </button>
          </fieldset>
          <label
            htmlFor="device-critical"
            style={{ display: "flex", alignItems: "center", gap: 8 }}
          >
            <input
              id="device-critical"
              type="checkbox"
              checked={critical}
              onChange={(e) => setCritical(e.target.checked)}
              data-testid="device-critical"
              style={{ width: "auto" }}
            />
            Critical device (faster failure backoff)
          </label>
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

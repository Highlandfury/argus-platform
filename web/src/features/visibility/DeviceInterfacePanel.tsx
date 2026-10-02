"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { fetchJSON, problemDetail, readCSRF } from "@/lib/api";

import StatusChip from "./StatusChip";
import { formatSpeedBps, shortTime } from "./format";

// Interface inventory + admin CRUD for the device detail page (M10-S3b-2).
// Reads GET /v1/devices/{id}/interfaces; admin mutations post
// POST /v1/devices/{id}/interfaces, PATCH /v1/interfaces/{id} and
// DELETE /v1/interfaces/{id} (session + CSRF, problem+json rendered per field).
// The editable surface mirrors the server allowlist in interfacePatchFields:
// if_name, if_alias, role, monitored, speed_bps, mtu, mac (if_index is the
// immutable SNMP identity key). Poll-derived columns (if_type, admin/oper
// status, description) stay server-owned and are not editable here.
export interface InterfaceRow {
  id: string;
  if_index: number;
  if_name: string;
  if_alias: string | null;
  admin_status: string | null;
  oper_status: string | null;
  speed_bps: number | null;
  mtu: number | null;
  mac: string | null;
  role: string;
  monitored: boolean;
  last_seen_at: string | null;
  status: "up" | "down" | "unknown";
}

interface ProblemFieldError {
  field?: string;
  code?: string;
  message?: string;
}

interface MatrixSeries {
  metric_key: string;
  dimensions: Record<string, string>;
  points: [number, number | null][];
}

const INTERFACE_ROLES = ["uplink", "access", "trunk", "unused", "unknown"];

// Same windows the device-detail range buttons drive for the utilization
// lookup (the panel follows the page range rather than owning a second one).
const RANGE_WINDOW_MS: Record<string, number> = {
  "1h": 60 * 60_000,
  "6h": 6 * 60 * 60_000,
  "24h": 24 * 60 * 60_000,
  "7d": 7 * 24 * 60 * 60_000,
};

export default function DeviceInterfacePanel({
  deviceID,
  canWrite,
  rangeKey,
  refreshKey = 0,
}: {
  deviceID: string;
  canWrite: boolean;
  rangeKey: string;
  refreshKey?: number;
}) {
  const [interfaces, setInterfaces] = useState<InterfaceRow[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [utilization, setUtilization] = useState<Map<string, number> | null>(
    null,
  );

  // Single form drives both modes; `editingID` distinguishes create (null)
  // from edit (row id). Values start from the row for edits so omitted
  // numbers keep their current value (PATCH semantics).
  const [formOpen, setFormOpen] = useState(false);
  const [editingID, setEditingID] = useState<string | null>(null);
  const [fIndex, setFIndex] = useState("1");
  const [fName, setFName] = useState("");
  const [fAlias, setFAlias] = useState("");
  const [fRole, setFRole] = useState("unknown");
  const [fMonitored, setFMonitored] = useState(true);
  const [fSpeed, setFSpeed] = useState("");
  const [fMtu, setFMtu] = useState("");
  const [fMac, setFMac] = useState("");
  const [formBusy, setFormBusy] = useState(false);
  const [formError, setFormError] = useState("");
  const [formMessage, setFormMessage] = useState("");
  const [fieldErrors, setFieldErrors] = useState<ProblemFieldError[]>([]);
  const [confirmDeleteID, setConfirmDeleteID] = useState<string | null>(null);
  const [deleteBusyID, setDeleteBusyID] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState("");

  const load = useCallback(async () => {
    const res = await fetchJSON<{ data?: InterfaceRow[] }>(
      `/api/v1/devices/${deviceID}/interfaces?limit=100`,
    );
    if (res.ok) {
      setInterfaces(res.data.data ?? []);
      setLoadError("");
    } else {
      setLoadError(res.error);
    }
  }, [deviceID]);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  // Bounded utilization lookup: one query for all interface rate series of
  // this device (selector without a dimension matches every port); the chart
  // range buttons at the page level select the window.
  useEffect(() => {
    if (!interfaces || interfaces.length === 0) return;
    let cancelled = false;
    async function loadUtilization() {
      const windowMs = RANGE_WINDOW_MS[rangeKey] ?? RANGE_WINDOW_MS["6h"];
      const to = new Date();
      const from = new Date(to.getTime() - windowMs);
      const res = await fetchJSON<{ series: MatrixSeries[] }>(
        "/api/v1/metrics/query",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            series: [
              { device_id: deviceID, metric_key: "net.if.in_octets" },
              { device_id: deviceID, metric_key: "net.if.out_octets" },
            ],
            from: from.toISOString(),
            to: to.toISOString(),
            step: "auto",
            agg: "avg",
            fill: "null",
          }),
        },
      );
      if (cancelled) return;
      if (!res.ok) return; // the table keeps the honest "—" fallback
      const latest = new Map<string, { t: number; v: number }>();
      for (const s of res.data.series) {
        const ifName = s.dimensions["if_name"];
        if (!ifName) continue;
        const last = [...s.points].reverse().find(([, v]) => v !== null);
        if (last && last[1] !== null) {
          const prev = latest.get(ifName);
          if (prev === undefined || last[0] > prev.t) {
            latest.set(ifName, { t: last[0], v: last[1] });
          }
        }
      }
      setUtilization(
        new Map(Array.from(latest, ([name, point]) => [name, point.v])),
      );
    }
    void loadUtilization();
    return () => {
      cancelled = true;
    };
  }, [interfaces, rangeKey, deviceID]);

  function utilizationPct(row: InterfaceRow): number | null {
    const value = utilization?.get(row.if_name);
    if (value === undefined) return null;
    // in_octets is bytes/s; the link capacity is bits/s.
    if (!row.speed_bps || row.speed_bps <= 0) return null;
    return Math.round(((value * 8) / row.speed_bps) * 1000) / 10;
  }

  function openCreate() {
    const next =
      interfaces && interfaces.length > 0
        ? Math.max(...interfaces.map((i) => i.if_index)) + 1
        : 1;
    setEditingID(null);
    setFIndex(String(next));
    setFName("");
    setFAlias("");
    setFRole("unknown");
    setFMonitored(true);
    setFSpeed("");
    setFMtu("");
    setFMac("");
    setFormError("");
    setFieldErrors([]);
    setFormOpen(true);
  }

  function openEdit(row: InterfaceRow) {
    setEditingID(row.id);
    setFIndex(String(row.if_index));
    setFName(row.if_name);
    setFAlias(row.if_alias ?? "");
    setFRole(row.role);
    setFMonitored(row.monitored);
    setFSpeed(row.speed_bps === null ? "" : String(row.speed_bps));
    setFMtu(row.mtu === null ? "" : String(row.mtu));
    setFMac(row.mac ?? "");
    setFormError("");
    setFieldErrors([]);
    setFormOpen(true);
  }

  function closeForm() {
    setFormOpen(false);
    setEditingID(null);
    setFormError("");
    setFieldErrors([]);
  }

  function nonNegativeInt(value: string, label: string): number | null {
    const n = Number(value);
    if (!Number.isInteger(n) || n < 0) {
      setFormError(`${label} must be a non-negative integer`);
      return null;
    }
    return n;
  }

  async function submitForm(e: React.FormEvent) {
    e.preventDefault();
    setFormError("");
    setFormMessage("");
    setFieldErrors([]);
    if (fName.trim() === "") {
      setFormError("if_name is required");
      return;
    }
    let ifIndex = 0;
    if (editingID === null) {
      ifIndex = Number(fIndex);
      if (!Number.isInteger(ifIndex) || ifIndex < 1) {
        setFormError("if_index must be a positive integer");
        return;
      }
    }
    let speed: number | null = null;
    if (fSpeed.trim() !== "") {
      speed = nonNegativeInt(fSpeed, "speed_bps");
      if (speed === null) return;
    }
    let mtu: number | null = null;
    if (fMtu.trim() !== "") {
      mtu = nonNegativeInt(fMtu, "mtu");
      if (mtu === null) return;
    }
    const body: Record<string, unknown> = {
      if_name: fName.trim(),
      if_alias: fAlias.trim() === "" ? null : fAlias.trim(),
      role: fRole,
      monitored: fMonitored,
      mac: fMac.trim() === "" ? null : fMac.trim(),
    };
    if (speed !== null) body.speed_bps = speed;
    if (mtu !== null) body.mtu = mtu;
    if (editingID === null) body.if_index = ifIndex;

    setFormBusy(true);
    try {
      const res = await fetch(
        editingID === null
          ? `/api/v1/devices/${deviceID}/interfaces`
          : `/api/v1/interfaces/${editingID}`,
        {
          method: editingID === null ? "POST" : "PATCH",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": readCSRF(),
          },
          body: JSON.stringify(body),
        },
      );
      if (!res.ok) {
        const problem = (await res.json().catch(() => null)) as {
          detail?: string;
          errors?: ProblemFieldError[];
        } | null;
        setFieldErrors(Array.isArray(problem?.errors) ? problem.errors : []);
        setFormError(
          problem?.detail ??
            `${editingID === null ? "add" : "update"} failed (status ${res.status})`,
        );
        return;
      }
      const saved = (await res.json()) as InterfaceRow;
      setFormMessage(
        editingID === null
          ? `Interface ${saved.if_name} added.`
          : `Interface ${saved.if_name} updated.`,
      );
      closeForm();
      await load();
    } catch {
      setFormError("network error");
    } finally {
      setFormBusy(false);
    }
  }

  async function remove(row: InterfaceRow) {
    setDeleteError("");
    setFormMessage("");
    setDeleteBusyID(row.id);
    try {
      const res = await fetch(`/api/v1/interfaces/${row.id}`, {
        method: "DELETE",
        headers: { "X-CSRF-Token": readCSRF() },
      });
      if (!res.ok) {
        setDeleteError(
          await problemDetail(res, `delete failed (status ${res.status})`),
        );
        return;
      }
      setFormMessage(`Interface ${row.if_name} deleted.`);
      setConfirmDeleteID(null);
      await load();
    } catch {
      setDeleteError("network error");
    } finally {
      setDeleteBusyID(null);
    }
  }

  return (
    <section className="panel" data-testid="device-interfaces-panel">
      <h2 style={{ marginTop: 0 }}>Interfaces</h2>
      {loadError && (
        <p className="error" data-testid="device-interfaces-error">
          {loadError}
        </p>
      )}
      {!loadError && interfaces === null && (
        <p className="muted">Loading interfaces…</p>
      )}
      {!loadError && interfaces?.length === 0 && (
        <p className="muted" data-testid="device-interfaces-empty">
          No interfaces discovered yet. SNMP polls auto-create interface rows;
          admins can also add one manually below.
        </p>
      )}
      {!loadError && interfaces && interfaces.length > 0 && (
        <table data-testid="device-interfaces-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Status</th>
              <th>Alias</th>
              <th>Speed</th>
              <th>Utilization (in)</th>
              <th>MAC</th>
              <th>Last seen</th>
              {canWrite && <th />}
            </tr>
          </thead>
          <tbody>
            {interfaces.map((row) => {
              const pct = utilizationPct(row);
              return (
                <tr key={row.id}>
                  <td>
                    <Link href={`/interfaces/${row.id}`}>{row.if_name}</Link>
                  </td>
                  <td>
                    <StatusChip status={row.status} />
                  </td>
                  <td className="muted">{row.if_alias ?? "—"}</td>
                  <td className="muted">{formatSpeedBps(row.speed_bps)}</td>
                  <td>
                    {pct === null ? (
                      <span
                        className="muted"
                        data-testid={`if-util-${row.if_name}`}
                        title="No rate samples in this range"
                      >
                        —
                      </span>
                    ) : (
                      <span className="util" data-testid={`if-util-${row.if_name}`}>
                        <span
                          className="util-bar"
                          style={{ width: `${Math.min(100, pct)}%` }}
                        />
                        <span className="util-text">{pct}%</span>
                      </span>
                    )}
                  </td>
                  <td className="muted">{row.mac ?? "—"}</td>
                  <td className="muted">{shortTime(row.last_seen_at)}</td>
                  {canWrite && (
                    <td>
                      {confirmDeleteID === row.id ? (
                        <span
                          className="btn-row"
                          style={{ alignItems: "center", gap: 6 }}
                          data-testid={`device-interface-delete-confirm-step-${row.if_name}`}
                        >
                          <button
                            type="button"
                            className="btn-sm btn-danger"
                            data-testid={`device-interface-delete-confirm-${row.if_name}`}
                            disabled={deleteBusyID === row.id}
                            onClick={() => void remove(row)}
                          >
                            {deleteBusyID === row.id
                              ? "Deleting…"
                              : "Confirm delete"}
                          </button>
                          <button
                            type="button"
                            className="btn-sm btn-ghost"
                            data-testid={`device-interface-delete-cancel-${row.if_name}`}
                            onClick={() => setConfirmDeleteID(null)}
                          >
                            Cancel
                          </button>
                        </span>
                      ) : (
                        <span className="btn-row" style={{ gap: 6 }}>
                          <button
                            type="button"
                            className="btn-sm btn-ghost"
                            data-testid={`device-interface-edit-${row.if_name}`}
                            onClick={() => openEdit(row)}
                          >
                            Edit
                          </button>
                          <button
                            type="button"
                            className="btn-sm btn-ghost"
                            data-testid={`device-interface-delete-${row.if_name}`}
                            onClick={() => {
                              setConfirmDeleteID(row.id);
                              setDeleteError("");
                            }}
                          >
                            Delete
                          </button>
                        </span>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      )}

      {!loadError && interfaces !== null && canWrite && !formOpen && (
        <div className="btn-row">
          <button
            type="button"
            className="btn-sm btn-ghost"
            data-testid="device-interface-add-open"
            onClick={openCreate}
          >
            Add interface
          </button>
        </div>
      )}

      {!loadError && !canWrite && (
        <p className="muted" data-testid="device-interfaces-readonly">
          Adding, editing and deleting interfaces requires the admin role (
          <code>interface.write</code>).
        </p>
      )}

      {!loadError && canWrite && formOpen && (
        <form
          onSubmit={submitForm}
          data-testid="device-interface-form"
          style={{ marginTop: 12 }}
        >
          <h3 className="vis-subhead">
            {editingID === null ? "Add interface" : `Edit ${fName || "interface"}`}
          </h3>
          <p className="muted">
            ifIndex is the immutable SNMP identity key; editing an interface
            never changes it. MAC values are canonicalized server-side.
          </p>
          {editingID === null && (
            <>
              <label htmlFor="device-interface-if-index">ifIndex</label>
              <input
                id="device-interface-if-index"
                type="number"
                min={1}
                value={fIndex}
                onChange={(e) => setFIndex(e.target.value)}
                data-testid="device-interface-if-index"
                required
              />
            </>
          )}
          <label htmlFor="device-interface-if-name">Name</label>
          <input
            id="device-interface-if-name"
            value={fName}
            onChange={(e) => setFName(e.target.value)}
            placeholder="Gi1/0/1"
            data-testid="device-interface-if-name"
            maxLength={200}
            required
          />
          <label htmlFor="device-interface-if-alias">Alias (blank clears)</label>
          <input
            id="device-interface-if-alias"
            value={fAlias}
            onChange={(e) => setFAlias(e.target.value)}
            data-testid="device-interface-if-alias"
          />
          <label htmlFor="device-interface-role">Role</label>
          <select
            id="device-interface-role"
            value={fRole}
            onChange={(e) => setFRole(e.target.value)}
            data-testid="device-interface-role"
          >
            {INTERFACE_ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <label htmlFor="device-interface-speed">
            Speed (bits/s, blank leaves unchanged)
          </label>
          <input
            id="device-interface-speed"
            type="number"
            min={0}
            value={fSpeed}
            onChange={(e) => setFSpeed(e.target.value)}
            data-testid="device-interface-speed"
          />
          <label htmlFor="device-interface-mtu">
            MTU (blank leaves unchanged)
          </label>
          <input
            id="device-interface-mtu"
            type="number"
            min={0}
            value={fMtu}
            onChange={(e) => setFMtu(e.target.value)}
            data-testid="device-interface-mtu"
          />
          <label htmlFor="device-interface-mac">MAC (blank clears)</label>
          <input
            id="device-interface-mac"
            value={fMac}
            onChange={(e) => setFMac(e.target.value)}
            placeholder="aa:bb:cc:dd:ee:ff"
            data-testid="device-interface-mac"
          />
          <label
            htmlFor="device-interface-monitored"
            style={{ display: "flex", alignItems: "center", gap: 8 }}
          >
            <input
              id="device-interface-monitored"
              type="checkbox"
              checked={fMonitored}
              onChange={(e) => setFMonitored(e.target.checked)}
              data-testid="device-interface-monitored"
              style={{ width: "auto" }}
            />
            Monitored
          </label>
          <div className="btn-row">
            <button
              type="submit"
              className="btn-sm"
              disabled={formBusy}
              data-testid="device-interface-submit"
            >
              {formBusy
                ? "Saving…"
                : editingID === null
                  ? "Add interface"
                  : "Save changes"}
            </button>
            <button
              type="button"
              className="btn-sm btn-ghost"
              disabled={formBusy}
              data-testid="device-interface-cancel"
              onClick={closeForm}
            >
              Cancel
            </button>
          </div>
          {formError && (
            <p className="error" data-testid="device-interface-form-error">
              {formError}
            </p>
          )}
          {fieldErrors.length > 0 && (
            <ul className="error" data-testid="device-interface-field-errors">
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

      {formMessage && (
        <p className="muted" data-testid="device-interface-result">
          {formMessage}
        </p>
      )}
      {deleteError && (
        <p className="error" data-testid="device-interface-delete-error">
          {deleteError}
        </p>
      )}
    </section>
  );
}

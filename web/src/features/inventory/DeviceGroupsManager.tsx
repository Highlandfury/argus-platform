"use client";

import { useCallback, useEffect, useState } from "react";

import { fetchJSON, problemDetail, readCSRF } from "@/lib/api";

interface DeviceGroup {
  id: string;
  name: string;
  selector: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface ProblemFieldError {
  field?: string;
  code?: string;
  message?: string;
}

function shortTime(value: string): string {
  return value ? new Date(value).toLocaleString() : "—";
}

// Client-side mirror of the server's validJSONObject rule
// (internal/modules/inventory/http.go): the selector must be a JSON object.
// Arrays, scalars and null are rejected with a 400 field error server-side, so
// the form fails fast on the same rule. The grammar of the selector keys is
// deliberately unpinned (docs/11 §21, M7 deferral): the API stores and
// validates the object only.
function parseSelector(
  text: string,
): { ok: true; value: unknown } | { ok: false; message: string } {
  if (text.trim() === "") return { ok: true, value: {} };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {
      ok: false,
      message:
        'selector must be valid JSON — a JSON object such as {"kinds":["switch"]} (or {} for none)',
    };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {
      ok: false,
      message:
        "selector must be a JSON object — the API rejects arrays, scalars and null",
    };
  }
  return { ok: true, value: parsed };
}

// DeviceGroupsManager is the M10-S3b-2 /device-groups surface: list, create,
// edit and delete dynamic device groups through GET/POST/PATCH/DELETE
// /v1/device-groups (session + CSRF on mutations, problem+json details and
// field errors rendered verbatim). The selector is edited as raw JSON with
// client-side validation of the one rule the API enforces (JSON object).
// Membership resolution is a documented deferral: no engine evaluates the
// selector, so the page shows the stored rule and says so explicitly.
export default function DeviceGroupsManager({
  canWrite,
}: {
  canWrite: boolean;
}) {
  const [groups, setGroups] = useState<DeviceGroup[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [forbidden, setForbidden] = useState("");
  const [editingID, setEditingID] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [selectorText, setSelectorText] = useState("{}");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [fieldErrors, setFieldErrors] = useState<ProblemFieldError[]>([]);
  const [confirmDeleteID, setConfirmDeleteID] = useState<string | null>(null);
  const [deleteBusyID, setDeleteBusyID] = useState<string | null>(null);
  const [deleteError, setDeleteError] = useState("");

  const load = useCallback(async () => {
    const res = await fetchJSON<{ data?: DeviceGroup[] }>(
      "/api/v1/device-groups?limit=100",
    );
    if (res.ok) {
      setGroups(res.data.data ?? []);
      setLoadError("");
      setForbidden("");
      return;
    }
    if (res.status === 403) {
      setForbidden(res.error);
      setGroups(null);
      return;
    }
    setLoadError(res.error);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  function resetForm() {
    setEditingID(null);
    setName("");
    setSelectorText("{}");
    setError("");
    setFieldErrors([]);
  }

  function openEdit(group: DeviceGroup) {
    setEditingID(group.id);
    setName(group.name);
    setSelectorText(JSON.stringify(group.selector ?? {}, null, 2));
    setError("");
    setMessage("");
    setFieldErrors([]);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setMessage("");
    setFieldErrors([]);
    if (name.trim() === "") {
      setError("name is required");
      return;
    }
    const selector = parseSelector(selectorText);
    if (!selector.ok) {
      setError(selector.message);
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(
        editingID === null
          ? "/api/v1/device-groups"
          : `/api/v1/device-groups/${editingID}`,
        {
          method: editingID === null ? "POST" : "PATCH",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": readCSRF(),
          },
          body: JSON.stringify({ name: name.trim(), selector: selector.value }),
        },
      );
      if (!res.ok) {
        const problem = (await res.json().catch(() => null)) as {
          detail?: string;
          errors?: ProblemFieldError[];
        } | null;
        setFieldErrors(Array.isArray(problem?.errors) ? problem.errors : []);
        setError(
          problem?.detail ??
            `${editingID === null ? "create" : "update"} failed (status ${res.status})`,
        );
        return;
      }
      const saved = (await res.json()) as DeviceGroup;
      setMessage(
        editingID === null
          ? `Device group ${saved.name} created.`
          : `Device group ${saved.name} updated.`,
      );
      resetForm();
      await load();
    } catch {
      setError("network error");
    } finally {
      setBusy(false);
    }
  }

  async function remove(group: DeviceGroup) {
    setDeleteError("");
    setMessage("");
    setDeleteBusyID(group.id);
    try {
      const res = await fetch(`/api/v1/device-groups/${group.id}`, {
        method: "DELETE",
        headers: { "X-CSRF-Token": readCSRF() },
      });
      if (!res.ok) {
        setDeleteError(
          await problemDetail(res, `delete failed (status ${res.status})`),
        );
        return;
      }
      setMessage(`Device group ${group.name} deleted.`);
      setConfirmDeleteID(null);
      if (editingID === group.id) resetForm();
      await load();
    } catch {
      setDeleteError("network error");
    } finally {
      setDeleteBusyID(null);
    }
  }

  if (forbidden) {
    return (
      <section className="panel" data-testid="device-groups-manager">
        <p className="error" data-testid="device-groups-forbidden">
          {forbidden}
        </p>
      </section>
    );
  }

  return (
    <section data-testid="device-groups-manager">
      <div className="panel">
        <p className="muted" data-testid="device-groups-membership-note">
          <strong>Membership resolution is deferred.</strong> The API stores and
          validates each group&apos;s selector as a JSON object; no engine
          evaluates it yet (documented M7 deferral, docs/11 §21). Groups still
          work as credential binding scopes, but the selector does not
          currently expand to member devices.
        </p>
        {loadError && (
          <p className="error" data-testid="device-groups-error">
            {loadError}
          </p>
        )}
        {!loadError && groups === null && (
          <p className="muted" data-testid="device-groups-loading">
            Loading device groups…
          </p>
        )}
        {!loadError && groups?.length === 0 && (
          <p className="muted" data-testid="device-groups-empty">
            No device groups yet.
            {canWrite
              ? " Create one below; the selector is stored as JSON."
              : " An admin can create one."}
          </p>
        )}
        {!loadError && groups && groups.length > 0 && (
          <table data-testid="device-groups-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Selector</th>
                <th>Updated</th>
                {canWrite && <th />}
              </tr>
            </thead>
            <tbody>
              {groups.map((group) => (
                <tr key={group.id} data-testid={`device-groups-row-${group.name}`}>
                  <td>{group.name}</td>
                  <td className="muted">
                    <code data-testid={`device-groups-selector-${group.name}`}>
                      {JSON.stringify(group.selector ?? {})}
                    </code>
                  </td>
                  <td className="muted">{shortTime(group.updated_at)}</td>
                  {canWrite && (
                    <td>
                      {confirmDeleteID === group.id ? (
                        <span
                          className="btn-row"
                          style={{ alignItems: "center", gap: 6 }}
                          data-testid={`device-groups-delete-confirm-step-${group.name}`}
                        >
                          <button
                            type="button"
                            className="btn-sm btn-danger"
                            data-testid={`device-groups-delete-confirm-${group.name}`}
                            disabled={deleteBusyID === group.id}
                            onClick={() => void remove(group)}
                          >
                            {deleteBusyID === group.id
                              ? "Deleting…"
                              : "Confirm delete"}
                          </button>
                          <button
                            type="button"
                            className="btn-sm btn-ghost"
                            data-testid={`device-groups-delete-cancel-${group.name}`}
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
                            data-testid={`device-groups-edit-${group.name}`}
                            onClick={() => openEdit(group)}
                          >
                            Edit
                          </button>
                          <button
                            type="button"
                            className="btn-sm btn-ghost"
                            data-testid={`device-groups-delete-${group.name}`}
                            onClick={() => {
                              setConfirmDeleteID(group.id);
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
              ))}
            </tbody>
          </table>
        )}
      </div>

      {canWrite && (
        <div className="panel" style={{ marginTop: 16 }}>
          <h2 style={{ marginTop: 0 }}>
            {editingID === null ? "Create device group" : "Edit device group"}
          </h2>
          <p className="muted">
            The selector is a free-form JSON object. The server enforces only
            that it is a JSON object (not an array, scalar or null); the key
            grammar is not yet pinned.
          </p>
          <form onSubmit={submit} data-testid="device-groups-form">
            <label htmlFor="device-groups-name">Name</label>
            <input
              id="device-groups-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              data-testid="device-groups-name"
              maxLength={200}
              required
            />
            <label htmlFor="device-groups-selector">Selector (JSON)</label>
            <textarea
              id="device-groups-selector"
              rows={4}
              value={selectorText}
              onChange={(e) => setSelectorText(e.target.value)}
              placeholder='{"kinds":["switch"]}'
              data-testid="device-groups-selector"
            />
            <p className="muted metric-foot" data-testid="device-groups-selector-hint">
              Validation hint from the API: the selector must be a JSON object,
              e.g. <code>{'{"kinds":["switch"]}'}</code>; <code>[]</code>,{" "}
              <code>"x"</code> and <code>null</code> are rejected with a 400
              field error.
            </p>
            <div className="btn-row">
              <button
                type="submit"
                className="btn-sm"
                disabled={busy}
                data-testid="device-groups-submit"
              >
                {busy
                  ? "Saving…"
                  : editingID === null
                    ? "Create group"
                    : "Save changes"}
              </button>
              {editingID !== null && (
                <button
                  type="button"
                  className="btn-sm btn-ghost"
                  disabled={busy}
                  data-testid="device-groups-cancel"
                  onClick={resetForm}
                >
                  Cancel edit
                </button>
              )}
            </div>
            {error && (
              <p className="error" data-testid="device-groups-form-error">
                {error}
              </p>
            )}
            {fieldErrors.length > 0 && (
              <ul className="error" data-testid="device-groups-field-errors">
                {fieldErrors.map((fe, i) => (
                  <li key={`${fe.field ?? "field"}-${i}`}>
                    {fe.field ? `${fe.field}: ` : ""}
                    {fe.message ?? "invalid value"}
                  </li>
                ))}
              </ul>
            )}
          </form>
          {message && (
            <p className="muted" data-testid="device-groups-result">
              {message}
            </p>
          )}
          {deleteError && (
            <p className="error" data-testid="device-groups-delete-error">
              {deleteError}
            </p>
          )}
        </div>
      )}
      {!canWrite && (
        <p className="muted" data-testid="device-groups-readonly">
          Creating, editing and deleting device groups requires the admin role (
          <code>device_group.write</code>).
        </p>
      )}
    </section>
  );
}

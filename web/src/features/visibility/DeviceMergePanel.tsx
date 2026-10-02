"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { fetchJSON, problemDetail, readCSRF } from "@/lib/api";

interface DeviceOption {
  id: string;
  name: string;
  kind: string;
  site_id: string;
  mgmt_ip: string | null;
  status: string;
}

interface SourceCounts {
  identities: number | null;
  interfaces: number | null;
}

// DeviceMergePanel is the M10-S3b-2 merge surface on the device detail page.
// It lists candidate source devices through GET /v1/devices (newest first,
// same first-page bound as the inventory list; search is client-side because
// the API has no text query), excludes the target, and posts the selection to
// POST /v1/devices/{id}/merge with the session + CSRF pair. The confirm step
// fetches each source's identity-window and interface counts so the operator
// sees exactly what moves; sources are soft-deleted by the server. Both 409
// codes (device.merge_conflict, device.identity_conflict) and the uniform 404
// render verbatim from problem+json.
export default function DeviceMergePanel({
  deviceID,
  deviceName,
  canWrite,
  onMerged,
}: {
  deviceID: string;
  deviceName: string;
  canWrite: boolean;
  onMerged?: () => void;
}) {
  const [devices, setDevices] = useState<DeviceOption[] | null>(null);
  const [loadError, setLoadError] = useState("");
  const [query, setQuery] = useState("");
  const [selectedIDs, setSelectedIDs] = useState<string[]>([]);
  const [confirming, setConfirming] = useState(false);
  const [counts, setCounts] = useState<Record<string, SourceCounts>>({});
  const [countsLoading, setCountsLoading] = useState(false);
  const [mergeBusy, setMergeBusy] = useState(false);
  const [mergeError, setMergeError] = useState("");
  const [mergeMessage, setMergeMessage] = useState("");

  const load = useCallback(async () => {
    const res = await fetchJSON<{ data?: DeviceOption[] }>(
      "/api/v1/devices?limit=100&order=desc&include=status",
    );
    if (res.ok) {
      setDevices((res.data.data ?? []).filter((d) => d.id !== deviceID));
      setLoadError("");
    } else {
      setLoadError(res.error);
    }
  }, [deviceID]);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const rows = devices ?? [];
    if (needle === "") return rows;
    return rows.filter(
      (d) =>
        d.name.toLowerCase().includes(needle) ||
        (d.mgmt_ip ?? "").toLowerCase().includes(needle),
    );
  }, [devices, query]);

  const selected = (devices ?? []).filter((d) => selectedIDs.includes(d.id));

  function toggle(id: string, checked: boolean) {
    setMergeError("");
    setMergeMessage("");
    setSelectedIDs((ids) =>
      checked ? [...ids, id] : ids.filter((current) => current !== id),
    );
  }

  async function openConfirm() {
    setMergeError("");
    setMergeMessage("");
    if (selectedIDs.length === 0) {
      setMergeError("select at least one source device");
      return;
    }
    setConfirming(true);
    setCountsLoading(true);
    const next: Record<string, SourceCounts> = {};
    await Promise.all(
      selectedIDs.map(async (id) => {
        const [ifRes, identityRes] = await Promise.all([
          fetchJSON<{ data?: unknown[] }>(
            `/api/v1/devices/${id}/interfaces?limit=100`,
          ),
          fetchJSON<{ data?: unknown[] }>(
            `/api/v1/devices/${id}/identity-history?limit=50`,
          ),
        ]);
        next[id] = {
          interfaces: ifRes.ok ? (ifRes.data.data ?? []).length : null,
          identities: identityRes.ok ? (identityRes.data.data ?? []).length : null,
        };
      }),
    );
    setCounts(next);
    setCountsLoading(false);
  }

  async function merge() {
    setMergeError("");
    setMergeMessage("");
    setMergeBusy(true);
    try {
      const res = await fetch(`/api/v1/devices/${deviceID}/merge`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify({ source_device_ids: selectedIDs }),
      });
      if (!res.ok) {
        setMergeError(
          await problemDetail(res, `merge failed (status ${res.status})`),
        );
        return;
      }
      setMergeMessage(
        `Merged ${selectedIDs.length} device(s) into ${deviceName}.`,
      );
      setSelectedIDs([]);
      setConfirming(false);
      setCounts({});
      await load();
      onMerged?.();
    } catch {
      setMergeError("network error");
    } finally {
      setMergeBusy(false);
    }
  }

  if (!canWrite) {
    return (
      <section className="panel" style={{ marginTop: 16 }} data-testid="device-merge-panel">
        <h2 style={{ marginTop: 0 }}>Merge devices</h2>
        <p className="muted" data-testid="device-merge-readonly">
          Merging source devices into this one requires the admin role (
          <code>device.merge</code>).
        </p>
      </section>
    );
  }

  return (
    <section className="panel" style={{ marginTop: 16 }} data-testid="device-merge-panel">
      <h2 style={{ marginTop: 0 }}>Merge devices</h2>
      <p className="muted">
        Merge duplicate inventory rows into <strong>{deviceName}</strong>. The
        selected source devices&apos; identity windows and interfaces move to
        this device, then the sources are soft-deleted (hidden from inventory).
        The merge is atomic: an ifIndex collision aborts it untouched.
      </p>

      {loadError && (
        <p className="error" data-testid="device-merge-load-error">
          {loadError}
        </p>
      )}
      {!loadError && devices === null && (
        <p className="muted" data-testid="device-merge-loading">
          Loading candidate devices…
        </p>
      )}

      {!loadError && devices !== null && (
        <>
          <label htmlFor="device-merge-search">Search source devices</label>
          <input
            id="device-merge-search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="name or mgmt IP"
            data-testid="device-merge-search"
          />
          {devices.length === 0 ? (
            <p className="muted" data-testid="device-merge-empty">
              No other devices are available to merge.
            </p>
          ) : filtered.length === 0 ? (
            <p className="muted" data-testid="device-merge-nomatch">
              No loaded devices match this search. The picker covers the first
              100 devices (newest first); refine the search.
            </p>
          ) : (
            <table data-testid="device-merge-list">
              <thead>
                <tr>
                  <th />
                  <th>Name</th>
                  <th>Kind</th>
                  <th>Mgmt IP</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((d) => (
                  <tr key={d.id}>
                    <td style={{ width: 36 }}>
                      <input
                        type="checkbox"
                        aria-label={`Select ${d.name}`}
                        checked={selectedIDs.includes(d.id)}
                        onChange={(e) => toggle(d.id, e.target.checked)}
                        data-testid={`device-merge-option-${d.name}`}
                        style={{ width: "auto" }}
                      />
                    </td>
                    <td>{d.name}</td>
                    <td className="muted">{d.kind}</td>
                    <td className="muted">{d.mgmt_ip ?? "—"}</td>
                    <td className="muted">{d.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {selected.length > 0 && !confirming && (
            <div className="btn-row">
              <button
                type="button"
                className="btn-sm"
                data-testid="device-merge-submit"
                onClick={() => void openConfirm()}
              >
                Merge {selected.length} device(s) into this one
              </button>
              <button
                type="button"
                className="btn-sm btn-ghost"
                data-testid="device-merge-clear"
                onClick={() => {
                  setSelectedIDs([]);
                  setMergeError("");
                }}
              >
                Clear selection
              </button>
            </div>
          )}

          {confirming && (
            <div
              data-testid="device-merge-confirm-step"
              style={{ marginTop: 12, borderTop: "1px solid #2c3640", paddingTop: 12 }}
            >
              <h3 className="vis-subhead" style={{ marginTop: 0 }}>
                Confirm merge
              </h3>
              {countsLoading ? (
                <p className="muted" data-testid="device-merge-counts-loading">
                  Counting identity windows and interfaces to move…
                </p>
              ) : (
                <ul data-testid="device-merge-confirm-summary">
                  {selected.map((d) => {
                    const c = counts[d.id];
                    return (
                      <li key={d.id}>
                        <strong>{d.name}</strong>:{" "}
                        {c?.identities === null || c === undefined
                          ? "identity windows unknown"
                          : `${c.identities} identity window(s)`}
                        ,{" "}
                        {c?.interfaces === null || c === undefined
                          ? "interfaces unknown"
                          : `${c.interfaces} interface(s)`}
                        {" "}move to {deviceName}; {d.name} is soft-deleted.
                      </li>
                    );
                  })}
                </ul>
              )}
              <div className="btn-row">
                <button
                  type="button"
                  className="btn-sm btn-danger"
                  data-testid="device-merge-confirm"
                  disabled={mergeBusy || countsLoading}
                  onClick={() => void merge()}
                >
                  {mergeBusy ? "Merging…" : "Confirm merge"}
                </button>
                <button
                  type="button"
                  className="btn-sm btn-ghost"
                  disabled={mergeBusy}
                  data-testid="device-merge-cancel"
                  onClick={() => {
                    setConfirming(false);
                    setCounts({});
                  }}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {mergeError && (
            <p className="error" data-testid="device-merge-error">
              {mergeError}
            </p>
          )}
          {mergeMessage && (
            <p className="muted" data-testid="device-merge-result">
              {mergeMessage}
            </p>
          )}
        </>
      )}
    </section>
  );
}

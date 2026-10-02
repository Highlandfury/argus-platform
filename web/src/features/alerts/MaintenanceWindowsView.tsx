"use client";

import { useEffect, useState } from "react";

import { fetchJSON, problemDetail, readCSRF } from "@/lib/api";
import Badge from "@/ui/Badge";
import Button from "@/ui/Button";
import Dialog from "@/ui/Dialog";
import EmptyState from "@/ui/EmptyState";
import ErrorState from "@/ui/ErrorState";
import Panel from "@/ui/Panel";
import Skeleton from "@/ui/Skeleton";

import {
  fromDatetimeLocal,
  scopeSummary,
  shortId,
  shortTime,
  toDatetimeLocal,
  windowStatus,
} from "./format";
import {
  DEVICE_KINDS,
  type DeviceRef,
  type MaintenanceWindow,
  type MaintenanceWindowPage,
  type SiteRef,
  type TargetScope,
} from "./types";

const PAGE_LIMIT = 25;

// MaintenanceWindowsView is the M11-S3b suppression admin surface: single
// [starts_at, ends_at) windows over the canonical scope vocabulary
// (sites/device_ids/device_kinds). It lives as a tab of /alerts because the
// established IA groups alert suppression with the alerting workspace (the
// sidebar's Alerts item) rather than inventing a parallel Admin route.
export default function MaintenanceWindowsView({
  canWrite,
}: {
  canWrite: boolean;
}) {
  const [windows, setWindows] = useState<MaintenanceWindow[] | null>(null);
  const [nextCursor, setNextCursor] = useState("");
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [sites, setSites] = useState<SiteRef[] | null>(null);
  const [devices, setDevices] = useState<DeviceRef[] | null>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [scopeSites, setScopeSites] = useState<string[]>([]);
  const [scopeKinds, setScopeKinds] = useState<string[]>([]);
  const [scopeDevices, setScopeDevices] = useState<string[]>([]);
  const [startsAt, setStartsAt] = useState("");
  const [endsAt, setEndsAt] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");

  const [pendingDelete, setPendingDelete] = useState<MaintenanceWindow | null>(
    null,
  );
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setWindows(null);
      setError("");
      const res = await fetchJSON<MaintenanceWindowPage>(
        `/api/v1/maintenance-windows?limit=${PAGE_LIMIT}`,
      );
      if (cancelled) return;
      if (res.ok) {
        setWindows(res.data.data ?? []);
        setNextCursor(res.data.next_cursor ?? "");
        setHasMore(res.data.has_more ?? false);
      } else {
        setError(res.error);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [reloadToken]);

  useEffect(() => {
    let cancelled = false;
    async function loadPickers() {
      const [sitesRes, devicesRes] = await Promise.all([
        fetchJSON<{ data?: SiteRef[] }>("/api/v1/sites?limit=100"),
        fetchJSON<{ data?: DeviceRef[] }>("/api/v1/devices?limit=100&order=desc"),
      ]);
      if (cancelled) return;
      setSites(sitesRes.ok ? (sitesRes.data.data ?? []) : null);
      setDevices(devicesRes.ok ? (devicesRes.data.data ?? []) : null);
    }
    void loadPickers();
    return () => {
      cancelled = true;
    };
  }, []);

  const siteNames = new Map((sites ?? []).map((site) => [site.id, site.name]));
  const deviceNames = new Map(
    (devices ?? []).map((device) => [device.id, device.name]),
  );

  function openCreate() {
    const now = new Date();
    now.setSeconds(0, 0);
    const start = new Date(now.getTime() + 60_000);
    const end = new Date(now.getTime() + 60 * 60 * 1000);
    setName("");
    setScopeSites([]);
    setScopeKinds([]);
    setScopeDevices([]);
    setStartsAt(toDatetimeLocal(start));
    setEndsAt(toDatetimeLocal(end));
    setEnabled(true);
    setCreateError("");
    setCreateOpen(true);
  }

  function multiValues(
    event: React.ChangeEvent<HTMLSelectElement>,
  ): string[] {
    return Array.from(event.target.selectedOptions).map(
      (option) => option.value,
    );
  }

  async function createWindow(): Promise<boolean> {
    if (name.trim() === "") {
      setCreateError("Name is required.");
      return false;
    }
    if (startsAt === "" || endsAt === "") {
      setCreateError("Start and end are required.");
      return false;
    }
    const startMs = new Date(startsAt).getTime();
    const endMs = new Date(endsAt).getTime();
    if (Number.isNaN(startMs) || Number.isNaN(endMs)) {
      setCreateError("Start and end must be valid datetimes.");
      return false;
    }
    if (endMs <= startMs) {
      setCreateError("End must be after start (a single [start, end) interval).");
      return false;
    }
    const scope: TargetScope = {};
    if (scopeSites.length > 0) scope.sites = scopeSites;
    if (scopeDevices.length > 0) scope.device_ids = scopeDevices;
    if (scopeKinds.length > 0) scope.device_kinds = scopeKinds;
    setCreating(true);
    setCreateError("");
    try {
      const res = await fetch("/api/v1/maintenance-windows", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify({
          name: name.trim(),
          scope,
          enabled,
          starts_at: fromDatetimeLocal(startsAt),
          ends_at: fromDatetimeLocal(endsAt),
        }),
      });
      if (!res.ok) {
        setCreateError(await problemDetail(res));
        return false;
      }
      const created = (await res.json()) as MaintenanceWindow;
      setCreateOpen(false);
      setNotice(
        `Maintenance window ${created.name} created. Matching alerts are suppressed (maintenance) while it is active.`,
      );
      setReloadToken((token) => token + 1);
      return true;
    } catch {
      setCreateError("network error");
      return false;
    } finally {
      setCreating(false);
    }
  }

  async function deleteWindow(): Promise<void> {
    if (!pendingDelete) return;
    setDeleting(true);
    setDeleteError("");
    try {
      const res = await fetch(
        `/api/v1/maintenance-windows/${encodeURIComponent(pendingDelete.id)}`,
        {
          method: "DELETE",
          headers: { "X-CSRF-Token": readCSRF() },
        },
      );
      if (!res.ok && res.status !== 204) {
        setDeleteError(await problemDetail(res));
        return;
      }
      setNotice(`Maintenance window ${pendingDelete.name} deleted.`);
      setPendingDelete(null);
      setReloadToken((token) => token + 1);
    } catch {
      setDeleteError("network error");
    } finally {
      setDeleting(false);
    }
  }

  async function loadMore() {
    if (nextCursor === "" || loadingMore) return;
    setLoadingMore(true);
    try {
      const res = await fetchJSON<MaintenanceWindowPage>(
        `/api/v1/maintenance-windows?limit=${PAGE_LIMIT}&cursor=${encodeURIComponent(
          nextCursor,
        )}`,
      );
      if (res.ok) {
        setWindows((rows) => [...(rows ?? []), ...(res.data.data ?? [])]);
        setNextCursor(res.data.next_cursor ?? "");
        setHasMore(res.data.has_more ?? false);
      } else {
        setError(res.error);
      }
    } finally {
      setLoadingMore(false);
    }
  }

  const pickersUnavailable = sites === null || devices === null;

  return (
    <section data-testid="maintenance-view">
      <Panel
        title="Maintenance windows"
        subtitle="Single [starts_at, ends_at) intervals. While active, matching alerts are Suppressed (maintenance): still recorded and evaluated, never notified. Recurrence is a V2 horizon item."
        actions={
          canWrite ? (
            <Button
              size="sm"
              variant="primary"
              onClick={openCreate}
              data-testid="maintenance-create-open"
            >
              New maintenance window
            </Button>
          ) : (
            <span className="muted" data-testid="maintenance-readonly">
              Your role can view but not manage suppression objects
              (alert.silence).
            </span>
          )
        }
        testId="maintenance-panel"
      >
        {notice !== "" && (
          <p className="muted" data-testid="maintenance-notice">
            {notice}
          </p>
        )}
        {error !== "" && (
          <ErrorState
            title="Maintenance windows unavailable"
            message={error}
            action={
              <Button
                size="sm"
                variant="secondary"
                onClick={() => setReloadToken((token) => token + 1)}
              >
                Try again
              </Button>
            }
            testId="maintenance-error"
          />
        )}
        {error === "" && windows === null && (
          <div data-testid="maintenance-loading" aria-busy="true">
            <Skeleton height={14} width="85%" />
            <div style={{ height: 8 }} />
            <Skeleton height={14} width="70%" />
          </div>
        )}
        {error === "" && windows !== null && windows.length === 0 && (
          <EmptyState
            title="No maintenance windows"
            description="Create a window to suppress matching alerts during planned work. Windows are single intervals over sites, device kinds or device ids."
            testId="maintenance-empty"
          />
        )}
        {error === "" && windows !== null && windows.length > 0 && (
          <>
            <div className="alert-table-wrap">
              <table data-testid="maintenance-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Status</th>
                    <th>Scope</th>
                    <th>Starts</th>
                    <th>Ends</th>
                    <th>Enabled</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {windows.map((window) => {
                    const status = windowStatus(window);
                    return (
                      <tr
                        key={window.id}
                        data-testid={`maintenance-row-${window.id}`}
                        data-active={window.active ? "true" : "false"}
                      >
                        <td>{window.name}</td>
                        <td>
                          <Badge variant={status.variant}>{status.label}</Badge>
                        </td>
                        <td className="muted">
                          {scopeSummary(window.scope, siteNames, deviceNames)}
                        </td>
                        <td className="muted">{shortTime(window.starts_at)}</td>
                        <td className="muted">{shortTime(window.ends_at)}</td>
                        <td className="muted">{window.enabled ? "yes" : "no"}</td>
                        <td style={{ textAlign: "right" }}>
                          {canWrite && (
                            <Button
                              size="sm"
                              variant="danger"
                              onClick={() => {
                                setDeleteError("");
                                setPendingDelete(window);
                              }}
                              data-testid={`maintenance-delete-${window.id}`}
                            >
                              Delete
                            </Button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {hasMore && (
              <div className="btn-row" style={{ marginTop: 12 }}>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={loadingMore}
                  onClick={() => void loadMore()}
                  data-testid="maintenance-load-more"
                >
                  {loadingMore ? "Loading…" : "Load more"}
                </Button>
              </div>
            )}
          </>
        )}
      </Panel>

      <Dialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="New maintenance window"
        testId="maintenance-create-dialog"
        footer={
          <>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setCreateOpen(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              variant="primary"
              disabled={creating}
              onClick={() => void createWindow()}
              data-testid="maintenance-submit"
            >
              {creating ? "Creating…" : "Create window"}
            </Button>
          </>
        }
      >
        {pickersUnavailable && (
          <p className="muted" data-testid="maintenance-pickers-unavailable">
            Site/device pickers are unavailable right now; the window can still
            be created org-wide or with device kinds.
          </p>
        )}
        <label htmlFor="maintenance-name">Name</label>
        <input
          id="maintenance-name"
          value={name}
          maxLength={200}
          onChange={(e) => setName(e.target.value)}
          data-testid="maintenance-name"
          placeholder="Core switch upgrade — HQ"
        />
        <label htmlFor="maintenance-scope-sites">Sites (optional)</label>
        <select
          id="maintenance-scope-sites"
          multiple
          size={3}
          className="alert-multiselect"
          disabled={sites === null}
          value={scopeSites}
          onChange={(e) => setScopeSites(multiValues(e))}
          data-testid="maintenance-scope-sites"
        >
          {(sites ?? []).map((site) => (
            <option key={site.id} value={site.id}>
              {site.name}
            </option>
          ))}
        </select>
        <label htmlFor="maintenance-scope-kinds">Device kinds (optional)</label>
        <select
          id="maintenance-scope-kinds"
          multiple
          size={3}
          className="alert-multiselect"
          value={scopeKinds}
          onChange={(e) => setScopeKinds(multiValues(e))}
          data-testid="maintenance-scope-kinds"
        >
          {DEVICE_KINDS.map((kind) => (
            <option key={kind} value={kind}>
              {kind}
            </option>
          ))}
        </select>
        <label htmlFor="maintenance-scope-devices">Devices (optional)</label>
        <select
          id="maintenance-scope-devices"
          multiple
          size={3}
          className="alert-multiselect"
          disabled={devices === null}
          value={scopeDevices}
          onChange={(e) => setScopeDevices(multiValues(e))}
          data-testid="maintenance-scope-devices"
        >
          {(devices ?? []).map((device) => (
            <option key={device.id} value={device.id}>
              {device.name}
            </option>
          ))}
        </select>
        <label htmlFor="maintenance-starts">Starts at</label>
        <input
          id="maintenance-starts"
          type="datetime-local"
          value={startsAt}
          onChange={(e) => setStartsAt(e.target.value)}
          data-testid="maintenance-starts"
        />
        <label htmlFor="maintenance-ends">Ends at</label>
        <input
          id="maintenance-ends"
          type="datetime-local"
          value={endsAt}
          onChange={(e) => setEndsAt(e.target.value)}
          data-testid="maintenance-ends"
        />
        <label style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            data-testid="maintenance-enabled"
            style={{ width: "auto", margin: 0 }}
          />
          Enabled
        </label>
        {createError !== "" && (
          <p className="error" data-testid="maintenance-create-error">
            {createError}
          </p>
        )}
      </Dialog>

      <Dialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        title="Delete maintenance window"
        testId="maintenance-delete-dialog"
        footer={
          <>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setPendingDelete(null)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              variant="danger"
              disabled={deleting}
              onClick={() => void deleteWindow()}
              data-testid="maintenance-delete-confirm"
            >
              {deleting ? "Deleting…" : "Delete"}
            </Button>
          </>
        }
      >
        <p className="muted">
          Delete <strong>{pendingDelete?.name}</strong> (
          {pendingDelete ? shortId(pendingDelete.id) : ""})? Suppression history
          stays on the alert timeline; only the window object is removed.
        </p>
        {deleteError !== "" && (
          <p className="error" data-testid="maintenance-delete-error">
            {deleteError}
          </p>
        )}
      </Dialog>
    </section>
  );
}

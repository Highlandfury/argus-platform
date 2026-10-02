"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import { fetchJSON, problemDetail, readCSRF } from "@/lib/api";

interface Device {
  id: string;
  site_id: string;
  name: string;
  kind: string;
  status: string;
  critical: boolean;
  mgmt_ip: string | null;
  first_seen_at: string;
  last_seen_at: string | null;
  updated_at: string;
  // M10-S1 include=status decoration (poll-health rollup, up/down/unknown).
  poll_status?: {
    status: "up" | "down" | "unknown";
    last_checked_at: string | null;
  } | null;
}

interface Site {
  id: string;
  name: string;
}

interface DevicePage {
  data?: Device[];
  next_cursor?: string | null;
  has_more?: boolean;
}

// Canonical device taxonomy (docs/05 FR-INV-001); the list filter mirrors the
// set the add/edit forms offer. Existing rows with a custom kind are still
// listed (the filter simply cannot select them).
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

// Cursor pagination is server-side (next_cursor). "Load more" appends bounded
// pages; search and poll-status filtering are client-side over the loaded rows
// because /v1/devices has no text-query parameter and filter[status] is the
// inventory lifecycle, not the S1 poll-health rollup. The first page keeps the
// pre-existing 100-row size so a freshly added device (newest UUIDv7 id) is
// visible without walking the cursor first.
const PAGE_LIMIT = 100;
const MAX_PAGES = 5;

function shortTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function statusClass(status: string): string {
  switch (status) {
    case "up":
      return "status status-active";
    case "down":
      return "status status-revoked";
    case "degraded":
      return "status status-stale";
    default:
      return "status status-pending";
  }
}

function pollStatus(device: Device): "up" | "down" | "unknown" {
  return device.poll_status?.status ?? "unknown";
}

// DevicesList renders the M7 device inventory (name, kind, site, lifecycle and
// poll status, management IP, updated/last-seen) from the real /v1/devices API
// with M10-S1 `include=status`. M10-S3b-1 adds server filters (site/kind),
// URL-driven params (site/status/kind/q), a client-side name/IP search over the
// loaded rows, and a cursor-driven "Load more". Loading/empty/error states stay
// observable; refreshKey re-runs the first page after a successful manual add.
export default function DevicesList({
  refreshKey = 0,
  canWrite = false,
}: {
  refreshKey?: number;
  canWrite?: boolean;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const siteFilter = searchParams.get("site") ?? "";
  const statusFilter = searchParams.get("status") ?? "all";
  const kindFilter = searchParams.get("kind") ?? "";
  const query = searchParams.get("q") ?? "";

  const [devices, setDevices] = useState<Device[] | null>(null);
  const [sites, setSites] = useState<Site[]>([]);
  const [nextCursor, setNextCursor] = useState("");
  const [hasMore, setHasMore] = useState(false);
  const [pages, setPages] = useState(1);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");

  function setParam(key: string, value: string) {
    // Read the live URL rather than the hook snapshot so rapid filter changes
    // do not re-apply a stale parameter from the previous render.
    const base =
      typeof window !== "undefined"
        ? window.location.search
        : `?${searchParams.toString()}`;
    const params = new URLSearchParams(base);
    if (value === "" || value === "all") params.delete(key);
    else params.set(key, value);
    const qs = params.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }

  // First page (and any server-filter change). Server-supported filters are
  // site and kind; status/search stay client-side over these rows.
  useEffect(() => {
    let cancelled = false;
    async function load() {
      setDevices(null);
      setNextCursor("");
      setHasMore(false);
      setPages(1);
      setError("");
      const params = new URLSearchParams({
        include: "status",
        limit: String(PAGE_LIMIT),
        order: "desc",
      });
      if (siteFilter !== "") params.set("filter[site_id]", siteFilter);
      if (kindFilter !== "") params.set("filter[kind]", kindFilter);
      const res = await fetchJSON<DevicePage>(
        `/api/v1/devices?${params.toString()}`,
      );
      if (cancelled) return;
      if (res.ok) {
        setDevices(res.data.data ?? []);
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
  }, [siteFilter, kindFilter, refreshKey]);

  useEffect(() => {
    let cancelled = false;
    async function loadSites() {
      const res = await fetchJSON<{ data?: Site[] }>("/api/v1/sites?limit=100");
      if (!cancelled && res.ok) setSites(res.data.data ?? []);
    }
    void loadSites();
    return () => {
      cancelled = true;
    };
  }, []);

  async function loadMore() {
    if (nextCursor === "" || loadingMore) return;
    setLoadingMore(true);
    try {
      const params = new URLSearchParams({
        include: "status",
        limit: String(PAGE_LIMIT),
        cursor: nextCursor,
        order: "desc",
      });
      if (siteFilter !== "") params.set("filter[site_id]", siteFilter);
      if (kindFilter !== "") params.set("filter[kind]", kindFilter);
      const res = await fetchJSON<DevicePage>(
        `/api/v1/devices?${params.toString()}`,
      );
      if (res.ok) {
        setDevices((rows) => [...(rows ?? []), ...(res.data.data ?? [])]);
        setNextCursor(res.data.next_cursor ?? "");
        setHasMore(res.data.has_more ?? false);
        setPages((p) => p + 1);
      } else {
        setError(res.error);
      }
    } finally {
      setLoadingMore(false);
    }
  }

  const siteName = new Map(sites.map((s) => [s.id, s.name]));

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (devices ?? []).filter((d) => {
      if (
        statusFilter !== "all" &&
        pollStatus(d) !== statusFilter
      ) {
        return false;
      }
      if (needle === "") return true;
      return (
        d.name.toLowerCase().includes(needle) ||
        (d.mgmt_ip ?? "").toLowerCase().includes(needle)
      );
    });
  }, [devices, statusFilter, query]);

  const filters = (
    <div
      className="filter-row"
      style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}
      data-testid="devices-filters"
    >
      <div>
        <label htmlFor="devices-filter-site">Site</label>
        <select
          id="devices-filter-site"
          value={siteFilter}
          onChange={(e) => setParam("site", e.target.value)}
          data-testid="devices-filter-site"
          style={{ width: "auto" }}
        >
          <option value="">All sites</option>
          {sites.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor="devices-filter-status">Poll status</label>
        <select
          id="devices-filter-status"
          value={statusFilter}
          onChange={(e) => setParam("status", e.target.value)}
          data-testid="devices-filter-status"
          style={{ width: "auto" }}
        >
          <option value="all">All statuses</option>
          <option value="up">up</option>
          <option value="down">down</option>
          <option value="unknown">unknown</option>
        </select>
      </div>
      <div>
        <label htmlFor="devices-filter-kind">Kind</label>
        <select
          id="devices-filter-kind"
          value={kindFilter}
          onChange={(e) => setParam("kind", e.target.value)}
          data-testid="devices-filter-kind"
          style={{ width: "auto" }}
        >
          <option value="">All kinds</option>
          {DEVICE_KINDS.map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor="devices-search">Search</label>
        <input
          id="devices-search"
          value={query}
          onChange={(e) => setParam("q", e.target.value)}
          placeholder="name or mgmt IP"
          data-testid="devices-search"
          style={{ width: "auto" }}
        />
      </div>
    </div>
  );

  if (error) {
    return (
      <>
        {filters}
        <p className="error" data-testid="devices-error">
          {error}
        </p>
      </>
    );
  }
  if (devices === null) {
    return (
      <>
        {filters}
        <p className="muted" data-testid="devices-loading">
          Loading devices…
        </p>
      </>
    );
  }
  return (
    <>
      {filters}
      {devices.length === 0 ? (
        <p className="muted" data-testid="devices-empty">
          No devices match this page of inventory. Admins can add one with the
          Add device form; discovered devices will appear here once discovery
          ships.
        </p>
      ) : filtered.length === 0 ? (
        <p className="muted" data-testid="devices-nomatch">
          No loaded devices match the current filters. Load more pages or refine
          the filters.
        </p>
      ) : (
        <>
          <p className="muted" data-testid="devices-filter-count">
            {filtered.length} of {devices.length} loaded devices match the
            current filters
          </p>
          <table data-testid="devices-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Kind</th>
                  <th>Site</th>
                  <th>Status</th>
                  <th>Poll status</th>
                  <th>Mgmt IP</th>
                  <th>Last seen</th>
                  <th>Updated</th>
                  {canWrite && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {filtered.map((d) => (
                  <tr key={d.id} data-device-id={d.id}>
                    <td>
                      <a href={`/devices/${d.id}`}>{d.name}</a>
                      {d.critical && (
                        <span
                          className="status status-stale"
                          style={{ marginLeft: 8 }}
                          title="Critical device (5-minute failure backoff ceiling)"
                        >
                          critical
                        </span>
                      )}
                    </td>
                    <td className="muted">{d.kind}</td>
                    <td className="muted">{siteName.get(d.site_id) ?? "—"}</td>
                    <td>
                      <span className={statusClass(d.status)}>{d.status}</span>
                    </td>
                    <td>
                      <span
                        className={statusClass(pollStatus(d))}
                        data-status={pollStatus(d)}
                      >
                        {pollStatus(d)}
                      </span>
                    </td>
                    <td className="muted">{d.mgmt_ip ?? "—"}</td>
                    <td className="muted">{shortTime(d.last_seen_at)}</td>
                    <td className="muted">{shortTime(d.updated_at)}</td>
                    {canWrite && (
                      <td>
                        <DeviceRowDelete
                          deviceId={d.id}
                          onDeleted={(id) =>
                            setDevices((prev) =>
                              prev ? prev.filter((x) => x.id !== id) : prev,
                            )
                          }
                        />
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          {hasMore &&
            (pages < MAX_PAGES ? (
              <div className="btn-row" style={{ marginTop: 12 }}>
                <button
                  type="button"
                  className="btn-sm btn-ghost"
                  disabled={loadingMore}
                  data-testid="devices-load-more"
                  onClick={() => void loadMore()}
                >
                  {loadingMore ? "Loading…" : "Load more"}
                </button>
              </div>
            ) : (
              <p className="muted metric-foot" data-testid="devices-load-more-limit">
                Showing the first {MAX_PAGES * PAGE_LIMIT} devices; refine the
                filters to narrow the list.
              </p>
            ))}
        </>
      )}
    </>
  );
}

// DeviceRowDelete is the M10-S3b-4 row action: a two-step confirm that
// soft-deletes through DELETE /v1/devices/{id} (session + CSRF) and removes the
// row locally on success, without a trip to the detail page.
function DeviceRowDelete({
  deviceId,
  onDeleted,
}: {
  deviceId: string;
  onDeleted: (id: string) => void;
}) {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function remove() {
    setBusy(true);
    setError("");
    try {
      const res = await fetch(`/api/v1/devices/${deviceId}`, {
        method: "DELETE",
        headers: { "X-CSRF-Token": readCSRF() },
      });
      if (!res.ok) {
        setError(
          await problemDetail(res, `delete failed (status ${res.status})`),
        );
        setConfirming(false);
        return;
      }
      onDeleted(deviceId);
    } catch {
      setError("network error");
    } finally {
      setBusy(false);
    }
  }

  if (!confirming) {
    return (
      <button
        type="button"
        className="btn-sm btn-ghost"
        data-testid="device-row-delete"
        onClick={() => {
          setConfirming(true);
          setError("");
        }}
      >
        Delete
      </button>
    );
  }
  return (
    <span className="btn-row">
      <button
        type="button"
        className="btn-sm"
        disabled={busy}
        data-testid="device-row-delete-confirm"
        onClick={() => void remove()}
      >
        {busy ? "Deleting…" : "Confirm"}
      </button>
      <button
        type="button"
        className="btn-sm btn-ghost"
        disabled={busy}
        data-testid="device-row-delete-cancel"
        onClick={() => setConfirming(false)}
      >
        Cancel
      </button>
      {error && (
        <span className="error" data-testid="device-row-delete-error">
          {error}
        </span>
      )}
    </span>
  );
}

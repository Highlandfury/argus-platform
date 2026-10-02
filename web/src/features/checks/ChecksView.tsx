"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";

import { fetchJSON } from "@/lib/api";

interface DeviceCheck {
  check_id: string;
  device_id: string;
  collector_id: string | null;
  poll_type: string;
  status: "pending" | "completed" | "failed";
  outcome: string;
  error_class: string;
  latency_ms: number | null;
  created_at: string;
  completed_at: string | null;
  status_url: string;
}

interface DeviceCheckPage {
  data?: DeviceCheck[];
  next_cursor?: string | null;
  has_more?: boolean;
}

interface PollHealthRecord {
  id: string;
  device_id: string;
  collector_id: string;
  poll_type: string;
  checked_at: string;
  latency_ms: number;
  outcome: "success" | "failure";
  error_class: string;
  consecutive_failures: number;
  origin: string;
}

interface PollHealthFeed {
  data?: PollHealthRecord[];
  since?: string;
}

interface Device {
  id: string;
  name: string;
}

const CHECK_STATUSES = ["pending", "completed", "failed"];
const POLL_TYPES = ["icmp", "snmp"];

// Bounded window selector for the poll-health feed. `since` is a URL param so
// the view is linkable; the API additionally enforces the 24 h maximum.
const SINCE_OPTIONS = [
  { value: "1h", label: "Last hour", hours: 1 },
  { value: "6h", label: "Last 6 hours", hours: 6 },
  { value: "24h", label: "Last 24 hours", hours: 24 },
] as const;

const CHECK_PAGE_LIMIT = 25;
const HEALTH_LIMIT = 50;

function shortTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function shortID(id: string): string {
  return id.slice(0, 8);
}

function checkStatusClass(status: string): string {
  switch (status) {
    case "pending":
      return "status status-pending";
    case "completed":
      return "status status-active";
    default:
      return "status status-revoked";
  }
}

function outcomeLabel(c: DeviceCheck): string {
  if (c.outcome === "") return c.error_class || "—";
  return c.error_class ? `${c.outcome} · ${c.error_class}` : c.outcome;
}

// ChecksView is the M10-S3b-3 /checks operator page: the org-wide on-demand
// check ledger (newest first, cursor "Load more") plus the bounded recent
// poll-failure feed. Filters are URL-driven (status/poll_type/since), states
// stay observable, and every row links to its device.
export default function ChecksView() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  // Last URL applied through setParam (intent), so rapid filter changes compose
  // even while router.replace has not committed the previous one.
  const appliedSearchRef = useRef<string | null>(null);
  const statusFilter = searchParams.get("status") ?? "";
  const pollTypeFilter = searchParams.get("poll_type") ?? "";
  const sinceParam = searchParams.get("since") ?? "1h";

  const [checks, setChecks] = useState<DeviceCheck[] | null>(null);
  const [nextCursor, setNextCursor] = useState("");
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [checksError, setChecksError] = useState("");

  const [health, setHealth] = useState<PollHealthRecord[] | null>(null);
  const [healthError, setHealthError] = useState("");

  const [devices, setDevices] = useState<Device[]>([]);

  function setParam(key: string, value: string, fallback = "") {
    // Read the live URL rather than the hook snapshot so rapid filter changes
    // do not re-apply a stale parameter from the previous render.
    const base =
      appliedSearchRef.current !== null
        ? `?${appliedSearchRef.current}`
        : typeof window !== "undefined"
          ? window.location.search
          : `?${searchParams.toString()}`;
    const params = new URLSearchParams(base);
    if (value === fallback) params.delete(key);
    else params.set(key, value);
    const qs = params.toString();
    appliedSearchRef.current = qs;
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }

  useEffect(() => {
    // Re-sync the intent ref whenever the committed URL changes (external
    // navigation, back/forward); setParam keeps it ahead of the router.
    appliedSearchRef.current = searchParams.toString();
  }, [searchParams]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setChecks(null);
      setNextCursor("");
      setHasMore(false);
      setChecksError("");
      const params = new URLSearchParams({
        limit: String(CHECK_PAGE_LIMIT),
        order: "desc",
      });
      if (statusFilter !== "") params.set("filter[status]", statusFilter);
      if (pollTypeFilter !== "") params.set("filter[poll_type]", pollTypeFilter);
      const res = await fetchJSON<DeviceCheckPage>(
        `/api/v1/checks?${params.toString()}`,
      );
      if (cancelled) return;
      if (res.ok) {
        setChecks(res.data.data ?? []);
        setNextCursor(res.data.next_cursor ?? "");
        setHasMore(res.data.has_more ?? false);
      } else {
        setChecksError(res.error);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [statusFilter, pollTypeFilter]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setHealth(null);
      setHealthError("");
      const option =
        SINCE_OPTIONS.find((o) => o.value === sinceParam) ?? SINCE_OPTIONS[0];
      const since = new Date(
        Date.now() - option.hours * 60 * 60 * 1000,
      ).toISOString();
      const params = new URLSearchParams({
        outcome: "failure",
        limit: String(HEALTH_LIMIT),
        since,
      });
      const res = await fetchJSON<PollHealthFeed>(
        `/api/v1/poll-health?${params.toString()}`,
      );
      if (cancelled) return;
      if (res.ok) setHealth(res.data.data ?? []);
      else setHealthError(res.error);
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [sinceParam]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      const res = await fetchJSON<{ data?: Device[] }>(
        "/api/v1/devices?limit=100&order=desc",
      );
      if (!cancelled && res.ok) setDevices(res.data.data ?? []);
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const deviceName = useMemo(
    () => new Map(devices.map((d) => [d.id, d.name])),
    [devices],
  );

  async function loadMore() {
    if (nextCursor === "" || loadingMore) return;
    setLoadingMore(true);
    try {
      const params = new URLSearchParams({
        limit: String(CHECK_PAGE_LIMIT),
        order: "desc",
        cursor: nextCursor,
      });
      if (statusFilter !== "") params.set("filter[status]", statusFilter);
      if (pollTypeFilter !== "") params.set("filter[poll_type]", pollTypeFilter);
      const res = await fetchJSON<DeviceCheckPage>(
        `/api/v1/checks?${params.toString()}`,
      );
      if (res.ok) {
        setChecks((rows) => [...(rows ?? []), ...(res.data.data ?? [])]);
        setNextCursor(res.data.next_cursor ?? "");
        setHasMore(res.data.has_more ?? false);
      } else {
        setChecksError(res.error);
      }
    } finally {
      setLoadingMore(false);
    }
  }

  function deviceCell(id: string, rowTestId: string) {
    const name = deviceName.get(id);
    return (
      <a href={`/devices/${id}`} data-testid={rowTestId}>
        {name ?? shortID(id)}
      </a>
    );
  }

  const checkFilters = (
    <div
      className="filter-row"
      style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}
      data-testid="checks-filters"
    >
      <div>
        <label htmlFor="checks-filter-status">Status</label>
        <select
          id="checks-filter-status"
          value={statusFilter}
          onChange={(e) => setParam("status", e.target.value)}
          data-testid="checks-filter-status"
          style={{ width: "auto" }}
        >
          <option value="">All statuses</option>
          {CHECK_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor="checks-filter-poll-type">Poll type</label>
        <select
          id="checks-filter-poll-type"
          value={pollTypeFilter}
          onChange={(e) => setParam("poll_type", e.target.value)}
          data-testid="checks-filter-poll-type"
          style={{ width: "auto" }}
        >
          <option value="">All poll types</option>
          {POLL_TYPES.map((p) => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </select>
      </div>
    </div>
  );

  return (
    <section data-testid="checks-view">
      <div className="panel" data-testid="checks-panel">
        <h2 style={{ marginTop: 0 }}>On-demand checks</h2>
        <p className="muted" data-testid="checks-note">
          Org-wide check ledger, newest first. Checks run on demand against a
          device&apos;s site collector; a pending row completes when the
          collector reports, or is failed as expired after the server TTL.
        </p>
        {checkFilters}
        {checksError && (
          <p className="error" data-testid="checks-error">
            {checksError}
          </p>
        )}
        {!checksError && checks === null && (
          <p className="muted" data-testid="checks-loading">
            Loading checks…
          </p>
        )}
        {!checksError && checks !== null && checks.length === 0 && (
          <p className="muted" data-testid="checks-empty">
            No checks match the current filters. Run an on-demand check from a
            device page; completed and expired checks appear here.
          </p>
        )}
        {!checksError && checks !== null && checks.length > 0 && (
          <>
            <table data-testid="checks-table">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Poll type</th>
                  <th>Status</th>
                  <th>Outcome</th>
                  <th>Latency</th>
                  <th>Created</th>
                  <th>Completed</th>
                </tr>
              </thead>
              <tbody>
                {checks.map((c) => (
                  <tr
                    key={c.check_id}
                    data-testid={`checks-row-${c.check_id}`}
                    data-status={c.status}
                    data-device-id={c.device_id}
                  >
                    <td>
                      {deviceCell(c.device_id, `checks-device-${c.check_id}`)}
                    </td>
                    <td className="muted">{c.poll_type}</td>
                    <td>
                      <span
                        className={checkStatusClass(c.status)}
                        data-status={c.status}
                      >
                        {c.status}
                      </span>
                    </td>
                    <td className="muted" data-outcome={c.outcome || "none"}>
                      {outcomeLabel(c)}
                    </td>
                    <td className="muted">
                      {c.latency_ms === null ? "—" : `${c.latency_ms} ms`}
                    </td>
                    <td className="muted">{shortTime(c.created_at)}</td>
                    <td className="muted">{shortTime(c.completed_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {hasMore && (
              <div className="btn-row" style={{ marginTop: 12 }}>
                <button
                  type="button"
                  className="btn-sm btn-ghost"
                  disabled={loadingMore}
                  data-testid="checks-load-more"
                  onClick={() => void loadMore()}
                >
                  {loadingMore ? "Loading…" : "Load more"}
                </button>
              </div>
            )}
          </>
        )}
      </div>

      <div className="panel" style={{ marginTop: 16 }} data-testid="poll-health-panel">
        <h2 style={{ marginTop: 0 }}>Recent poll failures</h2>
        <p className="muted" data-testid="poll-health-note">
          Bounded failure feed from scheduled and on-demand polls (times are the
          collector probe timestamps). At most a 24-hour window; deep
          pagination is deliberately not offered.
        </p>
        <div
          className="filter-row"
          style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}
          data-testid="poll-health-filters"
        >
          <div>
            <label htmlFor="poll-health-filter-since">Window</label>
            <select
              id="poll-health-filter-since"
              value={sinceParam}
              onChange={(e) => setParam("since", e.target.value, "1h")}
              data-testid="poll-health-filter-since"
              style={{ width: "auto" }}
            >
              {SINCE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </div>
        </div>
        {healthError && (
          <p className="error" data-testid="poll-health-error">
            {healthError}
          </p>
        )}
        {!healthError && health === null && (
          <p className="muted" data-testid="poll-health-loading">
            Loading recent poll failures…
          </p>
        )}
        {!healthError && health !== null && health.length === 0 && (
          <p className="muted" data-testid="poll-health-empty">
            No poll failures in the selected window.
          </p>
        )}
        {!healthError && health !== null && health.length > 0 && (
          <table data-testid="poll-health-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Device</th>
                <th>Poll type</th>
                <th>Error class</th>
                <th>Latency</th>
                <th>Consecutive failures</th>
              </tr>
            </thead>
            <tbody>
              {health.map((r) => (
                <tr
                  key={r.id}
                  data-testid={`poll-health-row-${r.id}`}
                  data-device-id={r.device_id}
                >
                  <td className="muted">{shortTime(r.checked_at)}</td>
                  <td>{deviceCell(r.device_id, `poll-health-device-${r.id}`)}</td>
                  <td className="muted">{r.poll_type}</td>
                  <td className="muted" data-error-class={r.error_class || "none"}>
                    {r.error_class || "—"}
                  </td>
                  <td className="muted">{r.latency_ms} ms</td>
                  <td className="muted">{r.consecutive_failures}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}

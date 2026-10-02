"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import { fetchJSON } from "@/lib/api";

import StatusChip from "./StatusChip";
import { formatLatency, shortTime } from "./format";

// SiteDashboard answers the site-level questions in <= 3 clicks: status mix,
// recent issues and a URL-driven device table. The device list is one
// /v1/devices?include=status call; "recent issues" fans out to at most five
// poll-health calls (bounded) and never fetches per-device data for healthy
// devices.
export interface SiteDevice {
  id: string;
  name: string;
  kind: string;
  critical: boolean;
  mgmt_ip: string | null;
  status: string;
  poll_status?: {
    status: "up" | "down" | "unknown";
    since: string | null;
    last_outcome: string | null;
    last_error_class: string | null;
    last_latency_ms: number | null;
    consecutive_failures: number | null;
    last_checked_at: string | null;
  } | null;
}

interface PollHealthRecord {
  id: string;
  poll_type: string;
  checked_at: string;
  latency_ms: number;
  outcome: string;
  error_class: string;
  consecutive_failures: number;
  origin: string;
}

interface Issue {
  id: string;
  deviceID: string;
  deviceName: string;
  poll_type: string;
  checked_at: string;
  latency_ms: number;
  error_class: string;
  consecutive_failures: number;
}

const MAX_ISSUE_DEVICES = 5;
const MAX_ISSUES = 10;

function pollStatus(device: SiteDevice): "up" | "down" | "unknown" {
  return device.poll_status?.status ?? "unknown";
}

export default function SiteDashboard({
  siteID,
  siteName,
}: {
  siteID: string;
  siteName: string;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const statusFilter = searchParams.get("status") ?? "all";
  const query = searchParams.get("q") ?? "";

  const [devices, setDevices] = useState<SiteDevice[] | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [error, setError] = useState("");
  const [issues, setIssues] = useState<Issue[] | null>(null);
  const [issuesError, setIssuesError] = useState("");

  function setParam(key: string, value: string) {
    // Read the live URL rather than the hook snapshot: rapid filter changes
    // (click a status chip, then type) would otherwise re-apply a stale
    // parameter from the previous render.
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

  useEffect(() => {
    let cancelled = false;
    async function load() {
      const params = new URLSearchParams({
        "filter[site_id]": siteID,
        include: "status",
        limit: "100",
      });
      const res = await fetchJSON<{ data?: SiteDevice[]; has_more?: boolean }>(
        `/api/v1/devices?${params.toString()}`,
      );
      if (cancelled) return;
      if (res.ok) {
        setDevices(res.data.data ?? []);
        setHasMore(res.data.has_more ?? false);
        setError("");
      } else {
        setError(res.error);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [siteID]);

  const counts = useMemo(() => {
    const base = { up: 0, down: 0, unknown: 0 };
    for (const d of devices ?? []) base[pollStatus(d)] += 1;
    return base;
  }, [devices]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (devices ?? []).filter((d) => {
      if (statusFilter !== "all" && pollStatus(d) !== statusFilter) return false;
      if (needle === "") return true;
      return (
        d.name.toLowerCase().includes(needle) ||
        (d.mgmt_ip ?? "").toLowerCase().includes(needle) ||
        d.kind.toLowerCase().includes(needle)
      );
    });
  }, [devices, statusFilter, query]);

  const failing = useMemo(
    () =>
      (devices ?? [])
        .filter((d) => d.poll_status?.last_outcome === "failure")
        .sort((a, b) =>
          (b.poll_status?.last_checked_at ?? "").localeCompare(
            a.poll_status?.last_checked_at ?? "",
          ),
        ),
    [devices],
  );

  useEffect(() => {
    if (devices === null) return;
    setIssuesError("");
    const candidates = failing.slice(0, MAX_ISSUE_DEVICES);
    if (candidates.length === 0) {
      setIssues([]);
      return;
    }
    let cancelled = false;
    async function load() {
      const results = await Promise.all(
        candidates.map((d) =>
          fetchJSON<{ data?: PollHealthRecord[] }>(
            `/api/v1/devices/${d.id}/poll-health?limit=5`,
          ),
        ),
      );
      if (cancelled) return;
      const rows: Issue[] = [];
      results.forEach((res, index) => {
        const device = candidates[index];
        if (!res.ok) {
          setIssuesError(res.error);
          return;
        }
        for (const row of res.data.data ?? []) {
          if (row.outcome !== "failure") continue;
          rows.push({
            id: row.id,
            deviceID: device.id,
            deviceName: device.name,
            poll_type: row.poll_type,
            checked_at: row.checked_at,
            latency_ms: row.latency_ms,
            error_class: row.error_class,
            consecutive_failures: row.consecutive_failures,
          });
        }
      });
      rows.sort((a, b) => b.checked_at.localeCompare(a.checked_at));
      setIssues(rows.slice(0, MAX_ISSUES));
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [devices, failing]);

  return (
    <>
      <div className="stat-grid" data-testid="site-status-counts">
        {(["all", "up", "down", "unknown"] as const).map((key) => {
          const count = key === "all" ? (devices?.length ?? 0) : counts[key];
          const active = statusFilter === key;
          return (
            <button
              key={key}
              type="button"
              className={`stat-card ${active ? "stat-card-active" : ""}`}
              aria-pressed={active}
              data-testid={`site-status-filter-${key}`}
              onClick={() => setParam("status", key)}
            >
              <span className="metric-label">
                {key === "all" ? "devices" : key}
              </span>
              <span className="metric-value" data-testid={`site-count-${key}`}>
                {count}
              </span>
            </button>
          );
        })}
      </div>

      <section className="panel" style={{ marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>Recent issues</h2>
        {issuesError && (
          <p className="error" data-testid="site-issues-error">
            {issuesError}
          </p>
        )}
        {!issuesError && issues === null && (
          <p className="muted" data-testid="site-issues-loading">
            Loading recent failures…
          </p>
        )}
        {!issuesError && issues?.length === 0 && (
          <p className="muted" data-testid="site-issues-empty">
            No recent poll-health failures for {siteName} devices.
          </p>
        )}
        {!issuesError && issues && issues.length > 0 && (
          <table data-testid="site-issues-table">
            <thead>
              <tr>
                <th>Checked</th>
                <th>Device</th>
                <th>Type</th>
                <th>Error class</th>
                <th>Latency</th>
                <th>Failures</th>
              </tr>
            </thead>
            <tbody>
              {issues.map((issue) => (
                <tr key={issue.id}>
                  <td className="muted">{shortTime(issue.checked_at)}</td>
                  <td>
                    <Link href={`/devices/${issue.deviceID}`}>{issue.deviceName}</Link>
                  </td>
                  <td>{issue.poll_type}</td>
                  <td className="muted">{issue.error_class || "—"}</td>
                  <td>{formatLatency(issue.latency_ms)}</td>
                  <td>{issue.consecutive_failures}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {failing.length > MAX_ISSUE_DEVICES && (
          <p className="muted metric-foot">
            Showing failures from the {MAX_ISSUE_DEVICES} most recently failing
            devices (bounded).
          </p>
        )}
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>Devices</h2>
        <label htmlFor="site-device-search">Filter devices</label>
        <input
          id="site-device-search"
          value={query}
          onChange={(e) => setParam("q", e.target.value)}
          placeholder="name, IP or kind"
          data-testid="site-device-search"
        />
        {error && (
          <p className="error" data-testid="site-devices-error">
            {error}
          </p>
        )}
        {!error && devices === null && (
          <p className="muted" data-testid="site-devices-loading">
            Loading devices…
          </p>
        )}
        {!error && devices && devices.length === 0 && (
          <p className="muted" data-testid="site-devices-empty">
            No devices in this site yet.
          </p>
        )}
        {!error && devices && devices.length > 0 && filtered.length === 0 && (
          <p className="muted" data-testid="site-devices-nomatch">
            No devices match the current filters.
          </p>
        )}
        {!error && filtered.length > 0 && (
          <>
            <p className="muted" data-testid="site-device-count">
              {filtered.length} of {devices?.length ?? 0} devices
            </p>
            <table data-testid="site-devices-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Kind</th>
                  <th>Mgmt IP</th>
                  <th>Status</th>
                  <th>Last outcome</th>
                  <th>Last checked</th>
                  <th>Failures</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((d) => (
                  <tr key={d.id}>
                    <td>
                      <Link href={`/devices/${d.id}`}>{d.name}</Link>
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
                    <td className="muted">{d.mgmt_ip ?? "—"}</td>
                    <td>
                      <StatusChip status={pollStatus(d)} />
                    </td>
                    <td className="muted">
                      {d.poll_status?.last_outcome
                        ? `${d.poll_status.last_outcome}${d.poll_status.last_error_class ? ` (${d.poll_status.last_error_class})` : ""}`
                        : "—"}
                    </td>
                    <td className="muted">
                      {shortTime(d.poll_status?.last_checked_at)}
                    </td>
                    <td>{d.poll_status?.consecutive_failures ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {hasMore && (
              <p className="muted metric-foot" data-testid="site-devices-more">
                Showing the first 100 devices; pagination beyond one page is not
                wired into this v1 dashboard.
              </p>
            )}
          </>
        )}
      </section>
    </>
  );
}

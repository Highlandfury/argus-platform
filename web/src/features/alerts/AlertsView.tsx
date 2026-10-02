"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { fetchJSON } from "@/lib/api";
import Badge from "@/ui/Badge";
import Button from "@/ui/Button";
import EmptyState from "@/ui/EmptyState";
import ErrorState from "@/ui/ErrorState";
import Panel from "@/ui/Panel";
import Skeleton from "@/ui/Skeleton";

import {
  alertStateLabel,
  formatDuration,
  severityLabel,
  shortId,
  shortTime,
  suppressionLabel,
  suppressionTarget,
  valueSummary,
} from "./format";
import LiveIndicator from "./LiveIndicator";
import { useAlertStream } from "./stream";
import {
  ALERT_SEVERITIES,
  ALERT_STATES,
  alertStateBadgeVariant,
  severityBadgeVariant,
  type Alert,
  type AlertPage,
  type AlertRule,
  type AlertRulePage,
  type AlertStreamEvent,
  type DeviceRef,
  type SiteRef,
} from "./types";

const PAGE_LIMIT = 25;

// AlertStateBadge is the queue/detail state chip: canonical alert state word
// plus the suppression qualifier when the API reports one (maintenance /
// silence / storm). Text-first; color is secondary.
export function AlertStateBadge({
  state,
  suppressionReason,
  suppressionRef,
  testId,
}: {
  state: string;
  suppressionReason?: string;
  suppressionRef?: string | null;
  testId?: string;
}) {
  return (
    <span className="alert-state-badges" data-testid={testId}>
      <Badge variant={alertStateBadgeVariant(state)} dot>
        {alertStateLabel(state)}
      </Badge>
      {suppressionReason !== "" && suppressionReason !== undefined && (
        <Badge
          variant={
            suppressionReason === "maintenance" || suppressionReason === "silence"
              ? "maintenance"
              : "unknown"
          }
          title={`Suppressed by ${suppressionTarget(suppressionReason, suppressionRef)}`}
        >
          {suppressionLabel(suppressionReason)}
        </Badge>
      )}
    </span>
  );
}

export function SeverityBadge({
  severity,
  testId,
}: {
  severity: string;
  testId?: string;
}) {
  return (
    <Badge variant={severityBadgeVariant(severity)} testId={testId}>
      {severityLabel(severity)}
    </Badge>
  );
}

function applyStreamPatch(row: Alert, event: AlertStreamEvent): Alert {
  return {
    ...row,
    state: event.state ?? row.state,
    severity: event.severity ?? row.severity,
    suppression_reason: event.suppression_reason ?? row.suppression_reason,
    suppression_ref: event.suppression_reason
      ? (event.suppression_ref ?? null)
      : null,
    last_evaluated_at: event.occurred_at ?? row.last_evaluated_at,
  };
}

// AlertsView is the M11-S3b /alerts queue: the real M11-S1 alert list with
// server-side filters (state/severity/rule/device — the exact API parameters),
// cursor paging, explicit loading/empty/error states, and a live SSE
// connection (M11-S3a) that patches visible rows and refreshes the head when a
// new matching alert appears. When the stream is unavailable the view says so
// and keeps manual refresh.
export default function AlertsView() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  // Last URL applied through setParam (intent), so rapid filter changes compose
  // even while router.replace has not committed the previous one.
  const appliedSearchRef = useRef<string | null>(null);
  const stateFilter = searchParams.get("state") ?? "";
  const severityFilter = searchParams.get("severity") ?? "";
  const ruleFilter = searchParams.get("rule") ?? "";
  const deviceFilter = searchParams.get("device") ?? "";

  const [rows, setRows] = useState<Alert[] | null>(null);
  const [nextCursor, setNextCursor] = useState("");
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [pendingLive, setPendingLive] = useState(0);

  const [rules, setRules] = useState<AlertRule[] | null>(null);
  const [rulesFailed, setRulesFailed] = useState(false);
  const [devices, setDevices] = useState<DeviceRef[] | null>(null);
  const [devicesFailed, setDevicesFailed] = useState(false);
  const [sites, setSites] = useState<SiteRef[]>([]);

  const rowsRef = useRef<Alert[] | null>(null);
  const pagesRef = useRef(1);
  const refreshTimerRef = useRef<number | null>(null);

  function setParam(key: string, value: string) {
    const base =
      appliedSearchRef.current !== null
        ? `?${appliedSearchRef.current}`
        : typeof window !== "undefined"
          ? window.location.search
          : `?${searchParams.toString()}`;
    const params = new URLSearchParams(base);
    if (value === "") params.delete(key);
    else params.set(key, value);
    const qs = params.toString();
    appliedSearchRef.current = qs;
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }

  function clearFilters() {
    const base =
      typeof window !== "undefined"
        ? window.location.search
        : `?${searchParams.toString()}`;
    const params = new URLSearchParams(base);
    for (const key of ["state", "severity", "rule", "device"]) {
      params.delete(key);
    }
    const qs = params.toString();
    appliedSearchRef.current = qs;
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }

  useEffect(() => {
    appliedSearchRef.current = searchParams.toString();
  }, [searchParams]);

  useEffect(() => {
    pagesRef.current = 1;
  }, [stateFilter, severityFilter, ruleFilter, deviceFilter]);

  const load = useCallback(
    async (silent = false) => {
      if (!silent) {
        setRows(null);
        setError("");
        setPendingLive(0);
      }
      const params = new URLSearchParams({ limit: String(PAGE_LIMIT) });
      if (stateFilter !== "") params.set("filter[state]", stateFilter);
      if (severityFilter !== "") params.set("filter[severity]", severityFilter);
      if (ruleFilter !== "") params.set("filter[rule_id]", ruleFilter);
      if (deviceFilter !== "") params.set("filter[device_id]", deviceFilter);
      const res = await fetchJSON<AlertPage>(`/api/v1/alerts?${params.toString()}`);
      if (res.ok) {
        setRows(res.data.data ?? []);
        setNextCursor(res.data.next_cursor ?? "");
        setHasMore(res.data.has_more ?? false);
        setError("");
        setPendingLive(0);
      } else {
        setError(res.error);
      }
    },
    [stateFilter, severityFilter, ruleFilter, deviceFilter],
  );

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    rowsRef.current = rows;
  }, [rows]);

  // Auxiliary picker data. A failed fetch leaves the filter as a text input
  // (UUID) instead of a dead end; nothing is fabricated.
  useEffect(() => {
    let cancelled = false;
    async function loadRules() {
      const res = await fetchJSON<AlertRulePage>("/api/v1/alert-rules?limit=100");
      if (cancelled) return;
      if (res.ok) setRules(res.data.data ?? []);
      else setRulesFailed(true);
    }
    async function loadDevices() {
      const [devicesRes, sitesRes] = await Promise.all([
        fetchJSON<{ data?: DeviceRef[] }>(
          "/api/v1/devices?limit=100&order=desc",
        ),
        fetchJSON<{ data?: SiteRef[] }>("/api/v1/sites?limit=100"),
      ]);
      if (cancelled) return;
      if (devicesRes.ok) setDevices(devicesRes.data.data ?? []);
      else setDevicesFailed(true);
      if (sitesRes.ok) setSites(sitesRes.data.data ?? []);
    }
    void loadRules();
    void loadDevices();
    return () => {
      cancelled = true;
    };
  }, []);

  const siteNames = useMemo(
    () => new Map(sites.map((s) => [s.id, s.name])),
    [sites],
  );
  const deviceById = useMemo(
    () => new Map((devices ?? []).map((d) => [d.id, d])),
    [devices],
  );
  const ruleById = useMemo(
    () => new Map((rules ?? []).map((r) => [r.rule_id, r])),
    [rules],
  );

  // SSE: patch visible rows in place when their state/severity/suppression
  // transitioned; remove rows that no longer match the active state filter;
  // refresh the first page when a new matching alert appears (collapsing extra
  // pages is avoided by offering an explicit refresh chip instead).
  const handleStreamEvent = useCallback(
    (event: AlertStreamEvent) => {
      const current = rowsRef.current;
      if (current === null) return;
      const visible = current.some((row) => row.id === event.alert_id);
      if (visible) {
        if (stateFilter !== "" && event.state !== undefined && event.state !== stateFilter) {
          setRows((rs) => (rs ?? []).filter((row) => row.id !== event.alert_id));
          return;
        }
        setRows((rs) =>
          (rs ?? []).map((row) =>
            row.id === event.alert_id ? applyStreamPatch(row, event) : row,
          ),
        );
        return;
      }
      if (stateFilter !== "" && event.state !== undefined && event.state !== stateFilter) {
        return;
      }
      if (severityFilter !== "" && event.severity && event.severity !== severityFilter) {
        return;
      }
      if (ruleFilter !== "" && event.rule_id && event.rule_id !== ruleFilter) {
        return;
      }
      if (deviceFilter !== "" && event.resource_id && event.resource_id !== deviceFilter) {
        return;
      }
      if (pagesRef.current > 1) {
        setPendingLive((n) => n + 1);
        return;
      }
      if (refreshTimerRef.current !== null) return;
      refreshTimerRef.current = window.setTimeout(() => {
        refreshTimerRef.current = null;
        void load(true);
      }, 400);
    },
    [stateFilter, severityFilter, ruleFilter, deviceFilter, load],
  );

  const live = useAlertStream(handleStreamEvent);

  useEffect(
    () => () => {
      if (refreshTimerRef.current !== null) {
        window.clearTimeout(refreshTimerRef.current);
      }
    },
    [],
  );

  async function loadMore() {
    if (nextCursor === "" || loadingMore) return;
    setLoadingMore(true);
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_LIMIT),
        cursor: nextCursor,
      });
      if (stateFilter !== "") params.set("filter[state]", stateFilter);
      if (severityFilter !== "") params.set("filter[severity]", severityFilter);
      if (ruleFilter !== "") params.set("filter[rule_id]", ruleFilter);
      if (deviceFilter !== "") params.set("filter[device_id]", deviceFilter);
      const res = await fetchJSON<AlertPage>(
        `/api/v1/alerts?${params.toString()}`,
      );
      if (res.ok) {
        setRows((rs) => [...(rs ?? []), ...(res.data.data ?? [])]);
        setNextCursor(res.data.next_cursor ?? "");
        setHasMore(res.data.has_more ?? false);
        pagesRef.current += 1;
      } else {
        setError(res.error);
      }
    } finally {
      setLoadingMore(false);
    }
  }

  async function refresh() {
    setRefreshing(true);
    try {
      await load(true);
    } finally {
      setRefreshing(false);
    }
  }

  function stopRowNav(event: React.MouseEvent | React.KeyboardEvent) {
    event.stopPropagation();
  }

  function deviceCell(alert: Alert) {
    const device = deviceById.get(alert.resource_id);
    const site = device ? siteNames.get(device.site_id) : undefined;
    return (
      <>
        <a
          href={`/devices/${alert.resource_id}`}
          data-testid={`alert-device-${alert.id}`}
          onClick={stopRowNav}
        >
          {device?.name ?? shortId(alert.resource_id)}
        </a>
        {site && <div className="muted alert-subtext">{site}</div>}
      </>
    );
  }

  function ruleCell(alert: Alert) {
    const rule = ruleById.get(alert.rule_id);
    return (
      <a
        href={`/alerts?rule=${alert.rule_id}`}
        data-testid={`alert-rule-${alert.id}`}
        title="Show alerts from this rule"
        onClick={stopRowNav}
      >
        {rule?.name ?? shortId(alert.rule_id)}
        <span className="muted"> v{alert.rule_version}</span>
      </a>
    );
  }

  const hasFilters =
    stateFilter !== "" ||
    severityFilter !== "" ||
    ruleFilter !== "" ||
    deviceFilter !== "";

  const filters = (
    <div
      className="filter-row"
      style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}
      data-testid="alerts-filters"
    >
      <div>
        <label htmlFor="alerts-filter-state">State</label>
        <select
          id="alerts-filter-state"
          value={stateFilter}
          onChange={(e) => setParam("state", e.target.value)}
          data-testid="alerts-filter-state"
          style={{ width: "auto" }}
        >
          <option value="">All states</option>
          {ALERT_STATES.map((state) => (
            <option key={state} value={state}>
              {alertStateLabel(state)}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor="alerts-filter-severity">Severity</label>
        <select
          id="alerts-filter-severity"
          value={severityFilter}
          onChange={(e) => setParam("severity", e.target.value)}
          data-testid="alerts-filter-severity"
          style={{ width: "auto" }}
        >
          <option value="">All severities</option>
          {ALERT_SEVERITIES.map((severity) => (
            <option key={severity} value={severity}>
              {severityLabel(severity)}
            </option>
          ))}
        </select>
      </div>
      <div>
        <label htmlFor="alerts-filter-rule">Rule</label>
        {rules !== null ? (
          <select
            id="alerts-filter-rule"
            value={ruleFilter}
            onChange={(e) => setParam("rule", e.target.value)}
            data-testid="alerts-filter-rule"
            style={{ width: "auto", maxWidth: 260 }}
          >
            <option value="">All rules</option>
            {rules.map((rule) => (
              <option key={rule.rule_id} value={rule.rule_id}>
                {rule.name}
                {rule.enabled ? "" : " (disabled)"}
              </option>
            ))}
          </select>
        ) : rulesFailed ? (
          <input
            id="alerts-filter-rule"
            defaultValue={ruleFilter}
            placeholder="Rule UUID, Enter"
            data-testid="alerts-filter-rule"
            style={{ width: 240 }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                setParam("rule", (e.target as HTMLInputElement).value.trim());
              }
            }}
            onBlur={(e) => setParam("rule", e.target.value.trim())}
          />
        ) : (
          <select
            id="alerts-filter-rule"
            disabled
            data-testid="alerts-filter-rule"
            style={{ width: "auto" }}
          >
            <option value="">Loading rules…</option>
          </select>
        )}
      </div>
      <div>
        <label htmlFor="alerts-filter-device">Device</label>
        {devices !== null ? (
          <select
            id="alerts-filter-device"
            value={deviceFilter}
            onChange={(e) => setParam("device", e.target.value)}
            data-testid="alerts-filter-device"
            style={{ width: "auto", maxWidth: 280 }}
          >
            <option value="">All devices</option>
            {groupDevicesBySite(devices, siteNames).map((group) => (
              <optgroup
                key={group.siteID || "unassigned"}
                label={group.siteName}
              >
                {group.devices.map((device) => (
                  <option key={device.id} value={device.id}>
                    {device.name}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
        ) : devicesFailed ? (
          <input
            id="alerts-filter-device"
            defaultValue={deviceFilter}
            placeholder="Device UUID, Enter"
            data-testid="alerts-filter-device"
            style={{ width: 240 }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                setParam("device", (e.target as HTMLInputElement).value.trim());
              }
            }}
            onBlur={(e) => setParam("device", e.target.value.trim())}
          />
        ) : (
          <select
            id="alerts-filter-device"
            disabled
            data-testid="alerts-filter-device"
            style={{ width: "auto" }}
          >
            <option value="">Loading devices…</option>
          </select>
        )}
      </div>
      {hasFilters && (
        <Button
          variant="ghost"
          size="sm"
          onClick={clearFilters}
          data-testid="alerts-clear-filters"
        >
          Clear filters
        </Button>
      )}
    </div>
  );

  return (
    <section data-testid="alerts-view">
      <Panel
        title="Alert queue"
        subtitle="Newest onset first, cursor-paged. Filters are URL-driven and shareable; the list is scope-filtered by the caller's site bindings server-side."
        actions={
          <>
            <LiveIndicator status={live} testId="alerts-sse-status" />
            <Button
              size="sm"
              variant="secondary"
              onClick={() => void refresh()}
              disabled={refreshing}
              data-testid="alerts-refresh"
            >
              {refreshing ? "Refreshing…" : "Refresh"}
            </Button>
          </>
        }
        testId="alerts-panel"
      >
        {filters}
        <p className="muted alert-note" data-testid="alerts-filter-note">
          Server filters: state, severity, rule and device (the API&apos;s
          <code>filter[...]</code> parameters). Free-text search and time-range
          filters are not exposed by the alerts API yet and are deliberately not
          faked; devices are grouped by site.
        </p>

        {error !== "" && rows === null && (
          <ErrorState
            title="Alerts unavailable"
            message={error}
            action={
              <Button size="sm" variant="secondary" onClick={() => void load()}>
                Try again
              </Button>
            }
            testId="alerts-error"
          />
        )}
        {error !== "" && rows !== null && (
          <p className="error" data-testid="alerts-error-inline">
            {error}
          </p>
        )}

        {rows === null && error === "" && (
          <div data-testid="alerts-loading" aria-busy="true">
            <Skeleton height={14} />
            <div style={{ height: 8 }} />
            <Skeleton height={14} width="92%" />
            <div style={{ height: 8 }} />
            <Skeleton height={14} width="78%" />
          </div>
        )}

        {rows !== null && rows.length === 0 && error === "" && (
          <EmptyState
            title="No alerts match the current filters"
            description={
              hasFilters
                ? "Nothing matches these filters right now. Clear a filter to widen the queue."
                : "No alerts are recorded for this organization yet. Alerts appear when a rule's condition stays true for its for_duration (M11-S1)."
            }
            testId="alerts-empty"
          />
        )}

        {rows !== null && rows.length > 0 && error === "" && (
          <>
            <div className="alert-table-wrap">
              <table data-testid="alerts-table">
                <thead>
                  <tr>
                    <th>Summary</th>
                    <th>State</th>
                    <th>Severity</th>
                    <th>Resource</th>
                    <th>Rule</th>
                    <th>Started</th>
                    <th>Age</th>
                    <th>Ack</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((alert) => (
                    <tr
                      key={alert.id}
                      className="alert-row"
                      tabIndex={0}
                      data-testid={`alerts-row-${alert.id}`}
                      data-state={alert.state}
                      data-severity={alert.severity}
                      data-device-id={alert.resource_id}
                      onClick={() => router.push(`/alerts/${alert.id}`)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") router.push(`/alerts/${alert.id}`);
                      }}
                    >
                      <td>
                        <a
                          href={`/alerts/${alert.id}`}
                          className="alert-summary"
                          data-testid={`alert-link-${alert.id}`}
                          onClick={stopRowNav}
                        >
                          {valueSummary(alert.value)}
                        </a>
                        {alert.dimension_subset &&
                          Object.keys(alert.dimension_subset).length > 0 && (
                            <div className="muted alert-subtext">
                              {Object.entries(alert.dimension_subset)
                                .map(([k, v]) => `${k}=${String(v)}`)
                                .join(" · ")}
                            </div>
                          )}
                      </td>
                      <td>
                        <AlertStateBadge
                          state={alert.state}
                          suppressionReason={alert.suppression_reason}
                          suppressionRef={alert.suppression_ref}
                          testId={`alert-state-${alert.id}`}
                        />
                      </td>
                      <td>
                        <SeverityBadge
                          severity={alert.severity}
                          testId={`alert-severity-${alert.id}`}
                        />
                      </td>
                      <td>{deviceCell(alert)}</td>
                      <td>{ruleCell(alert)}</td>
                      <td className="muted" title={shortTime(alert.started_at)}>
                        {shortTime(alert.started_at)}
                      </td>
                      <td
                        className="muted"
                        title={`Started ${shortTime(alert.started_at)}`}
                      >
                        {formatDuration(alert.started_at, alert.resolved_at ?? undefined)}
                      </td>
                      <td
                        className="muted"
                        data-testid={`alert-ack-${alert.id}`}
                        title={alert.ack_by ? `By ${alert.ack_by}` : undefined}
                      >
                        {alert.ack_at
                          ? shortTime(alert.ack_at)
                          : alert.state === "acknowledged"
                            ? "Acknowledged"
                            : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="btn-row" style={{ marginTop: 12 }}>
              {hasMore && (
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={loadingMore}
                  onClick={() => void loadMore()}
                  data-testid="alerts-load-more"
                >
                  {loadingMore ? "Loading…" : "Load more"}
                </Button>
              )}
              {pendingLive > 0 && (
                <Button
                  size="sm"
                  variant="primary"
                  onClick={() => void refresh()}
                  data-testid="alerts-new-events"
                >
                  {pendingLive} new update{pendingLive === 1 ? "" : "s"} — Refresh
                </Button>
              )}
            </div>
          </>
        )}
      </Panel>
    </section>
  );
}

function groupDevicesBySite(
  devices: DeviceRef[],
  siteNames: Map<string, string>,
): { siteID: string; siteName: string; devices: DeviceRef[] }[] {
  const groups = new Map<string, DeviceRef[]>();
  for (const device of devices) {
    const list = groups.get(device.site_id) ?? [];
    list.push(device);
    groups.set(device.site_id, list);
  }
  return [...groups.entries()].map(([siteID, groupDevices]) => ({
    siteID,
    siteName: siteNames.get(siteID) ?? "Unassigned / other site",
    devices: groupDevices,
  }));
}

"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";

import { fetchJSON, problemDetail, readCSRF } from "@/lib/api";

import AvailabilityRibbon from "./AvailabilityRibbon";
import CheckRunner from "./CheckRunner";
import DeviceAdminPanel from "./DeviceAdminPanel";
import DeviceCredentialPanel from "./DeviceCredentialPanel";
import DeviceInterfacePanel from "./DeviceInterfacePanel";
import DeviceMergePanel from "./DeviceMergePanel";
import StatusChip from "./StatusChip";
import TimeSeriesChart, {
  type ChartMeta,
  type ChartSeries,
} from "./TimeSeriesChart";
import { formatLatency, shortTime } from "./format";

// DeviceDetail is the M10-S3 device visibility page: live poll-health status,
// identity + identity history, live interfaces, ICMP availability/RTT/loss
// charts (canonical /v1/metrics/query), poll-health history and the M10-S0
// on-demand check runner. All data comes from the real APIs; every panel has
// its own loading/empty/error state.
export interface Device {
  id: string;
  site_id: string;
  name: string;
  kind: string;
  status: string;
  critical: boolean;
  mgmt_ip: string | null;
  serial: string | null;
  sys_object_id: string | null;
  firmware: string | null;
  poll_profile: string;
  confidence: number;
  first_seen_at: string;
  last_seen_at: string | null;
  updated_at: string;
}

export interface DeviceStatus {
  device_id: string;
  status: "up" | "down" | "unknown";
  since: string | null;
  last_outcome: string | null;
  last_error_class: string | null;
  last_latency_ms: number | null;
  consecutive_failures: number | null;
  last_checked_at: string | null;
  down_threshold: number;
  freshness_seconds: number;
}

interface IdentityRecord {
  id: string;
  identifier_type: string;
  identifier_value: string;
  source: string;
  first_seen_at: string;
  last_seen_at: string | null;
}

interface ProblemFieldError {
  field?: string;
  code?: string;
  message?: string;
}

// Server-allowed identity types (device_identity_history CHECK; M10-S3b-1 add
// endpoint). Values are canonicalized server-side (MAC case, management IP).
const IDENTITY_TYPES = [
  "serial",
  "chassis_id",
  "sys_object_id",
  "mac",
  "hostname",
  "mgmt_ip",
];

interface PollHealthRecord {
  id: string;
  poll_type: string;
  checked_at: string;
  latency_ms: number;
  outcome: string;
  error_class: string;
  consecutive_failures: number;
  origin: "scheduled" | "on_demand";
}

interface MatrixSeries {
  id: string;
  metric_key: string;
  unit: string;
  dimensions: Record<string, string>;
  labels: Record<string, string>;
  points: [number, number | null][];
}

interface MatrixMeta {
  resolution: string;
  partial: boolean;
  raw_fallback: boolean;
  series_returned: number;
  expected_points: number;
  returned_points: number;
  resolution_warning?: string;
  quality: { gaps: number; dropped_samples: number };
}

interface MatrixResponse {
  series: MatrixSeries[];
  meta: MatrixMeta;
}

type RangeKey = "1h" | "6h" | "24h" | "7d";

const RANGES: { key: RangeKey; label: string; windowMs: number }[] = [
  { key: "1h", label: "1h", windowMs: 60 * 60_000 },
  { key: "6h", label: "6h", windowMs: 6 * 60 * 60_000 },
  { key: "24h", label: "24h", windowMs: 24 * 60 * 60_000 },
  { key: "7d", label: "7d", windowMs: 7 * 24 * 60 * 60_000 },
];

const STATUS_POLL_MS = 30_000;

function baseName(labels: Record<string, string>, metricKey: string): string {
  const dims = Object.keys(labels).filter(
    (k) => !["metric", "unit", "device"].includes(k),
  );
  if (dims.length === 0) return metricKey;
  return `${metricKey} (${dims.map((k) => `${k}=${labels[k]}`).join(", ")})`;
}

function toChartSeries(rows: MatrixSeries[], fallbackUnit: string): ChartSeries[] {
  return rows.map((row) => ({
    id: row.id,
    name: baseName(row.labels, row.metric_key),
    unit: row.unit || fallbackUnit,
    points: row.points.map(([t, v]) => ({ t, v })),
  }));
}

export default function DeviceDetail({
  device,
  siteName,
  role,
}: {
  device: Device;
  siteName: string | null;
  role: string;
}) {
  // current mirrors the server-resolved device and is updated in place after a
  // successful edit (M10-S3a), so the header reflects the change immediately;
  // router.refresh() then re-syncs the server data.
  const [current, setCurrent] = useState<Device>(device);
  useEffect(() => {
    setCurrent(device);
  }, [device]);
  const [status, setStatus] = useState<DeviceStatus | null>(null);
  const [statusError, setStatusError] = useState("");
  const [identity, setIdentity] = useState<IdentityRecord[] | null>(null);
  const [identityError, setIdentityError] = useState("");
  const [identityActionError, setIdentityActionError] = useState("");
  const [identityFieldErrors, setIdentityFieldErrors] = useState<
    ProblemFieldError[]
  >([]);
  const [identityMessage, setIdentityMessage] = useState("");
  const [identityType, setIdentityType] = useState("mac");
  const [identityValue, setIdentityValue] = useState("");
  const [identityBusy, setIdentityBusy] = useState(false);
  const [closingIdentityID, setClosingIdentityID] = useState<string | null>(
    null,
  );
  // Bumped after a merge so the interface panel refetches the re-pointed rows.
  const [interfacesKey, setInterfacesKey] = useState(0);
  // M10-S3b-2 split: open identity rows selected for detachment + new name.
  const [splitSelectedIDs, setSplitSelectedIDs] = useState<string[]>([]);
  const [splitName, setSplitName] = useState("");
  const [splitBusy, setSplitBusy] = useState(false);
  const [splitError, setSplitError] = useState("");
  const [splitFieldErrors, setSplitFieldErrors] = useState<
    ProblemFieldError[]
  >([]);
  const [splitMessage, setSplitMessage] = useState("");
  const [splitCreatedID, setSplitCreatedID] = useState<string | null>(null);
  const [health, setHealth] = useState<PollHealthRecord[] | null>(null);
  const [healthError, setHealthError] = useState("");
  const [rangeKey, setRangeKey] = useState<RangeKey>("6h");
  const [matrix, setMatrix] = useState<MatrixResponse | null>(null);
  const [chartsLoading, setChartsLoading] = useState(true);
  const [chartsError, setChartsError] = useState("");
  const router = useRouter();

  const loadStatus = useCallback(async () => {
    const res = await fetchJSON<DeviceStatus>(
      `/api/v1/devices/${device.id}/status`,
    );
    if (res.ok) {
      setStatus(res.data);
      setStatusError("");
    } else {
      setStatusError(res.error);
    }
  }, [device.id]);

  const loadTables = useCallback(async () => {
    const [identityRes, healthRes] = await Promise.all([
      fetchJSON<{ data?: IdentityRecord[] }>(
        `/api/v1/devices/${device.id}/identity-history?limit=50`,
      ),
      fetchJSON<{ data?: PollHealthRecord[] }>(
        `/api/v1/devices/${device.id}/poll-health?limit=25`,
      ),
    ]);
    if (identityRes.ok) {
      setIdentity(identityRes.data.data ?? []);
      setIdentityError("");
    } else {
      setIdentityError(identityRes.error);
    }
    if (healthRes.ok) {
      setHealth(healthRes.data.data ?? []);
      setHealthError("");
    } else {
      setHealthError(healthRes.error);
    }
  }, [device.id]);

  // M10-S3b-1: open/close identity-history windows. Both mutations carry the
  // session + CSRF pair, render problem+json (including indexed field errors
  // for the add form), and refresh the identity table from the server.
  async function addIdentity(e: React.FormEvent) {
    e.preventDefault();
    setIdentityActionError("");
    setIdentityMessage("");
    setIdentityFieldErrors([]);
    if (identityValue.trim() === "") {
      setIdentityActionError("identity value is required");
      return;
    }
    setIdentityBusy(true);
    try {
      const res = await fetch(`/api/v1/devices/${device.id}/identities`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify({ type: identityType, value: identityValue.trim() }),
      });
      if (!res.ok) {
        const problem = (await res.json().catch(() => null)) as {
          detail?: string;
          errors?: ProblemFieldError[];
        } | null;
        setIdentityFieldErrors(
          Array.isArray(problem?.errors) ? problem.errors : [],
        );
        setIdentityActionError(
          problem?.detail ?? `identity add failed (status ${res.status})`,
        );
        return;
      }
      setIdentityMessage(`Identity ${identityType} added.`);
      setIdentityValue("");
      await loadTables();
    } catch {
      setIdentityActionError("network error");
    } finally {
      setIdentityBusy(false);
    }
  }

  async function closeIdentity(row: IdentityRecord) {
    setIdentityActionError("");
    setIdentityMessage("");
    setIdentityFieldErrors([]);
    setClosingIdentityID(row.id);
    try {
      const res = await fetch(
        `/api/v1/devices/${device.id}/identities/${row.id}/close`,
        {
          method: "POST",
          headers: { "X-CSRF-Token": readCSRF() },
        },
      );
      if (!res.ok) {
        setIdentityActionError(
          await problemDetail(res, `identity close failed (status ${res.status})`),
        );
        return;
      }
      setIdentityMessage(
        `Identity ${row.identifier_type} ${row.identifier_value} closed.`,
      );
      await loadTables();
    } catch {
      setIdentityActionError("network error");
    } finally {
      setClosingIdentityID(null);
    }
  }

  const loadCharts = useCallback(
    async (key: RangeKey) => {
      const range = RANGES.find((r) => r.key === key) ?? RANGES[1];
      const to = new Date();
      const from = new Date(to.getTime() - range.windowMs);
      setChartsLoading(true);
      const body = {
        series: [
          { device_id: device.id, metric_key: "net.icmp.reachable" },
          { device_id: device.id, metric_key: "net.icmp.rtt_ms" },
          { device_id: device.id, metric_key: "net.icmp.loss_pct" },
        ],
        from: from.toISOString(),
        to: to.toISOString(),
        step: "auto",
        agg: "avg",
        fill: "null",
      };
      const res = await fetchJSON<MatrixResponse>("/api/v1/metrics/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (res.ok) {
        setMatrix(res.data);
        setChartsError("");
      } else {
        setChartsError(res.error);
      }
      setChartsLoading(false);
    },
    [device.id],
  );

  useEffect(() => {
    void loadStatus();
    const timer = setInterval(() => void loadStatus(), STATUS_POLL_MS);
    return () => clearInterval(timer);
  }, [loadStatus]);

  useEffect(() => {
    void loadTables();
  }, [loadTables]);

  useEffect(() => {
    void loadCharts(rangeKey);
  }, [loadCharts, rangeKey]);

  const chartMeta: ChartMeta | null = useMemo(() => {
    if (!matrix) return null;
    return {
      resolution: matrix.meta.resolution,
      gaps: matrix.meta.quality?.gaps ?? 0,
      returned_points: matrix.meta.returned_points ?? 0,
      expected_points: matrix.meta.expected_points ?? 0,
      series_returned: matrix.meta.series_returned ?? 0,
      partial: matrix.meta.partial ?? false,
      raw_fallback: matrix.meta.raw_fallback ?? false,
      resolution_warning: matrix.meta.resolution_warning,
    };
  }, [matrix]);

  const reachable = matrix?.series.find(
    (s) => s.metric_key === "net.icmp.reachable",
  );
  const ribbonPoints =
    reachable?.points.map(([t, v]) => ({ t, v })) ?? [];

  const rttSeries = useMemo(
    () => toChartSeries(matrix?.series.filter((s) => s.metric_key === "net.icmp.rtt_ms") ?? [], "ms"),
    [matrix],
  );
  const lossSeries = useMemo(
    () =>
      toChartSeries(
        matrix?.series.filter((s) => s.metric_key === "net.icmp.loss_pct") ?? [],
        "percent",
      ),
    [matrix],
  );
  const icmpChartSeries = useMemo<ChartSeries[]>(() => {
    const rtt = rttSeries.map((s) => ({ ...s, yAxisIndex: 0 }));
    const loss = lossSeries.map((s) => ({ ...s, yAxisIndex: 1 }));
    return [...rtt, ...loss];
  }, [rttSeries, lossSeries]);

  const onDemand = (health ?? [])
    .filter((h) => h.origin === "on_demand")
    .slice(0, 5);

  // M10-S3b-2 split: only open identity windows can be detached; the API
  // re-points the selected rows to a newly created device and derives its
  // serial/sysObjectID/mgmt IP from the open windows (splitRequest).
  function toggleSplitRow(rowID: string, checked: boolean) {
    setSplitError("");
    setSplitMessage("");
    setSplitCreatedID(null);
    setSplitSelectedIDs((ids) =>
      checked ? [...ids, rowID] : ids.filter((id) => id !== rowID),
    );
  }

  async function splitDevice(e: React.FormEvent) {
    e.preventDefault();
    setSplitError("");
    setSplitMessage("");
    setSplitCreatedID(null);
    setSplitFieldErrors([]);
    if (splitSelectedIDs.length === 0) {
      setSplitError("select at least one open identity window");
      return;
    }
    if (splitName.trim() === "") {
      setSplitError("new device name is required");
      return;
    }
    setSplitBusy(true);
    try {
      const res = await fetch(`/api/v1/devices/${device.id}/split`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify({
          identity_history_ids: splitSelectedIDs,
          name: splitName.trim(),
        }),
      });
      if (!res.ok) {
        const problem = (await res.json().catch(() => null)) as {
          detail?: string;
          errors?: ProblemFieldError[];
        } | null;
        setSplitFieldErrors(
          Array.isArray(problem?.errors) ? problem.errors : [],
        );
        setSplitError(problem?.detail ?? `split failed (status ${res.status})`);
        return;
      }
      const created = (await res.json()) as Device;
      setSplitMessage(
        `Split ${splitSelectedIDs.length} identity window(s) into ${created.name}.`,
      );
      setSplitCreatedID(created.id);
      setSplitSelectedIDs([]);
      setSplitName("");
      await loadTables();
      router.refresh();
    } catch {
      setSplitError("network error");
    } finally {
      setSplitBusy(false);
    }
  }

  // A merge re-points identity history and interfaces into this device and
  // soft-deletes the sources: refresh both tables and the server-rendered
  // shell, then drop the router cache for this route.
  function handleMerged() {
    void loadTables();
    setInterfacesKey((k) => k + 1);
    router.refresh();
  }

  return (
    <>
      <section className="panel" data-testid="device-header">
        <div className="detail-head">
          <h1 style={{ margin: 0 }}>
            {current.name}{" "}
            {current.critical && (
              <span
                className="status status-stale"
                data-testid="device-critical"
                title="Critical device (5-minute failure backoff ceiling)"
              >
                critical
              </span>
            )}
          </h1>
          <StatusChip
            status={status?.status ?? "unknown"}
            testId="device-status-chip"
            title="Poll-health rollup from scheduled checks"
          />
        </div>
        <p className="muted" style={{ marginTop: 8 }}>
          {current.kind} ·{" "}
          {siteName ? (
            <Link href={`/sites/${current.site_id}`}>{siteName}</Link>
          ) : (
            current.site_id
          )}{" "}
          · mgmt IP {current.mgmt_ip ?? "—"} · inventory status{" "}
          {current.status} · poll profile {current.poll_profile}
        </p>
        {statusError ? (
          <p className="error" data-testid="device-status-error">
            {statusError}
          </p>
        ) : (
          <ul className="kv" data-testid="device-status-detail">
            <li>
              last check: <span data-testid="device-last-checked">{shortTime(status?.last_checked_at)}</span>
            </li>
            <li>
              last outcome:{" "}
              <span data-testid="device-last-outcome">
                {status?.last_outcome
                  ? `${status.last_outcome}${status.last_error_class ? ` (${status.last_error_class})` : ""}`
                  : "—"}
              </span>
            </li>
            <li>
              latency: <span data-testid="device-last-latency">{formatLatency(status?.last_latency_ms)}</span>
            </li>
            <li>
              consecutive failures:{" "}
              <span data-testid="device-consecutive-failures">
                {status?.consecutive_failures ?? "—"} / {status?.down_threshold ?? 3}
              </span>
            </li>
            <li>
              since: <span data-testid="device-status-since">{shortTime(status?.since)}</span>
            </li>
            <li className="muted">
              unknown after {Math.round((status?.freshness_seconds ?? 1200) / 60)} min
              without scheduled health
            </li>
          </ul>
        )}
        <div style={{ marginTop: 12 }}>
          <DeviceAdminPanel
            device={current}
            canWrite={role === "admin"}
            onUpdated={setCurrent}
          />
        </div>
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>Identity</h2>
        {identityError && <p className="error" data-testid="device-identity-error">{identityError}</p>}
        {!identityError && identity === null && <p className="muted">Loading identity…</p>}
        {!identityError && identity?.length === 0 && (
          <p className="muted" data-testid="device-identity-empty">
            No identity records yet.
          </p>
        )}
        {!identityError && identity && identity.length > 0 && (
          <table data-testid="device-identity-table">
            <thead>
              <tr>
                {role === "admin" && <th />}
                <th>Type</th>
                <th>Value</th>
                <th>Source</th>
                <th>First seen</th>
                <th>Last seen</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {identity.map((row) => (
                <tr key={row.id}>
                  {role === "admin" && (
                    <td style={{ width: 36 }}>
                      {row.last_seen_at === null && (
                        <input
                          type="checkbox"
                          aria-label={`Select open identity ${row.identifier_type} ${row.identifier_value} for split`}
                          checked={splitSelectedIDs.includes(row.id)}
                          onChange={(e) =>
                            toggleSplitRow(row.id, e.target.checked)
                          }
                          data-testid={`device-identity-split-select-${row.identifier_value}`}
                          style={{ width: "auto" }}
                        />
                      )}
                    </td>
                  )}
                  <td>{row.identifier_type}</td>
                  <td className="muted">{row.identifier_value}</td>
                  <td>{row.source}</td>
                  <td className="muted">{shortTime(row.first_seen_at)}</td>
                  <td className="muted">
                    {row.last_seen_at ? shortTime(row.last_seen_at) : "open window"}
                  </td>
                  <td>
                    {row.last_seen_at === null && role === "admin" && (
                      <button
                        type="button"
                        className="btn-sm btn-ghost"
                        data-testid={`device-identity-close-${row.identifier_value}`}
                        disabled={closingIdentityID === row.id}
                        onClick={() => void closeIdentity(row)}
                      >
                        {closingIdentityID === row.id ? "Closing…" : "Close"}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!identityError && identity !== null && role === "admin" && (
          <form
            onSubmit={addIdentity}
            data-testid="device-identity-add-form"
            style={{ marginTop: 12 }}
          >
            <h3 className="vis-subhead">Add identity</h3>
            <p className="muted">
              Opens a new identity-history window (source=manual). Repeating an
              existing key on this device is a no-op; a key already open on
              another live device is rejected as a conflict.
            </p>
            <label htmlFor="device-identity-add-type">Type</label>
            <select
              id="device-identity-add-type"
              value={identityType}
              onChange={(e) => setIdentityType(e.target.value)}
              data-testid="device-identity-add-type"
            >
              {IDENTITY_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <label htmlFor="device-identity-add-value">Value</label>
            <input
              id="device-identity-add-value"
              value={identityValue}
              onChange={(e) => setIdentityValue(e.target.value)}
              placeholder={identityType === "mac" ? "aa:bb:cc:dd:ee:ff" : "value"}
              data-testid="device-identity-add-value"
            />
            <button
              type="submit"
              className="btn-sm"
              disabled={identityBusy}
              data-testid="device-identity-add-submit"
            >
              {identityBusy ? "Adding…" : "Add identity"}
            </button>
          </form>
        )}
        {!identityError && identity !== null && role === "admin" && (
          <form
            onSubmit={splitDevice}
            data-testid="device-split-form"
            style={{ marginTop: 12 }}
          >
            <h3 className="vis-subhead">Split to a new device</h3>
            <p className="muted">
              Tick the open identity windows above and name the new device.
              The selected windows move to the new device (which inherits the
              site and derives its serial / sysObjectID / management IP from
              them); closed history and interfaces stay here. The split is one
              transaction and never clones rows.
            </p>
            <label htmlFor="device-split-name">New device name</label>
            <input
              id="device-split-name"
              value={splitName}
              onChange={(e) => setSplitName(e.target.value)}
              placeholder="new device name"
              data-testid="device-split-name"
              maxLength={200}
            />
            <button
              type="submit"
              className="btn-sm"
              disabled={splitBusy}
              data-testid="device-split-submit"
            >
              {splitBusy
                ? "Splitting…"
                : `Split selected window(s) into a new device`}
            </button>
            {splitError && (
              <p className="error" data-testid="device-split-error">
                {splitError}
              </p>
            )}
            {splitFieldErrors.length > 0 && (
              <ul className="error" data-testid="device-split-field-errors">
                {splitFieldErrors.map((fe, i) => (
                  <li key={`${fe.field ?? "field"}-${i}`}>
                    {fe.field ? `${fe.field}: ` : ""}
                    {fe.message ?? "invalid value"}
                  </li>
                ))}
              </ul>
            )}
            {splitMessage && (
              <p className="muted" data-testid="device-split-result">
                {splitMessage}{" "}
                {splitCreatedID && (
                  <Link
                    href={`/devices/${splitCreatedID}`}
                    data-testid="device-split-new-link"
                  >
                    Open the new device
                  </Link>
                )}
              </p>
            )}
          </form>
        )}
        {!identityError && identity !== null && role !== "admin" && (
          <p className="muted" data-testid="device-identity-readonly">
            Adding or closing identity windows requires the admin role (
            <code>device.write</code>).
          </p>
        )}
        {identityFieldErrors.length > 0 && (
          <ul className="error" data-testid="device-identity-field-errors">
            {identityFieldErrors.map((fe, i) => (
              <li key={`${fe.field ?? "field"}-${i}`}>
                {fe.field ? `${fe.field}: ` : ""}
                {fe.message ?? "invalid value"}
              </li>
            ))}
          </ul>
        )}
        {identityActionError && (
          <p className="error" data-testid="device-identity-action-error">
            {identityActionError}
          </p>
        )}
        {identityMessage && (
          <p className="muted" data-testid="device-identity-action-result">
            {identityMessage}
          </p>
        )}
      </section>

      <DeviceInterfacePanel
        deviceID={current.id}
        canWrite={role === "admin"}
        rangeKey={rangeKey}
        refreshKey={interfacesKey}
      />

      <DeviceMergePanel
        deviceID={current.id}
        deviceName={current.name}
        canWrite={role === "admin"}
        onMerged={handleMerged}
      />

      <DeviceCredentialPanel
        deviceID={device.id}
        siteID={current.site_id}
        canManage={role === "admin"}
      />

      <section className="panel" style={{ marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>ICMP health</h2>
        <div className="metric-ranges" role="group" aria-label="Chart time range">
          {RANGES.map((r) => (
            <button
              key={r.key}
              type="button"
              className={`btn-sm ${r.key === rangeKey ? "btn-range-active" : "btn-ghost"}`}
              aria-pressed={r.key === rangeKey}
              data-testid={`device-range-${r.key}`}
              onClick={() => setRangeKey(r.key)}
            >
              {r.label}
            </button>
          ))}
        </div>

        <h3 className="vis-subhead">Availability (reachable)</h3>
        <AvailabilityRibbon
          points={ribbonPoints}
          meta={chartMeta}
          loading={chartsLoading}
          error={chartsError}
          testIdPrefix="device-ribbon"
        />

        <h3 className="vis-subhead">RTT and packet loss</h3>
        <TimeSeriesChart
          series={icmpChartSeries}
          meta={chartMeta}
          loading={chartsLoading}
          error={chartsError}
          emptyLabel="No ICMP samples in this range; the device may never have been polled."
          testIdPrefix="device-chart"
          ariaLabel="ICMP RTT and packet loss"
        />
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>Recent poll health</h2>
        {healthError && (
          <p className="error" data-testid="device-health-error">
            {healthError}
          </p>
        )}
        {!healthError && health === null && <p className="muted">Loading poll health…</p>}
        {!healthError && health?.length === 0 && (
          <p className="muted" data-testid="device-health-empty">
            No poll-health rows yet. Scheduled probes appear after the collector's
            first cycle.
          </p>
        )}
        {!healthError && health && health.length > 0 && (
          <table data-testid="device-health-table">
            <thead>
              <tr>
                <th>Checked</th>
                <th>Type</th>
                <th>Origin</th>
                <th>Outcome</th>
                <th>Error class</th>
                <th>Latency</th>
                <th>Failures</th>
              </tr>
            </thead>
            <tbody>
              {health.map((row) => (
                <tr key={row.id}>
                  <td className="muted">{shortTime(row.checked_at)}</td>
                  <td>{row.poll_type}</td>
                  <td className="muted">{row.origin}</td>
                  <td>
                    <StatusChip status={row.outcome} />
                  </td>
                  <td className="muted">{row.error_class || "—"}</td>
                  <td>{formatLatency(row.latency_ms)}</td>
                  <td>{row.consecutive_failures}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>Checks</h2>
        <p className="muted">
          On-demand ICMP/SNMP probes run immediately on the site collector; they
          never emit metric samples or drive the status rollup.
        </p>
        <CheckRunner
          deviceID={device.id}
          canRun={role === "admin"}
          onSettled={() => void loadTables()}
        />
        {onDemand.length > 0 && (
          <table data-testid="device-recent-checks">
            <thead>
              <tr>
                <th>Requested result</th>
                <th>Type</th>
                <th>Outcome</th>
                <th>Error class</th>
                <th>Latency</th>
              </tr>
            </thead>
            <tbody>
              {onDemand.map((row) => (
                <tr key={row.id}>
                  <td className="muted">{shortTime(row.checked_at)}</td>
                  <td>{row.poll_type}</td>
                  <td>
                    <StatusChip status={row.outcome} />
                  </td>
                  <td className="muted">{row.error_class || "—"}</td>
                  <td>{formatLatency(row.latency_ms)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>Alerts</h2>
        <p className="muted" data-testid="device-alerts-placeholder">
          Alerting arrives with M11. Transitions visible today are the status
          rollup and poll-health history above.
        </p>
      </section>

      <p className="muted" style={{ marginTop: 16 }}>
        <Link href="/devices">← Back to devices</Link>
      </p>
    </>
  );
}

"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";

import { fetchJSON } from "@/lib/api";

import StatusChip from "./StatusChip";
import TimeSeriesChart, {
  type ChartMeta,
  type ChartSeries,
} from "./TimeSeriesChart";
import { formatSpeedBps, shortTime } from "./format";

// InterfaceDetail is the M10-S3 interface page: live IF-MIB identity plus
// counters charts resolved through the canonical /v1/metrics/query selector
// {device_id, metric_key, dimensions:{if_name}}. Counter series are stored as
// per-second rates (docs/08 §13.2), so the charts plot the stored values and
// render explicit null gaps rather than interpolating.
export interface InterfaceDetailData {
  id: string;
  device_id: string;
  if_index: number;
  if_name: string;
  if_alias: string | null;
  if_type: number | null;
  admin_status: string | null;
  oper_status: string | null;
  speed_bps: number | null;
  mtu: number | null;
  mac: string | null;
  description: string | null;
  role: string;
  monitored: boolean;
  first_seen_at: string;
  last_seen_at: string | null;
  status: "up" | "down" | "unknown";
  freshness_seconds: number;
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
  quality: { gaps: number };
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

function toMeta(meta: MatrixMeta): ChartMeta {
  return {
    resolution: meta.resolution,
    gaps: meta.quality?.gaps ?? 0,
    returned_points: meta.returned_points ?? 0,
    expected_points: meta.expected_points ?? 0,
    series_returned: meta.series_returned ?? 0,
    partial: meta.partial ?? false,
    raw_fallback: meta.raw_fallback ?? false,
    resolution_warning: meta.resolution_warning,
  };
}

export default function InterfaceDetail({
  iface,
  deviceName,
}: {
  iface: InterfaceDetailData;
  deviceName: string;
}) {
  const [rangeKey, setRangeKey] = useState<RangeKey>("6h");
  const [traffic, setTraffic] = useState<MatrixResponse | null>(null);
  const [trafficLoading, setTrafficLoading] = useState(true);
  const [trafficError, setTrafficError] = useState("");
  const [counters, setCounters] = useState<MatrixResponse | null>(null);
  const [countersLoading, setCountersLoading] = useState(true);
  const [countersError, setCountersError] = useState("");

  const load = useCallback(
    async (key: RangeKey) => {
      const range = RANGES.find((r) => r.key === key) ?? RANGES[1];
      const to = new Date();
      const from = new Date(to.getTime() - range.windowMs);
      const common = {
        from: from.toISOString(),
        to: to.toISOString(),
        step: "auto",
        agg: "avg",
        fill: "null",
      };
      const selector = (metricKey: string) => ({
        device_id: iface.device_id,
        metric_key: metricKey,
        dimensions: { if_name: iface.if_name },
      });
      setTrafficLoading(true);
      setCountersLoading(true);
      const [trafficRes, countersRes] = await Promise.all([
        fetchJSON<MatrixResponse>("/api/v1/metrics/query", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ...common,
            series: [selector("net.if.in_octets"), selector("net.if.out_octets")],
          }),
        }),
        fetchJSON<MatrixResponse>("/api/v1/metrics/query", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ...common,
            series: [
              selector("net.if.in_errors"),
              selector("net.if.out_errors"),
              selector("net.if.in_discards"),
              selector("net.if.out_discards"),
            ],
          }),
        }),
      ]);
      if (trafficRes.ok) {
        setTraffic(trafficRes.data);
        setTrafficError("");
      } else {
        setTrafficError(trafficRes.error);
      }
      if (countersRes.ok) {
        setCounters(countersRes.data);
        setCountersError("");
      } else {
        setCountersError(countersRes.error);
      }
      setTrafficLoading(false);
      setCountersLoading(false);
    },
    [iface.device_id, iface.if_name],
  );

  useEffect(() => {
    void load(rangeKey);
  }, [load, rangeKey]);

  function chartSeries(rows: MatrixSeries[] | undefined): ChartSeries[] {
    return (rows ?? []).map((row) => ({
      id: row.id,
      name: row.metric_key,
      unit: row.unit,
      points: row.points.map(([t, v]) => ({ t, v })),
    }));
  }

  const trafficSeries = useMemo(
    () => chartSeries(traffic?.series),
    [traffic],
  );
  const countersSeries = useMemo(
    () => chartSeries(counters?.series),
    [counters],
  );
  const trafficMeta = useMemo(
    () => (traffic ? toMeta(traffic.meta) : null),
    [traffic],
  );
  const countersMeta = useMemo(
    () => (counters ? toMeta(counters.meta) : null),
    [counters],
  );

  return (
    <>
      <section className="panel" data-testid="interface-header">
        <div className="detail-head">
          <h1 style={{ margin: 0 }}>
            {iface.if_name}
            {iface.if_alias ? (
              <span className="muted"> · {iface.if_alias}</span>
            ) : null}
          </h1>
          <StatusChip
            status={iface.status}
            testId="interface-status-chip"
            title="Live SNMP oper status + freshness"
          />
        </div>
        <p className="muted" style={{ marginTop: 8 }}>
          <Link href={`/devices/${iface.device_id}`} data-testid="interface-device-link">
            ← {deviceName}
          </Link>{" "}
          · ifIndex {iface.if_index} · role {iface.role} ·{" "}
          {iface.monitored ? "monitored" : "not monitored"}
        </p>
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>Identity</h2>
        <table data-testid="interface-identity-table">
          <tbody>
            <tr>
              <th>Name</th>
              <td>{iface.if_name}</td>
            </tr>
            <tr>
              <th>Alias</th>
              <td className="muted">{iface.if_alias ?? "—"}</td>
            </tr>
            <tr>
              <th>ifIndex</th>
              <td>{iface.if_index}</td>
            </tr>
            <tr>
              <th>Speed</th>
              <td data-testid="interface-speed">{formatSpeedBps(iface.speed_bps)}</td>
            </tr>
            <tr>
              <th>MTU</th>
              <td>{iface.mtu ?? "—"}</td>
            </tr>
            <tr>
              <th>MAC</th>
              <td className="muted">{iface.mac ?? "—"}</td>
            </tr>
            <tr>
              <th>Admin / oper status</th>
              <td>
                {iface.admin_status ?? "—"} / {iface.oper_status ?? "—"}
              </td>
            </tr>
            <tr>
              <th>ifType</th>
              <td className="muted">{iface.if_type ?? "—"}</td>
            </tr>
            <tr>
              <th>Last seen</th>
              <td data-testid="interface-last-seen">{shortTime(iface.last_seen_at)}</td>
            </tr>
            <tr>
              <th>Freshness window</th>
              <td className="muted">
                unknown after {Math.round(iface.freshness_seconds / 60)} min without
                an SNMP observation
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>Counters</h2>
        <div className="metric-ranges" role="group" aria-label="Chart time range">
          {RANGES.map((r) => (
            <button
              key={r.key}
              type="button"
              className={`btn-sm ${r.key === rangeKey ? "btn-range-active" : "btn-ghost"}`}
              aria-pressed={r.key === rangeKey}
              data-testid={`interface-range-${r.key}`}
              onClick={() => setRangeKey(r.key)}
            >
              {r.label}
            </button>
          ))}
        </div>

        <h3 className="vis-subhead">Traffic (in/out octets)</h3>
        <TimeSeriesChart
          series={trafficSeries}
          meta={trafficMeta}
          loading={trafficLoading}
          error={trafficError}
          emptyLabel="No SNMP counter samples for this interface in this range."
          testIdPrefix="iface-traffic"
          ariaLabel="Interface in and out traffic rates"
        />

        <h3 className="vis-subhead">Errors and discards</h3>
        <TimeSeriesChart
          series={countersSeries}
          meta={countersMeta}
          loading={countersLoading}
          error={countersError}
          emptyLabel="No error or discard samples for this interface in this range."
          testIdPrefix="iface-errors"
          ariaLabel="Interface error and discard rates"
        />

        <p className="muted" style={{ marginTop: 12 }}>
          Series are resolved by the query API selector{" "}
          <code>{`{device_id, metric_key, dimensions: {if_name: "${iface.if_name}"}}`}</code>
          . Counters are stored as rates; null buckets are shown as line gaps.
        </p>
      </section>

      <p className="muted" style={{ marginTop: 16 }}>
        <Link href={`/devices/${iface.device_id}`}>← Back to {deviceName}</Link>
      </p>
    </>
  );
}

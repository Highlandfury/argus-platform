"use client";

import type { ECharts, EChartsOption } from "echarts";
import { useCallback, useEffect, useRef, useState } from "react";

interface LatestSample {
  ts: string;
  value: number;
  age_seconds: number;
  status: "fresh" | "stale";
}

interface MetricResponse {
  metric: string;
  unit: string;
  resolution: string;
  from: string;
  to: string;
  status: "no_data" | "fresh" | "stale";
  latest?: LatestSample;
  points: [number, number][];
  meta: {
    expected_points: number;
    returned_points: number;
    gaps: number;
    truncated: boolean;
    sample_count: number;
  };
}

type RangeKey = "15m" | "1h" | "6h" | "24h";

const RANGES: { key: RangeKey; label: string; windowMs: number; step: string }[] = [
  { key: "15m", label: "15m", windowMs: 15 * 60_000, step: "raw" },
  { key: "1h", label: "1h", windowMs: 60 * 60_000, step: "10s" },
  { key: "6h", label: "6h", windowMs: 6 * 3600_000, step: "1m" },
  { key: "24h", label: "24h", windowMs: 24 * 3600_000, step: "5m" },
];

// Polling is the Phase-1 refresh mechanism (SPEC §14): 30 s is the least
// complex behavior that keeps the chart current; no SSE/WebSocket subsystem.
const POLL_MS = 30_000;

export default function MetricChart({
  collectorID,
  metric = "collector_cpu_percent",
}: {
  collectorID: string;
  metric?: string;
}) {
  const [rangeKey, setRangeKey] = useState<RangeKey>("15m");
  const [data, setData] = useState<MetricResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const chartDiv = useRef<HTMLDivElement | null>(null);
  const chart = useRef<ECharts | null>(null);

  const load = useCallback(
    async (key: RangeKey, silent: boolean) => {
      const range = RANGES.find((r) => r.key === key);
      if (!range) return;
      const to = new Date();
      const from = new Date(to.getTime() - range.windowMs);
      if (!silent) setLoading(true);
      try {
        const res = await fetch(
          `/api/v1/collectors/${collectorID}/metrics?metric=${encodeURIComponent(metric)}` +
            `&from=${encodeURIComponent(from.toISOString())}` +
            `&to=${encodeURIComponent(to.toISOString())}` +
            `&step=${range.step}`,
          { cache: "no-store" },
        );
        if (!res.ok) {
          const body = (await res.json().catch(() => null)) as { detail?: string } | null;
          setError(body?.detail ?? `query failed (status ${res.status})`);
          return;
        }
        setError("");
        setData((await res.json()) as MetricResponse);
      } catch {
        setError("network error");
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [collectorID, metric],
  );

  // Initial load + reload on range change.
  useEffect(() => {
    void load(rangeKey, false);
  }, [load, rangeKey]);

  // Periodic refresh (polling).
  useEffect(() => {
    const timer = setInterval(() => {
      void load(rangeKey, true);
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [load, rangeKey]);

  // Chart lifecycle: created on first data, updated on every response.
  useEffect(() => {
    let disposed = false;
    async function render() {
      if (!chartDiv.current) return;
      const echarts = await import("echarts");
      if (disposed || !chartDiv.current) return;
      if (!chart.current) {
        chart.current = echarts.init(chartDiv.current);
      }
      const points = data?.points ?? [];
      const option: EChartsOption = {
        animation: false,
        grid: { left: 46, right: 14, top: 14, bottom: 26 },
        tooltip: {
          trigger: "axis",
          valueFormatter: (value) => `${Number(value).toFixed(1)}%`,
        },
        xAxis: { type: "time", axisLine: { lineStyle: { color: "#2c3640" } } },
        yAxis: {
          type: "value",
          min: 0,
          max: 100,
          axisLabel: { formatter: "{value}%" },
          splitLine: { lineStyle: { color: "#202932" } },
        },
        series: [
          {
            name: "Collector CPU",
            type: "line",
            showSymbol: false,
            data: points.map(([seconds, value]) => [seconds * 1000, value]),
            lineStyle: { width: 2, color: "#4c9aff" },
            areaStyle: { opacity: 0.08, color: "#4c9aff" },
          },
        ],
      };
      chart.current.setOption(option, true);
      chart.current.resize();
    }
    void render();
    return () => {
      disposed = true;
    };
  }, [data]);

  useEffect(() => {
    const onResize = () => chart.current?.resize();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      chart.current?.dispose();
      chart.current = null;
    };
  }, []);

  const points = data?.points ?? [];
  const freshness = data?.status ?? "no_data";

  return (
    <section data-testid="metric-view">
      <div className="metric-ranges" role="group" aria-label="Time range">
        {RANGES.map((r) => (
          <button
            key={r.key}
            type="button"
            className={`btn-sm ${r.key === rangeKey ? "btn-range-active" : "btn-ghost"}`}
            aria-pressed={r.key === rangeKey}
            data-testid={`range-${r.key}`}
            onClick={() => setRangeKey(r.key)}
          >
            {r.label}
          </button>
        ))}
      </div>

      <div
        ref={chartDiv}
        className="metric-chart"
        data-testid="metric-chart"
        style={{ display: points.length > 0 ? "block" : "none" }}
      />

      {loading && (
        <p className="muted" data-testid="metric-loading">
          Loading…
        </p>
      )}
      {error && (
        <p className="error" data-testid="metric-error">
          {error}
        </p>
      )}

      {!loading && !error && (
        <>
          <div className="metric-grid">
            <div>
              <div className="metric-label">Current</div>
              <div className="metric-value" data-testid="metric-current">
                {data?.latest ? `${data.latest.value.toFixed(1)}%` : "—"}
              </div>
            </div>
            <div>
              <div className="metric-label">Last updated</div>
              <div data-testid="metric-last-updated">
                {data?.latest ? new Date(data.latest.ts).toLocaleTimeString() : "—"}
              </div>
            </div>
            <div>
              <div className="metric-label">Status</div>
              <div
                data-testid="metric-freshness"
                className={
                  freshness === "fresh"
                    ? "badge-fresh"
                    : freshness === "stale"
                      ? "badge-stale"
                      : "muted"
                }
              >
                {freshness === "fresh" ? "● Fresh" : freshness === "stale" ? "● Stale" : "No data"}
              </div>
            </div>
          </div>

          {points.length === 0 && (
            <p className="muted" data-testid="metric-empty">
              No data in this range.
            </p>
          )}

          <p className="muted metric-foot">
            <span data-testid="metric-points">{data?.meta.returned_points ?? 0} points</span>
            {" · "}
            {data?.meta.gaps ? `${data.meta.gaps} gaps` : "no gaps"}
            {" · "}
            <span data-testid="metric-sample-count">{data?.meta.sample_count ?? 0} samples</span>
            {" · auto-refresh 30s"}
          </p>
        </>
      )}
    </section>
  );
}

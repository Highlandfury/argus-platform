"use client";

import type { ECharts, EChartsOption } from "echarts";
import { useCallback, useEffect, useRef, useState } from "react";

// TimeSeriesChart renders the M10-S3 matrix contract: one or two y-axes by
// unit, an always-visible resolution badge, explicit null gaps (never
// interpolated) and a drag-to-zoom brush (pixel drag -> axis range) with a
// visible reset.
export interface ChartPoint {
  // [unix seconds, value]; null is an explicit server-reported gap.
  t: number;
  v: number | null;
}

export interface ChartSeries {
  id: string;
  name: string;
  unit: string;
  points: ChartPoint[];
  yAxisIndex?: number;
}

export interface ChartMeta {
  resolution: string;
  gaps: number;
  returned_points: number;
  expected_points: number;
  series_returned: number;
  partial: boolean;
  raw_fallback: boolean;
  resolution_warning?: string;
}

const COLORS = ["#4c9aff", "#7ee2a8", "#e2c97e", "#f0616d", "#c792ea", "#7fd1e0"];

function pointsToData(points: ChartPoint[]): [number, number | null][] {
  return points.map((p) => [p.t * 1000, p.v]);
}

export default function TimeSeriesChart({
  series,
  meta,
  loading = false,
  error = "",
  emptyLabel = "No data in this range.",
  height = 240,
  testIdPrefix = "chart",
  ariaLabel = "Time series chart",
}: {
  series: ChartSeries[];
  meta: ChartMeta | null;
  loading?: boolean;
  error?: string;
  emptyLabel?: string;
  height?: number;
  testIdPrefix?: string;
  ariaLabel?: string;
}) {
  const chartDiv = useRef<HTMLDivElement | null>(null);
  const chart = useRef<ECharts | null>(null);
  const [zoom, setZoom] = useState<{
    start?: number;
    end?: number;
    startValue?: number;
    endValue?: number;
  } | null>(null);
  const hasData = series.some((s) => s.points.some((p) => p.v !== null));

  useEffect(() => {
    let disposed = false;
    async function render() {
      if (!chartDiv.current || !hasData) return;
      const echarts = await import("echarts");
      if (disposed || !chartDiv.current) return;
      if (!chart.current || chart.current.isDisposed()) {
        const instance = echarts.init(chartDiv.current);
        // Brush-to-zoom: a horizontal drag over the plot converts the drag's
        // pixel range into axis values and applies them as the zoom window.
        // A plain click (below the pixel threshold) is ignored.
        let dragStart: { x: number; y: number } | null = null;
        const zr = instance.getZr();
        zr.on("mousedown", (e: { offsetX: number; offsetY: number }) => {
          dragStart = { x: e.offsetX, y: e.offsetY };
        });
        zr.on("mouseup", (e: { offsetX: number; offsetY: number }) => {
          const start = dragStart;
          dragStart = null;
          if (!start) return;
          if (Math.abs(e.offsetX - start.x) < 12) return;
          const left = Math.min(start.x, e.offsetX);
          const right = Math.max(start.x, e.offsetX);
          const startValue = instance.convertFromPixel(
            { xAxisIndex: 0 },
            left,
          ) as number;
          const endValue = instance.convertFromPixel(
            { xAxisIndex: 0 },
            right,
          ) as number;
          if (!Number.isFinite(startValue) || !Number.isFinite(endValue)) return;
          instance.dispatchAction({
            type: "dataZoom",
            startValue,
            endValue,
          });
          setZoom({ startValue, endValue });
        });
        // datazoom fires for the slider, wheel zoom and programmatic changes.
        instance.on("datazoom", (params: unknown) => {
          const p = params as {
            start?: number;
            end?: number;
            batch?: { start?: number; end?: number }[];
          };
          const start = p.batch?.[0]?.start ?? p.start ?? 0;
          const end = p.batch?.[0]?.end ?? p.end ?? 100;
          setZoom(start > 0.5 || end < 99.5 ? { start, end } : null);
        });
        chart.current = instance;
      }
      const units = Array.from(new Set(series.map((s) => s.unit))).slice(0, 2);
      const option: EChartsOption = {
        animation: false,
        aria: { enabled: true, decal: { show: false } },
        tooltip: { trigger: "axis" },
        legend: {
          top: 0,
          textStyle: { color: "#8b98a5" },
          icon: "roundRect",
        },
        grid: {
          left: 56,
          right: units.length > 1 ? 56 : 20,
          top: 34,
          bottom: 54,
        },
        xAxis: {
          type: "time",
          axisLine: { lineStyle: { color: "#2c3640" } },
          axisLabel: { color: "#8b98a5" },
        },
        yAxis: units.map((unit, index) => ({
          type: "value" as const,
          name: unit,
          nameTextStyle: { color: "#8b98a5" },
          position: index === 1 ? ("right" as const) : ("left" as const),
          axisLabel: { color: "#8b98a5" },
          splitLine: {
            lineStyle: { color: index === 0 ? "#202932" : "transparent" },
          },
        })),
        // The slider and wheel zoom stay available for pan/adjust.
        dataZoom: [
          // Wheel zoom + slider stay available; drag-to-pan is disabled so a
          // horizontal drag is always the brush-to-zoom gesture.
          { type: "inside", xAxisIndex: 0, moveOnMouseMove: false },
          {
            type: "slider",
            xAxisIndex: 0,
            height: 16,
            bottom: 8,
            borderColor: "#2c3640",
            textStyle: { color: "#8b98a5" },
          },
        ],
        series: series.map((s, index) => {
          const color = COLORS[index % COLORS.length];
          return {
            name: s.name,
            type: "line" as const,
            showSymbol: false,
            connectNulls: false,
            yAxisIndex: units.indexOf(s.unit) === 1 ? 1 : 0,
            data: pointsToData(s.points),
            lineStyle: { width: 2, color },
            itemStyle: { color },
          };
        }),
      };
      chart.current.setOption(option, true);
      chart.current.resize();
      setZoom(null);
    }
    void render();
    return () => {
      disposed = true;
    };
  }, [series, hasData]);

  useEffect(() => {
    const onResize = () => chart.current?.resize();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      chart.current?.dispose();
      chart.current = null;
    };
  }, []);

  const resetZoom = useCallback(() => {
    chart.current?.dispatchAction({ type: "dataZoom", start: 0, end: 100 });
    setZoom(null);
  }, []);

  const notes: string[] = [];
  if (meta?.partial) notes.push("partial response (caps applied)");
  if (meta?.raw_fallback) notes.push("raw fallback");
  if (meta?.resolution_warning) notes.push(meta.resolution_warning);

  return (
    <div data-testid={`${testIdPrefix}-wrap`}>
      <div className="chart-head">
        <span
          className="badge-res"
          data-testid={`${testIdPrefix}-resolution`}
          title="Server-selected resolution for this query window"
        >
          resolution: {meta?.resolution ?? "…"}
        </span>
        {notes.length > 0 && (
          <span
            className="muted chart-note"
            data-testid={`${testIdPrefix}-resolution-note`}
          >
            {notes.join(" · ")}
          </span>
        )}
        {zoom && (
          <span className="muted chart-note" data-testid={`${testIdPrefix}-zoom-state`}>
            zoomed{" "}
            {zoom.startValue !== undefined && zoom.endValue !== undefined
              ? `${new Date(zoom.startValue).toLocaleString()} – ${new Date(zoom.endValue).toLocaleString()}`
              : `${Math.round(zoom.start ?? 0)}%–${Math.round(zoom.end ?? 100)}%`}
          </span>
        )}
        {zoom && (
          <button
            type="button"
            className="btn-sm btn-ghost btn-inline"
            data-testid={`${testIdPrefix}-zoom-reset`}
            onClick={resetZoom}
          >
            Reset zoom
          </button>
        )}
      </div>

      <div
        ref={chartDiv}
        className="metric-chart"
        role="img"
        aria-label={ariaLabel}
        data-testid={`${testIdPrefix}-canvas`}
        style={{
          height,
          display: hasData && !error ? "block" : "none",
        }}
      />

      {loading && (
        <p className="muted" data-testid={`${testIdPrefix}-loading`}>
          Loading…
        </p>
      )}
      {error && (
        <p className="error" data-testid={`${testIdPrefix}-error`}>
          {error}
        </p>
      )}
      {!loading && !error && !hasData && (
        <p className="muted" data-testid={`${testIdPrefix}-empty`}>
          {emptyLabel}
        </p>
      )}

      {!loading && !error && meta && (
        <p className="muted metric-foot" data-testid={`${testIdPrefix}-foot`}>
          <span data-testid={`${testIdPrefix}-points`}>
            {meta.returned_points} points
          </span>
          {" · "}
          <span data-testid={`${testIdPrefix}-gaps`}>
            {meta.gaps > 0 ? `${meta.gaps} gaps` : "no gaps"}
          </span>
          {" · "}
          {meta.series_returned} series
        </p>
      )}
    </div>
  );
}

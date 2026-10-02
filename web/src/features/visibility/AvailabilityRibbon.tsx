"use client";

import type { ChartMeta, ChartPoint } from "./TimeSeriesChart";

// AvailabilityRibbon renders the net.icmp.reachable state series as a
// compact horizontal band. Values are 1/0 (or a per-bucket average when the
// query rounded the series); null is an explicit gap. The legend text, the
// per-segment title and the container aria-label all carry the state, so the
// ribbon never relies on color alone.
const MAX_SEGMENTS = 120;

type SegmentState = "up" | "down" | "partial" | "gap";

interface Segment {
  state: SegmentState;
  ok: number;
  bad: number;
  partial: number;
  gaps: number;
  items: number;
  first: number | null;
  last: number | null;
}

function segment(state: SegmentState, counts: Omit<Segment, "state">): Segment {
  return { state, ...counts };
}

function bucketize(points: ChartPoint[]): Segment[] {
  if (points.length === 0) return [];
  const size = Math.max(1, Math.ceil(points.length / MAX_SEGMENTS));
  const out: Segment[] = [];
  for (let i = 0; i < points.length; i += size) {
    const chunk = points.slice(i, i + size);
    let ok = 0;
    let bad = 0;
    let partial = 0;
    let gaps = 0;
    for (const p of chunk) {
      if (p.v === null) gaps += 1;
      else if (p.v >= 0.999) ok += 1;
      else if (p.v <= 0.001) bad += 1;
      else partial += 1;
    }
    const items = chunk.length;
    const first = chunk[0]?.t ?? null;
    const last = chunk[chunk.length - 1]?.t ?? null;
    const counts = { ok, bad, partial, gaps, items, first, last };
    let state: SegmentState;
    if (ok === 0 && bad === 0 && partial === 0) state = "gap";
    else if (bad === 0 && partial === 0) state = "up";
    else if (ok === 0 && partial === 0) state = "down";
    else state = "partial";
    out.push(segment(state, counts));
  }
  return out;
}

function segmentTitle(s: Segment): string {
  const from = s.first !== null ? new Date(s.first * 1000).toLocaleString() : "—";
  const to = s.last !== null ? new Date(s.last * 1000).toLocaleString() : "—";
  const label =
    s.state === "up"
      ? "reachable"
      : s.state === "down"
        ? "unreachable"
        : s.state === "partial"
          ? "partially reachable"
          : "no data";
  return `${from} – ${to}: ${label} (${s.ok} up, ${s.bad} down, ${s.partial} partial, ${s.gaps} no data)`;
}

export default function AvailabilityRibbon({
  points,
  meta,
  loading = false,
  error = "",
  testIdPrefix = "ribbon",
}: {
  points: ChartPoint[];
  meta: ChartMeta | null;
  loading?: boolean;
  error?: string;
  testIdPrefix?: string;
}) {
  const segments = bucketize(points);
  const observed = segments.filter((s) => s.state !== "gap").length;
  const up = segments.filter((s) => s.state === "up").length;
  const down = segments.filter((s) => s.state === "down").length;
  const partial = segments.filter((s) => s.state === "partial").length;
  const gaps = segments.filter((s) => s.state === "gap").length;
  const availability =
    observed === 0 ? null : Math.round((up / observed) * 1000) / 10;

  const summary =
    availability === null
      ? "No reachable samples in this window."
      : `${availability}% of observed buckets fully reachable (${up}/${observed})`;
  const aria = `${summary}. Legend: up reachable, down unreachable, partial mixed, no data. Resolution ${meta?.resolution ?? "unknown"}.`;

  return (
    <section data-testid={`${testIdPrefix}-wrap`} aria-label="ICMP availability ribbon">
      <div className="ribbon-legend muted" aria-hidden="true">
        <span className="ribbon-key ribbon-seg-up">▲ up</span>
        <span className="ribbon-key ribbon-seg-partial">◐ partial</span>
        <span className="ribbon-key ribbon-seg-down">▼ down</span>
        <span className="ribbon-key ribbon-seg-gap">– no data</span>
      </div>

      <div
        className="ribbon"
        role="img"
        aria-label={aria}
        data-testid={`${testIdPrefix}-strip`}
      >
        {segments.map((s, i) => (
          <span
            key={`${s.first ?? i}-${i}`}
            className={`ribbon-seg ribbon-seg-${s.state}`}
            data-testid={`${testIdPrefix}-seg-${i}`}
            data-state={s.state}
            title={segmentTitle(s)}
          />
        ))}
      </div>

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
      {!loading && !error && points.length === 0 && (
        <p className="muted" data-testid={`${testIdPrefix}-empty`}>
          No availability samples in this range.
        </p>
      )}
      {!loading && !error && points.length > 0 && (
        <p className="muted metric-foot" data-testid={`${testIdPrefix}-summary`}>
          {summary}
          {down > 0 ? ` · ${down} down` : ""}
          {partial > 0 ? ` · ${partial} partial` : ""}
          {gaps > 0 ? ` · ${gaps} no data` : ""}
        </p>
      )}
    </section>
  );
}

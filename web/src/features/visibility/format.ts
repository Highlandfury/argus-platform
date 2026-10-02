// Shared display helpers for the M10 visibility pages (device detail,
// interface detail, site dashboard). Times render in the browser locale via
// toLocaleString, matching the existing collector/devices pages.

export function shortTime(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "—";
}

export function formatSpeedBps(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(1)} Gbit/s`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)} Mbit/s`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)} kbit/s`;
  return `${value} bit/s`;
}

export function formatLatency(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `${value} ms`;
}

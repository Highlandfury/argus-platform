import type { ReactNode } from "react";

// StatusIndicator is the single canonical state renderer. It maps the raw
// backend vocabulary (up/down/unknown, active/revoked, completed/failed, ...)
// onto the six design-system tones, and always renders a glyph plus a text
// label so state is never conveyed by color alone (M10-S3 a11y rule).
export type StatusTone =
  | "healthy"
  | "degraded"
  | "down"
  | "unknown"
  | "maintenance"
  | "pending";

const TONE_BY_RAW: Record<string, StatusTone> = {
  up: "healthy",
  healthy: "healthy",
  ok: "healthy",
  active: "healthy",
  connected: "healthy",
  success: "healthy",
  completed: "healthy",
  available: "healthy",

  degraded: "degraded",
  warning: "degraded",
  warn: "degraded",
  stale: "degraded",

  down: "down",
  failed: "down",
  failure: "down",
  error: "down",
  revoked: "down",
  critical: "down",
  unreachable: "down",

  maintenance: "maintenance",
  acknowledged: "maintenance",
  ack: "maintenance",

  pending: "pending",
  new: "pending",
  snoozed: "pending",
  queued: "pending",

  unknown: "unknown",
  suppressed: "unknown",
  retired: "unknown",
  disabled: "unknown",
};

const GLYPH: Record<StatusTone, string> = {
  healthy: "▲",
  degraded: "!",
  down: "▼",
  unknown: "?",
  maintenance: "⏸",
  pending: "…",
};

const LABEL: Record<StatusTone, string> = {
  healthy: "Healthy",
  degraded: "Degraded",
  down: "Down",
  unknown: "Unknown",
  maintenance: "Maintenance",
  pending: "Pending",
};

export function statusTone(raw: string | null | undefined): StatusTone {
  if (!raw) return "unknown";
  return TONE_BY_RAW[raw.toLowerCase()] ?? "unknown";
}

export interface StatusIndicatorProps {
  /** Raw backend state (up, down, active, completed, ...). */
  status: string | null | undefined;
  /** Override the canonical label (e.g. show the raw word instead). */
  label?: string;
  /** Show the raw state next to the canonical label. */
  showRaw?: boolean;
  title?: string;
  testId?: string;
  className?: string;
  children?: ReactNode;
}

export default function StatusIndicator({
  status,
  label,
  showRaw = false,
  title,
  testId,
  className,
  children,
}: StatusIndicatorProps) {
  const raw = status ?? "unknown";
  const tone = statusTone(raw);
  return (
    <span
      className={`ui-status${className ? ` ${className}` : ""}`}
      data-tone={tone}
      data-status={raw}
      title={title ?? raw}
      data-testid={testId}
    >
      <span className="ui-status-glyph" aria-hidden="true">
        {GLYPH[tone]}
      </span>
      <span className="ui-status-label">{label ?? LABEL[tone]}</span>
      {showRaw && <span className="ui-status-raw">{raw}</span>}
      {children}
    </span>
  );
}

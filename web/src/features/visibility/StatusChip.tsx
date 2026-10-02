"use client";

// StatusChip renders a state with an explicit glyph AND the state word, so
// status is never conveyed by color alone (M10-S3 a11y rule). The color class
// reuses the existing status pill conventions (globals.css `.status-*`).
export interface StatusChipProps {
  status: string;
  testId?: string;
  title?: string;
}

const META: Record<string, { icon: string; className: string }> = {
  up: { icon: "▲", className: "status status-active" },
  down: { icon: "▼", className: "status status-revoked" },
  unknown: { icon: "?", className: "status status-pending" },
  new: { icon: "•", className: "status status-pending" },
  degraded: { icon: "!", className: "status status-stale" },
  maintenance: { icon: "⏸", className: "status status-stale" },
  retired: { icon: "■", className: "status status-pending" },
  pending: { icon: "…", className: "status status-pending" },
  completed: { icon: "✓", className: "status status-active" },
  failed: { icon: "✕", className: "status status-revoked" },
  success: { icon: "✓", className: "status status-active" },
  failure: { icon: "✕", className: "status status-revoked" },
};

export default function StatusChip({ status, testId, title }: StatusChipProps) {
  const meta = META[status] ?? { icon: "●", className: "status status-pending" };
  return (
    <span
      className={meta.className}
      data-testid={testId}
      data-status={status}
      title={title ?? status}
    >
      <span aria-hidden="true">{meta.icon}</span> {status}
    </span>
  );
}

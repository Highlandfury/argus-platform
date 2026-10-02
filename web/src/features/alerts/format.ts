// Display helpers for the M11-S3b alert surfaces: state/severity vocabulary,
// duration and age formatting, evidence summarization and scope rendering. All
// helpers take real API payloads and never invent a value for missing data.

import type { StatusTone } from "@/ui/StatusIndicator";

import type {
  AlertEvent,
  MaintenanceWindow,
  Silence,
  SilenceMatch,
  TargetScope,
} from "./types";

export function shortId(value: string | null | undefined, length = 8): string {
  if (!value) return "—";
  return value.slice(0, length);
}

export function shortTime(value: string | null | undefined): string {
  return value ? new Date(value).toLocaleString() : "—";
}

export function alertStateLabel(state: string | null | undefined): string {
  switch (state) {
    case "pending":
      return "Pending";
    case "active":
      return "Active";
    case "acknowledged":
      return "Acknowledged";
    case "snoozed":
      return "Snoozed";
    case "suppressed":
      return "Suppressed";
    case "resolved":
      return "Resolved";
    default:
      return state || "Unknown";
  }
}

export function severityLabel(severity: string | null | undefined): string {
  switch (severity) {
    case "critical":
      return "Critical";
    case "warning":
      return "Warning";
    case "info":
      return "Info";
    default:
      return severity || "—";
  }
}

// Suppression reason vocabulary from alerts.suppression_reason.
export function suppressionLabel(reason: string | null | undefined): string {
  switch (reason) {
    case "maintenance":
      return "Maintenance";
    case "silence":
      return "Silence";
    case "storm":
      return "Storm";
    default:
      return reason || "Suppressed";
  }
}

export function suppressionTarget(
  reason: string,
  ref: string | null | undefined,
): string {
  switch (reason) {
    case "maintenance":
      return `maintenance window ${shortId(ref)}`;
    case "silence":
      return `silence ${shortId(ref)}`;
    case "storm":
      return "storm control (this device exceeded the new-alert rate limit)";
    default:
      return "suppression";
  }
}

// formatDuration renders a bounded human duration between two instants; when
// `end` is omitted "now" is used. Negative or invalid spans render "—" rather
// than a fabricated value.
export function formatDuration(
  start: string | null | undefined,
  end?: string | null,
): string {
  if (!start) return "—";
  const from = new Date(start).getTime();
  const to = end ? new Date(end).getTime() : Date.now();
  if (Number.isNaN(from) || Number.isNaN(to) || to < from) return "—";
  const seconds = Math.floor((to - from) / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${minutes % 60}m`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h`;
}

function formatNumber(value: number): string {
  if (Number.isInteger(value)) return String(value);
  return value.toFixed(2).replace(/\.?0+$/, "");
}

export function opSymbol(op: unknown): string {
  switch (op) {
    case "gt":
      return ">";
    case "gte":
      return "≥";
    case "lt":
      return "<";
    case "lte":
      return "≤";
    case "eq":
      return "=";
    case "ne":
      return "≠";
    default:
      return String(op ?? "");
  }
}

function scalarText(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "number") return formatNumber(value);
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

// valueSummary builds the one-line evidence shown in the queue from the real
// `alerts.value` object (threshold/rate evidence, poll_health counts, sample
// absence). Unknown shapes fall back to the first scalar entry, never to a
// fabricated sentence.
export function valueSummary(value: Record<string, unknown> | null): string {
  if (!value || Object.keys(value).length === 0) return "—";
  const observed = value.value;
  if (typeof observed === "number") {
    if (typeof value.threshold === "number") {
      return `${formatNumber(observed)} ${opSymbol(value.op)} ${formatNumber(
        value.threshold,
      )}`;
    }
    if (typeof value.current === "number" && typeof value.previous === "number") {
      return `rate ${formatNumber(observed)}/s (${formatNumber(
        value.previous,
      )} → ${formatNumber(value.current)})`;
    }
    return formatNumber(observed);
  }
  if (typeof value.consecutive_failures === "number") {
    return `${value.consecutive_failures} consecutive scheduled poll failures`;
  }
  if (typeof value.last_sample_at === "string") {
    return `no sample for ${formatDuration(value.last_sample_at)}${
      typeof value.window === "string" ? ` (window ${value.window})` : ""
    }`;
  }
  if (value.missing === true) return "no data";
  for (const [key, entry] of Object.entries(value)) {
    if (
      typeof entry === "string" ||
      typeof entry === "number" ||
      typeof entry === "boolean"
    ) {
      return `${key}: ${scalarText(entry)}`;
    }
  }
  return "evidence recorded";
}

// valueEntries renders the full evidence object for the detail page with
// human labels for the documented evaluator fields.
export function valueEntries(
  value: Record<string, unknown> | null,
): { label: string; value: string }[] {
  if (!value) return [];
  const labels: Record<string, string> = {
    value: "Observed",
    op: "Operator",
    threshold: "Threshold",
    phase: "Phase",
    current: "Current",
    previous: "Previous",
    window: "Window",
    for_duration: "For duration",
    last_sample_at: "Last sample",
    age_seconds: "Sample age",
    consecutive_failures: "Consecutive failures",
    consecutive_successes: "Consecutive successes",
    last_outcome: "Last outcome",
    error_class: "Error class",
    partial: "Partial window",
    rollup_missing: "Rollup missing",
    suppressed: "Notified",
    recovery: "Recovery evidence",
  };
  const out: { label: string; value: string }[] = [];
  for (const [key, entry] of Object.entries(value)) {
    if (entry === null || entry === undefined || entry === "") continue;
    const label = labels[key] ?? key;
    let text: string;
    if (key === "op") text = opSymbol(entry);
    else if (key === "age_seconds" && typeof entry === "number") {
      text = formatDuration(new Date(Date.now() - entry * 1000).toISOString());
    } else if (key === "suppressed") text = entry ? "suppressed" : "dispatched";
    else text = scalarText(entry);
    out.push({ label, value: text });
  }
  return out;
}

const EVENT_TONES: Record<string, StatusTone> = {
  pending: "pending",
  activated: "down",
  updated: "unknown",
  acknowledged: "maintenance",
  snoozed: "pending",
  unsnoozed: "unknown",
  reactivated: "down",
  suppressed: "maintenance",
  unsuppressed: "unknown",
  resolved: "healthy",
  manual_resolved: "healthy",
  comment: "unknown",
  reopened: "down",
};

// eventPresentation turns one alert_events row into a timeline title and
// description using only the recorded `data` fields (from/to/reason/comment/
// evidence). Unknown kinds stay generic instead of being mislabeled.
export function eventPresentation(event: AlertEvent): {
  title: string;
  description: string;
  tone: StatusTone;
} {
  const data = event.data ?? {};
  const from = typeof data.from === "string" ? alertStateLabel(data.from) : "";
  const to = typeof data.to === "string" ? alertStateLabel(data.to) : "";
  const transition = from && to ? `${from} → ${to}` : to || from;
  const reason = typeof data.reason === "string" ? data.reason : "";
  const tone = EVENT_TONES[event.kind] ?? "unknown";

  switch (event.kind) {
    case "pending":
      return {
        title: "Pending",
        description: [transition, valueSummary(data.value as Record<string, unknown>)]
          .filter(Boolean)
          .join(" · "),
        tone,
      };
    case "activated":
      return {
        title: "Fired",
        description: [transition, valueSummary(data.value as Record<string, unknown>)]
          .filter(Boolean)
          .join(" · "),
        tone,
      };
    case "updated":
      return {
        title: "Re-evaluated",
        description: valueSummary(data.value as Record<string, unknown>),
        tone,
      };
    case "acknowledged":
      return { title: "Acknowledged", description: transition, tone };
    case "snoozed":
      return {
        title: "Snoozed",
        description: [
          typeof data.snooze_until === "string"
            ? `until ${shortTime(data.snooze_until)}`
            : "",
          reason,
        ]
          .filter(Boolean)
          .join(" · "),
        tone,
      };
    case "unsnoozed":
      return { title: "Snooze expired", description: reason, tone };
    case "reactivated":
      return { title: "Fired again", description: transition, tone };
    case "suppressed":
      return {
        title: `Suppressed (${suppressionLabel(reason)})`,
        description:
          typeof data.ref_id === "string" ? `ref ${shortId(data.ref_id)}` : "",
        tone,
      };
    case "unsuppressed":
      return { title: "Suppression ended", description: reason, tone };
    case "resolved":
      return {
        title: "Recovered",
        description: data.suppressed === true ? "resolved while suppressed — not notified" : "",
        tone,
      };
    case "manual_resolved":
      return { title: "Manually resolved", description: reason, tone };
    case "comment":
      return {
        title: "Comment",
        description: typeof data.comment === "string" ? data.comment : "",
        tone,
      };
    case "reopened":
      return { title: "Reopened", description: transition, tone };
    default:
      return {
        title: event.kind.replace(/_/g, " "),
        description: JSON.stringify(data),
        tone,
      };
  }
}

// scopeSummary renders the maintenance/silence TargetScope as an operator
// sentence. An empty scope is org-wide (the API's documented meaning).
export function scopeSummary(
  scope: TargetScope | null | undefined,
  siteNames: Map<string, string>,
  deviceNames: Map<string, string>,
): string {
  if (!scope) return "Org-wide";
  const parts: string[] = [];
  const sites = scope.sites ?? [];
  if (sites.length > 0) {
    const names = sites.slice(0, 3).map((id) => siteNames.get(id) ?? shortId(id));
    parts.push(
      `Sites: ${names.join(", ")}${sites.length > 3 ? ` +${sites.length - 3}` : ""}`,
    );
  }
  const kinds = scope.device_kinds ?? [];
  if (kinds.length > 0) parts.push(`Kinds: ${kinds.join(", ")}`);
  const devices = scope.device_ids ?? [];
  if (devices.length > 0) {
    const names = devices
      .slice(0, 3)
      .map((id) => deviceNames.get(id) ?? shortId(id));
    parts.push(
      `Devices: ${names.join(", ")}${
        devices.length > 3 ? ` +${devices.length - 3}` : ""
      }`,
    );
  }
  return parts.length > 0 ? parts.join(" · ") : "Org-wide";
}

export function silenceTargetSummary(
  match: SilenceMatch | null | undefined,
  siteNames: Map<string, string>,
  deviceNames: Map<string, string>,
): string {
  if (!match) return "—";
  const parts: string[] = [];
  if (match.alert_id) parts.push(`Alert ${shortId(match.alert_id)}`);
  if (match.fingerprint) {
    parts.push(`Fingerprint ${match.fingerprint.slice(0, 12)}…`);
  }
  if (match.scope && !scopeIsEmpty(match.scope)) {
    parts.push(scopeSummary(match.scope, siteNames, deviceNames));
  }
  return parts.length > 0 ? parts.join(" · ") : "—";
}

function scopeIsEmpty(scope: TargetScope): boolean {
  return (
    (scope.sites ?? []).length === 0 &&
    (scope.device_ids ?? []).length === 0 &&
    (scope.device_kinds ?? []).length === 0
  );
}

// windowStatus is the honest lifecycle label computed from the API's fields.
export function windowStatus(window: MaintenanceWindow): {
  label: string;
  variant: "healthy" | "pending" | "unknown" | "neutral" | "maintenance";
} {
  if (window.active) return { label: "Active", variant: "maintenance" };
  if (!window.enabled) return { label: "Disabled", variant: "unknown" };
  if (Date.now() < new Date(window.starts_at).getTime()) {
    return { label: "Scheduled", variant: "pending" };
  }
  return { label: "Expired", variant: "neutral" };
}

export function silenceStatus(silence: Silence): {
  label: string;
  variant: "healthy" | "unknown";
} {
  return silence.active
    ? { label: "Active", variant: "healthy" }
    : { label: "Expired", variant: "unknown" };
}

// toDatetimeLocal renders a Date for <input type="datetime-local"> in local
// time; fromDatetimeLocal converts the input back to RFC 3339 for the API.
export function toDatetimeLocal(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(
    date.getDate(),
  )}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function fromDatetimeLocal(value: string): string {
  return new Date(value).toISOString();
}

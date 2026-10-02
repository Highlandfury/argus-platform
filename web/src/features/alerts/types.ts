// M11-S3b alert surfaces: shared payload types mirroring the M11-S1/S2/S3a
// OpenAPI schemas (openapi/argus.v1.yaml). No fields are invented here: every
// interface is a subset of a documented payload, and optional fields stay
// optional so an older server never renders fabricated values.

import type { BadgeVariant } from "@/ui/Badge";

export type AlertState =
  | "pending"
  | "active"
  | "acknowledged"
  | "snoozed"
  | "suppressed"
  | "resolved";

export type AlertSeverity = "info" | "warning" | "critical";

export interface Alert {
  id: string;
  rule_id: string;
  rule_version: number;
  fingerprint: string;
  resource_type: string;
  resource_id: string;
  site_id?: string;
  dimension_subset: Record<string, unknown>;
  state: AlertState;
  severity: AlertSeverity;
  value: Record<string, unknown>;
  started_at: string;
  last_evaluated_at: string;
  resolved_at: string | null;
  ack_by: string | null;
  ack_at: string | null;
  snooze_until: string | null;
  suppression_reason: string;
  suppression_ref: string | null;
  created_at: string;
}

export interface AlertEvent {
  id: string;
  alert_id: string;
  kind: string;
  actor_id: string | null;
  data: Record<string, unknown>;
  ts: string;
}

export interface AlertDetail extends Alert {
  events?: AlertEvent[];
}

export interface AlertPage {
  data?: Alert[];
  next_cursor?: string | null;
  has_more?: boolean;
}

export interface AlertRule {
  rule_id: string;
  version: number;
  name: string;
  type: string;
  severity: AlertSeverity;
  scope_selector: Record<string, unknown>;
  condition: Record<string, unknown>;
  enabled: boolean;
  created_at: string;
}

export interface AlertRulePage {
  data?: AlertRule[];
  next_cursor?: string | null;
  has_more?: boolean;
}

// SSE payload from GET /v1/streams/events (docs/12 §22.16). `event_data` is the
// alert_events data object when present; the envelope only carries transition
// metadata, never a rendered summary (the UI must not invent one).
export interface AlertStreamEvent {
  alert_id: string;
  event_id: string;
  event_kind: string;
  state?: AlertState;
  severity?: AlertSeverity;
  rule_id?: string;
  fingerprint?: string;
  resource_type?: string;
  resource_id?: string;
  device_id?: string;
  site_id?: string;
  suppressed?: boolean;
  suppression_reason?: string;
  suppression_ref?: string;
  occurred_at?: string;
  event_data?: Record<string, unknown>;
}

export interface TargetScope {
  sites?: string[];
  device_ids?: string[];
  device_kinds?: string[];
}

export interface MaintenanceWindow {
  id: string;
  name: string;
  scope: TargetScope;
  enabled: boolean;
  starts_at: string;
  ends_at: string;
  active: boolean;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export interface MaintenanceWindowPage {
  data?: MaintenanceWindow[];
  next_cursor?: string | null;
  has_more?: boolean;
}

export interface SilenceMatch {
  alert_id?: string;
  fingerprint?: string;
  scope?: TargetScope;
}

export interface Silence {
  id: string;
  match: SilenceMatch;
  reason: string;
  starts_at: string;
  ends_at: string;
  active: boolean;
  created_by: string | null;
  created_at: string;
}

export interface SilencePage {
  data?: Silence[];
  next_cursor?: string | null;
  has_more?: boolean;
}

export interface NotificationDelivery {
  id: string;
  alert_id: string | null;
  event_id: string | null;
  event_kind: string;
  severity: AlertSeverity;
  route_id: string | null;
  channel_id: string;
  status: "pending" | "delivered" | "failed" | "dead_letter";
  attempts: number;
  next_attempt_at: string | null;
  response_code: number | null;
  response_excerpt: string;
  dedup_key: string;
  subject: string;
  body: string;
  created_at: string;
  updated_at: string;
  delivered_at: string | null;
}

export interface NotificationDeliveryPage {
  data?: NotificationDelivery[];
  next_cursor?: string | null;
  has_more?: boolean;
}

export interface DeviceRef {
  id: string;
  name: string;
  site_id: string;
  kind?: string;
}

export interface SiteRef {
  id: string;
  name: string;
}

// Server-alphabetical order of the documented alert states; the API rejects
// anything else, so the UI only offers these.
export const ALERT_STATES: AlertState[] = [
  "pending",
  "active",
  "acknowledged",
  "snoozed",
  "suppressed",
  "resolved",
];

export const ALERT_SEVERITIES: AlertSeverity[] = [
  "info",
  "warning",
  "critical",
];

// Canonical device taxonomy used by the inventory forms (docs/05 FR-INV-001).
// Only needed as scope options for maintenance windows.
export const DEVICE_KINDS = [
  "router",
  "switch",
  "firewall",
  "ap",
  "server",
  "printer",
  "camera",
  "nvr",
  "ups",
  "phone",
  "pos",
  "iot",
  "workstation",
  "unknown",
] as const;

// Alert state → Badge variant. The alert lifecycle is a different vocabulary
// from resource health, so the design-system StatusIndicator mapping is not
// reused for the state itself: a firing alert must not render as "Healthy".
// Text labels are always shown; color is never the only signal.
export function alertStateBadgeVariant(state: string): BadgeVariant {
  switch (state) {
    case "active":
      return "down";
    case "acknowledged":
      return "maintenance";
    case "snoozed":
      return "pending";
    case "suppressed":
      return "unknown";
    case "resolved":
      return "healthy";
    case "pending":
      return "pending";
    default:
      return "neutral";
  }
}

export function severityBadgeVariant(severity: string): BadgeVariant {
  switch (severity) {
    case "critical":
      return "down";
    case "warning":
      return "degraded";
    case "info":
      return "accent";
    default:
      return "neutral";
  }
}

export function deliveryBadgeVariant(status: string): BadgeVariant {
  switch (status) {
    case "delivered":
      return "healthy";
    case "pending":
      return "pending";
    case "failed":
      return "degraded";
    case "dead_letter":
      return "down";
    default:
      return "neutral";
  }
}

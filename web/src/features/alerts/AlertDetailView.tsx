"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { fetchJSON, problemDetail, readCSRF } from "@/lib/api";
import Badge from "@/ui/Badge";
import Button from "@/ui/Button";
import Dialog from "@/ui/Dialog";
import ErrorState from "@/ui/ErrorState";
import PageHeader from "@/ui/PageHeader";
import Panel from "@/ui/Panel";
import Skeleton from "@/ui/Skeleton";
import Timeline, { type TimelineItem } from "@/ui/Timeline";

import { AlertStateBadge, SeverityBadge } from "./AlertsView";
import {
  eventPresentation,
  formatDuration,
  shortId,
  shortTime,
  suppressionLabel,
  suppressionTarget,
  valueEntries,
  valueSummary,
} from "./format";
import LiveIndicator from "./LiveIndicator";
import { useAlertStream } from "./stream";
import {
  deliveryBadgeVariant,
  type AlertDetail,
  type AlertRule,
  type AlertRulePage,
  type AlertStreamEvent,
  type DeviceRef,
  type NotificationDelivery,
  type NotificationDeliveryPage,
  type SiteRef,
} from "./types";

const SNOOZE_PRESETS = [
  { value: 900, label: "15 minutes" },
  { value: 3600, label: "1 hour" },
  { value: 14400, label: "4 hours" },
  { value: 86400, label: "24 hours" },
  { value: 604800, label: "7 days" },
  { value: 2592000, label: "30 days (maximum)" },
] as const;

const DELIVERY_LIMIT = 25;

function deliveryResponse(delivery: NotificationDelivery): string {
  const code = delivery.response_code === null ? "" : `${delivery.response_code} `;
  const excerpt = delivery.response_excerpt || "";
  if (code === "" && excerpt === "") return "—";
  return `${code}${excerpt}`.trim();
}

// AlertDetailView is the M11-S3b /alerts/{id} surface: state/resource/rule
// context, suppression reason rendered against the real window/silence tabs,
// the lifecycle timeline from the alert payload, and the capability-gated
// actions (ack / snooze / resolve / comment / silence). It stays live over the
// same SSE stream and keeps an explicit unavailable/manual-refresh fallback.
export default function AlertDetailView({
  alertId,
  initialAlert,
  canAct,
}: {
  alertId: string;
  initialAlert: AlertDetail | null;
  canAct: boolean;
}) {
  const [alert, setAlert] = useState<AlertDetail | null>(initialAlert);
  const [error, setError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);

  const [device, setDevice] = useState<DeviceRef | null>(null);
  const [sites, setSites] = useState<SiteRef[]>([]);
  const [rules, setRules] = useState<AlertRule[] | null>(null);
  const [deliveries, setDeliveries] = useState<NotificationDelivery[] | null>(
    null,
  );
  const [deliveriesError, setDeliveriesError] = useState("");

  const [busyAction, setBusyAction] = useState("");
  const [actionError, setActionError] = useState("");
  const [actionResult, setActionResult] = useState("");

  const [snoozeOpen, setSnoozeOpen] = useState(false);
  const [snoozeDuration, setSnoozeDuration] = useState(3600);
  const [snoozeReason, setSnoozeReason] = useState("");
  const [snoozeError, setSnoozeError] = useState("");

  const [resolveOpen, setResolveOpen] = useState(false);
  const [resolveReason, setResolveReason] = useState("");
  const [resolveError, setResolveError] = useState("");

  const [commentOpen, setCommentOpen] = useState(false);
  const [commentText, setCommentText] = useState("");
  const [commentError, setCommentError] = useState("");

  const [silenceOpen, setSilenceOpen] = useState(false);
  const [silenceDuration, setSilenceDuration] = useState(3600);
  const [silenceReason, setSilenceReason] = useState("");
  const [silenceError, setSilenceError] = useState("");

  const reload = useCallback(() => setReloadToken((token) => token + 1), []);

  // Live refresh: patch-on-event is not enough for the detail (evidence,
  // timeline and suppression all change), so a matching event schedules one
  // bounded refetch.
  const streamTimerRef = useRef<number | null>(null);
  const onStreamEvent = useCallback(
    (event: AlertStreamEvent) => {
      if (event.alert_id !== alertId) return;
      if (streamTimerRef.current !== null) return;
      streamTimerRef.current = window.setTimeout(() => {
        streamTimerRef.current = null;
        reload();
      }, 400);
    },
    [alertId, reload],
  );
  const live = useAlertStream(onStreamEvent);
  useEffect(
    () => () => {
      if (streamTimerRef.current !== null) {
        window.clearTimeout(streamTimerRef.current);
      }
    },
    [],
  );

  useEffect(() => {
    let cancelled = false;
    async function load() {
      const res = await fetchJSON<AlertDetail>(
        `/api/v1/alerts/${encodeURIComponent(alertId)}`,
      );
      if (cancelled) return;
      if (res.ok) {
        setAlert(res.data);
        setError("");
      } else {
        setError(res.error);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [alertId, reloadToken]);

  useEffect(() => {
    let cancelled = false;
    async function loadContext() {
      const [sitesRes, rulesRes] = await Promise.all([
        fetchJSON<{ data?: SiteRef[] }>("/api/v1/sites?limit=100"),
        fetchJSON<AlertRulePage>("/api/v1/alert-rules?limit=100"),
      ]);
      if (cancelled) return;
      if (sitesRes.ok) setSites(sitesRes.data.data ?? []);
      if (rulesRes.ok) setRules(rulesRes.data.data ?? []);
    }
    void loadContext();
    return () => {
      cancelled = true;
    };
  }, [alertId]);

  // Device and site names resolve once the alert (and therefore its resource
  // id) is known; a retired/out-of-scope device degrades to the short id.
  const resourceID = alert?.resource_type === "device" ? alert.resource_id : "";
  useEffect(() => {
    if (resourceID === "") return;
    let cancelled = false;
    async function loadDevice() {
      const res = await fetchJSON<DeviceRef>(
        `/api/v1/devices/${encodeURIComponent(resourceID)}`,
      );
      if (!cancelled && res.ok) setDevice(res.data);
    }
    void loadDevice();
    return () => {
      cancelled = true;
    };
  }, [resourceID]);

  useEffect(() => {
    let cancelled = false;
    async function loadDeliveries() {
      setDeliveries(null);
      setDeliveriesError("");
      const res = await fetchJSON<NotificationDeliveryPage>(
        `/api/v1/notification/deliveries?filter[alert_id]=${encodeURIComponent(
          alertId,
        )}&limit=${DELIVERY_LIMIT}`,
      );
      if (cancelled) return;
      if (res.ok) setDeliveries(res.data.data ?? []);
      else setDeliveriesError(res.error);
    }
    void loadDeliveries();
    return () => {
      cancelled = true;
    };
  }, [alertId, reloadToken]);

  const siteNames = useMemo(
    () => new Map(sites.map((site) => [site.id, site.name])),
    [sites],
  );
  const rule = useMemo(
    () => (rules ?? []).find((entry) => entry.rule_id === alert?.rule_id),
    [rules, alert?.rule_id],
  );

  async function postAction(
    action: string,
    path: string,
    body: Record<string, unknown>,
  ): Promise<boolean> {
    setBusyAction(action);
    setActionError("");
    setActionResult("");
    try {
      const res = await fetch(
        `/api/v1/alerts/${encodeURIComponent(alertId)}${path}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": readCSRF(),
          },
          body: JSON.stringify(body),
        },
      );
      if (!res.ok) {
        setActionError(await problemDetail(res));
        return false;
      }
      reload();
      return true;
    } catch {
      setActionError("network error");
      return false;
    } finally {
      setBusyAction("");
    }
  }

  async function createSilence(): Promise<boolean> {
    if (silenceReason.trim() === "") {
      setSilenceError("A reason is required for a silence (operator audit).");
      return false;
    }
    setBusyAction("silence");
    setSilenceError("");
    setActionError("");
    setActionResult("");
    try {
      const res = await fetch("/api/v1/silences", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify({
          match: { alert_id: alertId },
          reason: silenceReason.trim(),
          duration_seconds: silenceDuration,
        }),
      });
      if (!res.ok) {
        setSilenceError(await problemDetail(res));
        return false;
      }
      setActionResult(
        "Silence created for this alert. Suppression takes effect at the next rule evaluation (still recorded and evaluated, never notified).",
      );
      setSilenceOpen(false);
      setSilenceReason("");
      reload();
      return true;
    } catch {
      setSilenceError("network error");
      return false;
    } finally {
      setBusyAction("");
    }
  }

  if (alert === null) {
    return (
      <section data-testid="alert-detail">
        <PageHeader
          title="Alert"
          breadcrumbs={[{ label: "Alerts", href: "/alerts" }]}
        />
        {error !== "" ? (
          <ErrorState
            title="Alert unavailable"
            message={error}
            action={
              <Button size="sm" variant="secondary" onClick={reload}>
                Try again
              </Button>
            }
            testId="alert-detail-error"
          />
        ) : (
          <div data-testid="alert-detail-loading" aria-busy="true">
            <Skeleton height={16} width={280} />
            <div style={{ height: 8 }} />
            <Skeleton height={14} width="70%" />
          </div>
        )}
      </section>
    );
  }

  const resolved = alert.state === "resolved";
  const age = formatDuration(alert.started_at, alert.resolved_at ?? undefined);
  const evidence = valueEntries(alert.value);
  const dimensions = Object.entries(alert.dimension_subset ?? {});
  const deviceName = device?.name ?? shortId(alert.resource_id);
  const siteName = alert.site_id ? siteNames.get(alert.site_id) : undefined;
  const timelineItems: TimelineItem[] = (alert.events ?? []).map((event) => {
    const presentation = eventPresentation(event);
    return {
      id: event.id,
      time: shortTime(event.ts),
      title: presentation.title,
      description: (
        <>
          {presentation.description}
          {event.actor_id && (
            <span className="muted"> · by {shortId(event.actor_id)}</span>
          )}
        </>
      ),
      tone: presentation.tone,
    };
  });

  const suppressionLink =
    alert.suppression_reason === "maintenance"
      ? { href: "/alerts?tab=maintenance", label: "View maintenance windows" }
      : alert.suppression_reason === "silence"
        ? { href: "/alerts?tab=silences", label: "View silences" }
        : null;

  return (
    <section data-testid="alert-detail">
      <PageHeader
        title={rule?.name ?? `Alert ${shortId(alert.id)}`}
        description={`${valueSummary(alert.value)} — started ${shortTime(
          alert.started_at,
        )} (${age})`}
        breadcrumbs={[
          { label: "Alerts", href: "/alerts" },
          { label: shortId(alert.id) },
        ]}
        actions={
          <>
            <LiveIndicator status={live} testId="alert-detail-sse" />
            {canAct && (
              <>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={resolved || busyAction !== ""}
                  onClick={() => void postAction("ack", "/ack", {})}
                  data-testid="alert-action-ack"
                >
                  {busyAction === "ack" ? "Acknowledging…" : "Acknowledge"}
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={resolved || busyAction !== ""}
                  onClick={() => {
                    setSnoozeError("");
                    setSnoozeOpen(true);
                  }}
                  data-testid="alert-action-snooze"
                >
                  Snooze
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={resolved || busyAction !== ""}
                  onClick={() => {
                    setResolveError("");
                    setResolveOpen(true);
                  }}
                  data-testid="alert-action-resolve"
                >
                  Resolve
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={busyAction !== ""}
                  onClick={() => {
                    setCommentError("");
                    setCommentOpen(true);
                  }}
                  data-testid="alert-action-comment"
                >
                  Comment
                </Button>
                <Button
                  size="sm"
                  variant="primary"
                  disabled={busyAction !== ""}
                  onClick={() => {
                    setSilenceError("");
                    setSilenceOpen(true);
                  }}
                  data-testid="alert-action-silence"
                >
                  Silence
                </Button>
              </>
            )}
          </>
        }
        testId="alert-detail-header"
      />

      {actionResult !== "" && (
        <p className="muted alert-result" data-testid="alert-action-result">
          {actionResult}
        </p>
      )}
      {actionError !== "" && (
        <p className="error" data-testid="alert-action-error">
          {actionError}
        </p>
      )}

      <Panel
        title="Alert context"
        actions={
          <>
            <AlertStateBadge
              state={alert.state}
              suppressionReason={alert.suppression_reason}
              suppressionRef={alert.suppression_ref}
              testId="alert-detail-state"
            />
            <SeverityBadge
              severity={alert.severity}
              testId="alert-detail-severity"
            />
          </>
        }
        testId="alert-context-panel"
      >
        <ul className="kv">
          <li>
            <span className="muted">Rule:</span>{" "}
            <a
              href={`/alerts?rule=${alert.rule_id}`}
              data-testid="alert-detail-rule"
            >
              {rule?.name ?? shortId(alert.rule_id)}
            </a>{" "}
            <span className="muted">v{alert.rule_version}</span>
          </li>
          <li>
            <span className="muted">Device:</span>{" "}
            <a
              href={`/devices/${alert.resource_id}`}
              data-testid="alert-detail-device"
            >
              {deviceName}
            </a>
            {alert.site_id && (
              <>
                {" "}
                <span className="muted">·</span>{" "}
                <a
                  href={`/sites/${alert.site_id}`}
                  className="muted"
                  data-testid="alert-detail-site"
                >
                  {siteName ?? shortId(alert.site_id)}
                </a>
              </>
            )}
          </li>
          <li>
            <span className="muted">Started:</span>{" "}
            <span data-testid="alert-detail-started">
              {shortTime(alert.started_at)}
            </span>
          </li>
          <li>
            <span className="muted">Duration:</span>{" "}
            <span data-testid="alert-detail-duration">{age}</span>
          </li>
          <li>
            <span className="muted">Last evaluated:</span>{" "}
            {shortTime(alert.last_evaluated_at)}
          </li>
          {alert.resolved_at && (
            <li>
              <span className="muted">Resolved:</span>{" "}
              {shortTime(alert.resolved_at)}
            </li>
          )}
          {alert.ack_at && (
            <li>
              <span className="muted">Acknowledged:</span>{" "}
              {shortTime(alert.ack_at)}
              {alert.ack_by && (
                <span className="muted"> · by {shortId(alert.ack_by)}</span>
              )}
            </li>
          )}
          {alert.snooze_until && (
            <li>
              <span className="muted">Snoozed until:</span>{" "}
              {shortTime(alert.snooze_until)}
            </li>
          )}
          {alert.suppression_reason !== "" && (
            <li data-testid="alert-detail-suppression">
              <Badge
                variant={
                  alert.suppression_reason === "storm" ? "unknown" : "maintenance"
                }
              >
                {suppressionLabel(alert.suppression_reason)}
              </Badge>{" "}
              suppressed by{" "}
              {suppressionTarget(
                alert.suppression_reason,
                alert.suppression_ref,
              )}
              {suppressionLink && (
                <>
                  {" — "}
                  <a href={suppressionLink.href}>{suppressionLink.label}</a>
                </>
              )}
            </li>
          )}
          <li>
            <span className="muted">Fingerprint:</span>{" "}
            <code data-testid="alert-detail-fingerprint">
              {alert.fingerprint}
            </code>
          </li>
        </ul>

        {dimensions.length > 0 && (
          <div className="alert-block">
            <h3 className="vis-subhead">Dimensions</h3>
            <div className="alert-chips" data-testid="alert-detail-dimensions">
              {dimensions.map(([key, value]) => (
                <code key={key}>
                  {key}={String(value)}
                </code>
              ))}
            </div>
          </div>
        )}

        <div className="alert-block">
          <h3 className="vis-subhead">Evidence</h3>
          {evidence.length === 0 ? (
            <p className="muted" data-testid="alert-detail-value-empty">
              No evidence fields recorded on this alert.
            </p>
          ) : (
            <table className="alert-evidence" data-testid="alert-detail-value">
              <tbody>
                {evidence.map((entry) => (
                  <tr key={entry.label}>
                    <th scope="row">{entry.label}</th>
                    <td>{entry.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Panel>

      <Panel
        title="Timeline"
        subtitle="alert_events, newest first (max 50 per the detail contract)"
        testId="alert-timeline-panel"
      >
        {timelineItems.length === 0 ? (
          <p className="muted" data-testid="alert-timeline-empty">
            No timeline events were returned for this alert.
          </p>
        ) : (
          <Timeline items={timelineItems} testId="alert-timeline" />
        )}
      </Panel>

      <Panel
        title="Notification deliveries"
        subtitle="M11-S2 delivery log for this alert (at-least-once, status and provider response)"
        testId="alert-deliveries-panel"
      >
        {deliveriesError !== "" && (
          <ErrorState
            title="Deliveries unavailable"
            message={deliveriesError}
            testId="alert-deliveries-error"
          />
        )}
        {deliveriesError === "" && deliveries === null && (
          <Skeleton height={14} width="80%" testId="alert-deliveries-loading" />
        )}
        {deliveriesError === "" && deliveries !== null && deliveries.length === 0 && (
          <p className="muted" data-testid="alert-deliveries-empty">
            No notification deliveries were recorded for this alert. Deliveries
            are created only when the alert fires/reactivates or resolves while
            an enabled route matches, and suppressed transitions are never
            dispatched.
          </p>
        )}
        {deliveriesError === "" && deliveries !== null && deliveries.length > 0 && (
          <table data-testid="alert-deliveries">
            <thead>
              <tr>
                <th>Status</th>
                <th>Transition</th>
                <th>Channel</th>
                <th>Attempts</th>
                <th>Response</th>
                <th>Delivered</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {deliveries.map((delivery) => (
                <tr
                  key={delivery.id}
                  data-testid={`alert-delivery-${delivery.id}`}
                  data-status={delivery.status}
                >
                  <td>
                    <Badge variant={deliveryBadgeVariant(delivery.status)}>
                      {delivery.status}
                    </Badge>
                  </td>
                  <td className="muted">{delivery.event_kind}</td>
                  <td className="muted" title={delivery.channel_id}>
                    {shortId(delivery.channel_id)}
                  </td>
                  <td className="muted">{delivery.attempts}</td>
                  <td className="muted alert-delivery-response">
                    {deliveryResponse(delivery)}
                  </td>
                  <td className="muted">{shortTime(delivery.delivered_at)}</td>
                  <td className="muted">{shortTime(delivery.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Dialog
        open={snoozeOpen}
        onClose={() => setSnoozeOpen(false)}
        title="Snooze alert"
        testId="alert-snooze-dialog"
        footer={
          <>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setSnoozeOpen(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              variant="primary"
              disabled={busyAction === "snooze"}
              data-testid="alert-snooze-submit"
              onClick={async () => {
                const ok = await postAction("snooze", "/snooze", {
                  duration_seconds: snoozeDuration,
                  reason: snoozeReason.trim(),
                });
                if (ok) {
                  setSnoozeOpen(false);
                  setSnoozeReason("");
                }
              }}
            >
              {busyAction === "snooze" ? "Snoozing…" : "Snooze"}
            </Button>
          </>
        }
      >
        <p className="muted">
          Evaluation continues while snoozed; if the condition is still true at
          expiry the alert reactivates (P2-AC-30). Expiry is bounded to 30 days.
        </p>
        <label htmlFor="alert-snooze-duration">Duration</label>
        <select
          id="alert-snooze-duration"
          value={snoozeDuration}
          onChange={(e) => setSnoozeDuration(Number(e.target.value))}
          data-testid="alert-snooze-duration"
        >
          {SNOOZE_PRESETS.map((preset) => (
            <option key={preset.value} value={preset.value}>
              {preset.label}
            </option>
          ))}
        </select>
        <label htmlFor="alert-snooze-reason">Reason (optional)</label>
        <input
          id="alert-snooze-reason"
          value={snoozeReason}
          maxLength={2000}
          onChange={(e) => setSnoozeReason(e.target.value)}
          data-testid="alert-snooze-reason"
          placeholder="Working the change window"
        />
        {snoozeError !== "" && (
          <p className="error" data-testid="alert-snooze-error">
            {snoozeError}
          </p>
        )}
        {actionError !== "" && (
          <p className="error" data-testid="alert-snooze-error">
            {actionError}
          </p>
        )}
      </Dialog>

      <Dialog
        open={resolveOpen}
        onClose={() => setResolveOpen(false)}
        title="Resolve alert"
        testId="alert-resolve-dialog"
        footer={
          <>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setResolveOpen(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              variant="danger"
              disabled={busyAction === "resolve"}
              data-testid="alert-resolve-submit"
              onClick={async () => {
                if (resolveReason.trim() === "") {
                  setResolveError(
                    "A reason is required for a manual resolve (canonical audit rule).",
                  );
                  return;
                }
                const ok = await postAction("resolve", "/resolve", {
                  reason: resolveReason.trim(),
                });
                if (ok) {
                  setResolveOpen(false);
                  setResolveReason("");
                }
              }}
            >
              {busyAction === "resolve" ? "Resolving…" : "Resolve"}
            </Button>
          </>
        }
      >
        <p className="muted">
          Manual resolve requires a reason. A re-fire of the same fingerprint
          within the 10-minute reopen cooldown reopens this same alert.
        </p>
        <label htmlFor="alert-resolve-reason">Reason (required)</label>
        <textarea
          id="alert-resolve-reason"
          value={resolveReason}
          maxLength={2000}
          rows={3}
          onChange={(e) => setResolveReason(e.target.value)}
          data-testid="alert-resolve-reason"
          placeholder="Mitigated by replacing the SFP; monitoring for recurrence"
        />
        {resolveError !== "" && (
          <p className="error" data-testid="alert-resolve-error">
            {resolveError}
          </p>
        )}
        {actionError !== "" && (
          <p className="error" data-testid="alert-resolve-error">
            {actionError}
          </p>
        )}
      </Dialog>

      <Dialog
        open={commentOpen}
        onClose={() => setCommentOpen(false)}
        title="Comment on alert"
        testId="alert-comment-dialog"
        footer={
          <>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setCommentOpen(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              variant="primary"
              disabled={busyAction === "comment"}
              data-testid="alert-comment-submit"
              onClick={async () => {
                if (commentText.trim() === "") {
                  setCommentError("Enter a comment first.");
                  return;
                }
                const ok = await postAction("comment", "/comment", {
                  comment: commentText.trim(),
                });
                if (ok) {
                  setCommentOpen(false);
                  setCommentText("");
                }
              }}
            >
              {busyAction === "comment" ? "Saving…" : "Add comment"}
            </Button>
          </>
        }
      >
        <label htmlFor="alert-comment-text">Comment (required)</label>
        <textarea
          id="alert-comment-text"
          value={commentText}
          maxLength={2000}
          rows={3}
          onChange={(e) => setCommentText(e.target.value)}
          data-testid="alert-comment-text"
          placeholder="What did you observe or do?"
        />
        {commentError !== "" && (
          <p className="error" data-testid="alert-comment-error">
            {commentError}
          </p>
        )}
        {actionError !== "" && (
          <p className="error" data-testid="alert-comment-error">
            {actionError}
          </p>
        )}
      </Dialog>

      <Dialog
        open={silenceOpen}
        onClose={() => setSilenceOpen(false)}
        title="Silence this alert"
        testId="alert-silence-dialog"
        footer={
          <>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setSilenceOpen(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              variant="primary"
              disabled={busyAction === "silence"}
              data-testid="alert-silence-submit"
              onClick={() => void createSilence()}
            >
              {busyAction === "silence" ? "Creating…" : "Create silence"}
            </Button>
          </>
        }
      >
        <p className="muted">
          Creates an operator silence (<code>POST /v1/silences</code> with a
          mandatory reason and an expiry of at most 30 days) matching exactly
          this alert. The alert stays recorded and evaluated; it is never
          notified while suppressed.
        </p>
        <label htmlFor="alert-silence-duration">Duration</label>
        <select
          id="alert-silence-duration"
          value={silenceDuration}
          onChange={(e) => setSilenceDuration(Number(e.target.value))}
          data-testid="alert-silence-duration"
        >
          {SNOOZE_PRESETS.map((preset) => (
            <option key={preset.value} value={preset.value}>
              {preset.label}
            </option>
          ))}
        </select>
        <label htmlFor="alert-silence-reason">Reason (required)</label>
        <input
          id="alert-silence-reason"
          value={silenceReason}
          maxLength={2000}
          onChange={(e) => setSilenceReason(e.target.value)}
          data-testid="alert-silence-reason"
          placeholder="Known firmware bug, fix tracked in CHG-1234"
        />
        {silenceError !== "" && (
          <p className="error" data-testid="alert-silence-error">
            {silenceError}
          </p>
        )}
      </Dialog>
    </section>
  );
}

"use client";

import { liveStatusLabel, type LiveStatus } from "./stream";

// LiveIndicator shows the real SSE connection state. "unavailable" is a
// first-class state (red dot + explicit label), paired with a manual refresh
// action by the caller; it never silently implies live data.
export default function LiveIndicator({
  status,
  testId,
}: {
  status: LiveStatus;
  testId?: string;
}) {
  return (
    <span
      className="alert-live"
      data-live={status}
      title={
        status === "live"
          ? "Connected to the alert event stream (GET /v1/streams/events)"
          : status === "connecting"
            ? "Connecting to the alert event stream…"
            : "The alert event stream is unreachable; use Refresh to update manually"
      }
      data-testid={testId}
    >
      <span className="alert-live-dot" aria-hidden="true" />
      {liveStatusLabel(status)}
    </span>
  );
}

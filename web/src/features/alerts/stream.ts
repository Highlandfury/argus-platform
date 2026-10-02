"use client";

import { useEffect, useRef, useState } from "react";

import type { AlertStreamEvent } from "./types";

export type LiveStatus = "connecting" | "live" | "unavailable";

// useAlertStream subscribes to GET /v1/streams/events (M11-S3a SSE) through the
// same-origin rewrite. The session cookie authenticates; EventSource resumes
// with Last-Event-ID automatically. The hook reports the connection state so
// the UI can show a real indicator and fall back to manual refresh when the
// stream is unavailable — no fake "live" state and no polling fallback that
// would imply realtime.
export function useAlertStream(
  onEvent: (event: AlertStreamEvent, name: string) => void,
): LiveStatus {
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const handlerRef = useRef(onEvent);

  useEffect(() => {
    handlerRef.current = onEvent;
  }, [onEvent]);

  useEffect(() => {
    if (typeof window === "undefined" || typeof EventSource === "undefined") {
      setStatus("unavailable");
      return;
    }
    const source = new EventSource("/api/v1/streams/events");
    source.onopen = () => setStatus("live");
    source.onerror = () => setStatus("unavailable");

    const listener = (event: MessageEvent<string>) => {
      let payload: AlertStreamEvent;
      try {
        payload = JSON.parse(event.data) as AlertStreamEvent;
      } catch {
        return; // malformed frame: ignore, never invent an update
      }
      if (!payload || typeof payload.alert_id !== "string") return;
      handlerRef.current(payload, event.type);
    };
    const names = ["alert.fired", "alert.resolved", "alert.updated"];
    for (const name of names) source.addEventListener(name, listener);
    return () => {
      for (const name of names) source.removeEventListener(name, listener);
      source.close();
    };
  }, []);

  return status;
}

// LiveIndicator renders the stream connection state plus the status semantics:
// text label always present, color secondary.
export function liveStatusLabel(status: LiveStatus): string {
  switch (status) {
    case "live":
      return "Live";
    case "connecting":
      return "Connecting…";
    default:
      return "Live updates unavailable";
  }
}

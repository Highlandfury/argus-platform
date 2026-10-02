"use client";

import { useEffect, useRef, useState } from "react";

import { problemDetail, readCSRF } from "@/lib/api";

import StatusChip from "./StatusChip";

// CheckRunner is the M10-S0 on-demand check UX: POST the check with CSRF +
// Idempotency-Key, then poll GET /v1/checks/{id} until the row reaches a
// terminal state. The buttons stay disabled while a check is pending so the
// per-device pending ceiling (10) is not accidentally consumed by UI retries.
export interface DeviceCheck {
  check_id: string;
  device_id: string;
  collector_id: string | null;
  poll_type: string;
  status: "pending" | "completed" | "failed";
  outcome: string;
  error_class: string;
  latency_ms: number | null;
  created_at: string;
  completed_at: string | null;
  status_url: string;
}

const POLL_MS = 1000;
const PENDING_TIMEOUT_MS = 90_000;

function idempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `ui-${Date.now()}-${Math.floor(Math.random() * 1e9)}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export default function CheckRunner({
  deviceID,
  canRun,
  onSettled,
}: {
  deviceID: string;
  canRun: boolean;
  onSettled?: () => void;
}) {
  const [active, setActive] = useState<DeviceCheck | null>(null);
  const [last, setLast] = useState<DeviceCheck | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const cancelled = useRef(false);
  const settleTimers = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => {
    cancelled.current = false;
    return () => {
      cancelled.current = true;
      for (const timer of settleTimers.current) clearTimeout(timer);
      settleTimers.current = [];
    };
  }, []);

  // The collector emits the on-demand poll-health row asynchronously (health
  // batcher → spool → ingest), so a single refresh right after the terminal
  // result can miss it; schedule two bounded follow-up refreshes.
  function notifySettled() {
    onSettled?.();
    for (const delay of [2000, 5000]) {
      settleTimers.current.push(setTimeout(() => onSettled?.(), delay));
    }
  }

  async function run(pollType: "icmp" | "snmp") {
    setError("");
    setNotice("");
    setLast(null);
    setActive({
      check_id: "",
      device_id: deviceID,
      collector_id: null,
      poll_type: pollType,
      status: "pending",
      outcome: "",
      error_class: "",
      latency_ms: null,
      created_at: new Date().toISOString(),
      completed_at: null,
      status_url: "",
    });
    try {
      const res = await fetch(`/api/v1/devices/${deviceID}/checks`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
          "Idempotency-Key": idempotencyKey(),
        },
        body: JSON.stringify({ poll_type: pollType }),
      });
      if (!res.ok) {
        setError(await problemDetail(res, `check request failed (status ${res.status})`));
        setActive(null);
        return;
      }
      let check = (await res.json()) as DeviceCheck;
      setActive(check);
      const startedAt = Date.now();
      while (
        check.status === "pending" &&
        Date.now() - startedAt < PENDING_TIMEOUT_MS &&
        !cancelled.current
      ) {
        await sleep(POLL_MS);
        if (cancelled.current) return;
        const poll = await fetch(`/api${check.status_url}`);
        if (!poll.ok) {
          setError(await problemDetail(poll, `check status failed (status ${poll.status})`));
          setActive(null);
          return;
        }
        check = (await poll.json()) as DeviceCheck;
        setActive(check);
      }
      if (check.status === "pending") {
        // The collector may be offline; the row stays pending until its TTL.
        setNotice(
          "Check is still pending after 90 s — the site collector may be offline. It will complete or expire server-side.",
        );
        setActive(null);
        return;
      }
      setLast(check);
      setActive(null);
      notifySettled();
    } catch {
      setError("network error");
      setActive(null);
    }
  }

  if (!canRun) {
    return (
      <div data-testid="check-runner">
        <p className="muted">
          Running checks requires the admin role (<code>diagnostic.run</code>).
        </p>
      </div>
    );
  }

  const pending = active !== null && active.status === "pending";

  return (
    <div data-testid="check-runner">
      <div className="btn-row">
        <button
          type="button"
          className="btn-sm"
          data-testid="run-check-icmp"
          disabled={pending}
          onClick={() => void run("icmp")}
        >
          {pending && active?.poll_type === "icmp" ? "Running ICMP…" : "Run ICMP check"}
        </button>
        <button
          type="button"
          className="btn-sm btn-ghost"
          data-testid="run-check-snmp"
          disabled={pending}
          onClick={() => void run("snmp")}
        >
          {pending && active?.poll_type === "snmp" ? "Running SNMP…" : "Run SNMP check"}
        </button>
      </div>

      {pending && (
        <p className="muted" data-testid="check-pending">
          <StatusChip status="pending" /> {active?.poll_type} check pending — waiting
          for the collector result…
        </p>
      )}

      {last && (
        <div data-testid="check-result">
          <p>
            <StatusChip status={last.outcome || last.status} testId="check-result-outcome" />{" "}
            <span data-testid="check-result-kind">{last.poll_type}</span>{" "}
            <span className="muted" data-testid="check-result-status">
              ({last.status})
            </span>
          </p>
          <p className="muted">
            Latency:{" "}
            <span data-testid="check-result-latency">
              {last.latency_ms === null ? "—" : `${last.latency_ms} ms`}
            </span>
            {last.error_class ? ` · error class: ${last.error_class}` : ""}
            {last.completed_at
              ? ` · completed ${new Date(last.completed_at).toLocaleString()}`
              : ""}
          </p>
        </div>
      )}

      {notice && (
        <p className="muted" data-testid="check-notice">
          {notice}
        </p>
      )}
      {error && (
        <p className="error" data-testid="check-error">
          {error}
        </p>
      )}
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";

// AlertIndicator polls the real alerts API (M11-S1) for a live active count.
// When the endpoint is absent/forbidden/unreachable the indicator hides
// entirely instead of showing a fabricated zero. `filter[state]=active` is the
// API's documented filter (the milestone note says state=active; the actual
// contract is filter[state]).
const POLL_MS = 60_000;
const LIMIT = 100;

interface AlertPage {
  data?: { state?: string }[];
  has_more?: boolean;
}

export default function AlertIndicator() {
  const [count, setCount] = useState<number | null>(null);
  const [capped, setCapped] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      try {
        const res = await fetch(
          `/api/v1/alerts?filter[state]=active&limit=${LIMIT}`,
          { cache: "no-store" },
        );
        if (!res.ok) {
          if (!cancelled) setCount(null);
          return;
        }
        const body = (await res.json()) as AlertPage;
        if (cancelled) return;
        setCount((body.data ?? []).length);
        setCapped(body.has_more === true);
      } catch {
        if (!cancelled) setCount(null);
      }
    }

    void load();
    const timer = window.setInterval(() => void load(), POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  if (count === null) return null;

  const label = capped ? `${LIMIT}+` : String(count);
  return (
    <a
      className={`alert-indicator${count > 0 ? " has-alerts" : ""}`}
      href="/alerts"
      title={
        count > 0
          ? `${label} active alert${count === 1 && !capped ? "" : "s"} — open the alerts queue`
          : "No active alerts"
      }
      data-testid="alert-indicator"
    >
      <span aria-hidden="true">◔</span>
      <span className="alert-count" data-testid="alert-count">
        {label}
      </span>
      <span>Alerts</span>
    </a>
  );
}

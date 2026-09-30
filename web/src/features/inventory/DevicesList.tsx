"use client";

import { useEffect, useState } from "react";

interface Device {
  id: string;
  site_id: string;
  name: string;
  kind: string;
  status: string;
  mgmt_ip: string | null;
  first_seen_at: string;
  last_seen_at: string | null;
  updated_at: string;
}

interface Site {
  id: string;
  name: string;
}

function shortTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function statusClass(status: string): string {
  switch (status) {
    case "up":
      return "status status-active";
    case "down":
      return "status status-revoked";
    case "degraded":
      return "status status-stale";
    default:
      return "status status-pending";
  }
}

// DevicesList renders the M7 device inventory (name, kind, site, status,
// management IP, updated/last-seen) from the real /v1/devices API. Client-side
// fetching mirrors the metrics chart pattern, which keeps loading/empty/error
// states observable and testable; the shell handles unauthenticated access.
export default function DevicesList() {
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [sites, setSites] = useState<Site[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [devicesRes, sitesRes] = await Promise.all([
          fetch("/api/v1/devices?limit=100"),
          fetch("/api/v1/sites?limit=100"),
        ]);
        if (!devicesRes.ok) {
          if (!cancelled) {
            setError(`devices unavailable (status ${devicesRes.status})`);
          }
          return;
        }
        const devicesBody = (await devicesRes.json()) as { data?: Device[] };
        const sitesBody = sitesRes.ok
          ? ((await sitesRes.json()) as { data?: Site[] })
          : { data: [] };
        if (!cancelled) {
          setDevices(devicesBody.data ?? []);
          setSites(sitesBody.data ?? []);
        }
      } catch {
        if (!cancelled) {
          setError("network error");
        }
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const siteName = new Map(sites.map((s) => [s.id, s.name]));

  if (error) {
    return (
      <p className="error" data-testid="devices-error">
        {error}
      </p>
    );
  }
  if (devices === null) {
    return (
      <p className="muted" data-testid="devices-loading">
        Loading devices…
      </p>
    );
  }
  if (devices.length === 0) {
    return (
      <p className="muted" data-testid="devices-empty">
        No devices yet. Devices appear here after a manual add or discovery
        (discovery arrives in a later milestone).
      </p>
    );
  }
  return (
    <table data-testid="devices-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Kind</th>
          <th>Site</th>
          <th>Status</th>
          <th>Mgmt IP</th>
          <th>Last seen</th>
          <th>Updated</th>
        </tr>
      </thead>
      <tbody>
        {devices.map((d) => (
          <tr key={d.id}>
            <td>{d.name}</td>
            <td className="muted">{d.kind}</td>
            <td className="muted">{siteName.get(d.site_id) ?? "—"}</td>
            <td>
              <span className={statusClass(d.status)}>{d.status}</span>
            </td>
            <td className="muted">{d.mgmt_ip ?? "—"}</td>
            <td className="muted">{shortTime(d.last_seen_at)}</td>
            <td className="muted">{shortTime(d.updated_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

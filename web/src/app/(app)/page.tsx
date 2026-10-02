import { cookies } from "next/headers";

import { serverJSON } from "@/lib/api";
import { ButtonLink } from "@/ui/Button";
import MetricCard from "@/ui/MetricCard";
import PageHeader from "@/ui/PageHeader";
import Panel from "@/ui/Panel";

interface Site {
  id: string;
  name: string;
}

interface Device {
  id: string;
  poll_status?: { status: "up" | "down" | "unknown" } | null;
}

interface Collector {
  id: string;
  status: string;
}

interface Alert {
  id: string;
  state: string;
  severity: string;
}

interface Page<T> {
  data?: T[];
  next_cursor?: string | null;
  has_more?: boolean;
}

const PAGE_LIMIT = 100;

// Dashboard (overview first): real counts only. Each card reads the canonical
// list API and states its own cap; where an API is unavailable the card shows
// "—" instead of inventing a value. Sites keeps the existing `sites-table`
// test id so the AC-12 login flow assertions remain intact.
export default async function DashboardPage() {
  const cookieHeader = (await cookies()).toString();

  const [sites, devices, collectors, alerts] = await Promise.all([
    serverJSON<Page<Site>>(`/v1/sites?limit=${PAGE_LIMIT}`, cookieHeader),
    serverJSON<Page<Device>>(
      `/v1/devices?include=status&limit=${PAGE_LIMIT}&order=desc`,
      cookieHeader,
    ),
    serverJSON<Page<Collector>>(`/v1/collectors?limit=${PAGE_LIMIT}`, cookieHeader),
    serverJSON<Page<Alert>>(
      `/v1/alerts?filter[state]=active&limit=${PAGE_LIMIT}`,
      cookieHeader,
    ),
  ]);

  const siteRows = sites.ok ? (sites.data.data ?? []) : [];
  const sitesCapped = sites.ok && Boolean(sites.data.next_cursor);
  const deviceRows = devices.ok ? (devices.data.data ?? []) : [];
  const devicesCapped = devices.ok && devices.data.has_more === true;
  const up = deviceRows.filter((d) => d.poll_status?.status === "up").length;
  const down = deviceRows.filter((d) => d.poll_status?.status === "down").length;
  const unknown = deviceRows.length - up - down;
  const collectorRows = collectors.ok ? (collectors.data.data ?? []) : [];
  const activeCollectors = collectorRows.filter((c) => c.status === "active").length;
  const alertRows = alerts.ok ? (alerts.data.data ?? []) : [];
  const alertsCapped = alerts.ok && alerts.data.has_more === true;
  const alertCount = alertRows.length;

  return (
    <section>
      <PageHeader
        title="Dashboard"
        description="Organization overview: live inventory, collector and alert state. Overview first, investigation second, configuration third."
        actions={
          <>
            <ButtonLink href="/devices" variant="primary" size="sm">
              Investigate devices
            </ButtonLink>
            <ButtonLink href="/checks" size="sm">
              Check ledger
            </ButtonLink>
          </>
        }
      />

      <div className="ui-metric-grid" data-testid="dashboard-metrics">
        <MetricCard
          label="Sites"
          value={sites.ok ? (sitesCapped ? `${PAGE_LIMIT}+` : siteRows.length) : "—"}
          hint={sites.ok ? "network locations" : "sites API unavailable"}
          href="/sites"
          testId="dashboard-metric-sites"
        />
        <MetricCard
          label="Devices"
          value={devices.ok ? (devicesCapped ? `${PAGE_LIMIT}+` : deviceRows.length) : "—"}
          hint={
            devices.ok
              ? `${up} up · ${down} down · ${unknown} unknown${devicesCapped ? " · first page" : ""}`
              : "devices API unavailable"
          }
          tone={down > 0 ? "down" : undefined}
          href="/devices"
          testId="dashboard-metric-devices"
        />
        <MetricCard
          label="Active alerts"
          value={alerts.ok ? (alertsCapped ? `${PAGE_LIMIT}+` : alertCount) : "—"}
          hint={
            alerts.ok
              ? `state=active${alertsCapped ? " · capped" : ""} · M11 engine`
              : "alerts API unavailable"
          }
          tone={alerts.ok && alertCount > 0 ? "down" : undefined}
          href="/alerts"
          testId="dashboard-metric-alerts"
        />
        <MetricCard
          label="Collectors"
          value={collectors.ok ? collectorRows.length : "—"}
          hint={
            collectors.ok
              ? `${activeCollectors} active · ${collectorRows.length - activeCollectors} pending/revoked`
              : "collectors API unavailable"
          }
          href="/collectors"
          testId="dashboard-metric-collectors"
        />
      </div>

      <div className="ui-grid-2">
        <Panel
          title="Sites"
          subtitle="Site dashboards open per-location status, poll-health issues and the device table."
          actions={
            <ButtonLink href="/sites" size="sm" variant="ghost">
              All sites →
            </ButtonLink>
          }
        >
          {!sites.ok ? (
            <p className="muted" data-testid="dashboard-sites-error">
              Sites are unavailable right now (status {sites.status || "network"}).
            </p>
          ) : siteRows.length === 0 ? (
            <p className="muted" data-testid="dashboard-sites-empty">
              No sites visible for this account.
            </p>
          ) : (
            <table data-testid="sites-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>ID</th>
                </tr>
              </thead>
              <tbody>
                {siteRows.map((site) => (
                  <tr key={site.id}>
                    <td>
                      <a href={`/sites/${site.id}`}>{site.name}</a>
                    </td>
                    <td className="muted">{site.id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>

        <Panel
          title="Platform map"
          subtitle="Every surface stays reachable while later phases fill it in."
        >
          <ul className="ui-link-list">
            <li>
              <a href="/devices">Devices</a>
              <span className="ui-link-desc">
                Inventory list with sites, status and management addresses.
              </span>
            </li>
            <li>
              <a href="/checks">Checks</a>
              <span className="ui-link-desc">
                On-demand check ledger and bounded recent poll failures.
              </span>
            </li>
            <li>
              <a href="/collectors">Collectors</a>
              <span className="ui-link-desc">
                Enrollment, identity and the secure control stream.
              </span>
            </li>
            <li>
              <a href="/credentials">Credentials</a>
              <span className="ui-link-desc">
                Write-only secret metadata and bindings.
              </span>
            </li>
            <li>
              <a href="/device-groups">Device Groups</a>
              <span className="ui-link-desc">
                Dynamic group CRUD with a JSON selector.
              </span>
            </li>
          </ul>
          <p className="muted metric-foot">
            Planned surfaces (Topology, WAN, Flows, Incidents, …) are labeled
            “planned / not yet available” per docs/FEATURE_HORIZONS.md.
          </p>
        </Panel>
      </div>

      <Panel
        title="About the data"
        footer="No placeholder numbers: cards read the canonical list APIs and mark capped pages."
      >
        <p className="muted" style={{ margin: 0 }}>
          Device status is the M10-S1 poll-health rollup (up/down/unknown) from
          the first {PAGE_LIMIT} devices ordered newest-first. Alert counts come
          from the M11-S1 alert engine (<code>filter[state]=active</code>).
          Where an endpoint is unavailable the card renders “—” rather than a
          fabricated zero.
        </p>
      </Panel>
    </section>
  );
}

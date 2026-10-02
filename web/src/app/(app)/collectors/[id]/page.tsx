import { cookies } from "next/headers";
import { notFound } from "next/navigation";

import CollectorActions from "@/components/CollectorActions";
import MetricChart from "@/features/collectors/MetricChart";
import { serverFetch } from "@/lib/api";
import ErrorState from "@/ui/ErrorState";
import PageHeader from "@/ui/PageHeader";

interface CollectorDetail {
  id: string;
  name: string;
  site_id: string;
  status: string;
  agent_version: string | null;
  hostname: string | null;
  os: string | null;
  enrolled_at: string | null;
  last_heartbeat_at: string | null;
  last_stream_at: string | null;
  connected: boolean;
  policy: { acked_version: number; max_version: number };
  certificate: { not_after: string | null; revoked_at: string | null };
  reported_stats: Record<string, unknown> | null;
}

interface MeResponse {
  user: { role: string };
}

function shortTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function spoolSummary(stats: Record<string, unknown> | null): string {
  if (!stats) return "—";
  const records = stats["spool_records"] ?? 0;
  const bytes = stats["spool_bytes"] ?? 0;
  const dropped = stats["dropped_records_total"] ?? 0;
  const corrupt = stats["corrupt_records_total"] ?? 0;
  return `${records} records · ${bytes} bytes · dropped ${dropped} · corrupt ${corrupt}`;
}

export default async function CollectorDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const cookieHeader = (await cookies()).toString();

  let collector: CollectorDetail | null = null;
  let role = "";
  try {
    const [detailRes, meRes] = await Promise.all([
      serverFetch(`/v1/collectors/${encodeURIComponent(id)}`, cookieHeader),
      serverFetch("/v1/me", cookieHeader),
    ]);
    if (detailRes.ok) {
      collector = (await detailRes.json()) as CollectorDetail;
    } else if (detailRes.status === 404) {
      notFound();
    }
    if (meRes.ok) {
      role = ((await meRes.json()) as MeResponse).user.role;
    }
  } catch {
    /* API unreachable: shell renders the outage */
  }

  if (!collector) {
    return (
      <section>
        <PageHeader
          title="Collector"
          breadcrumbs={[{ label: "Collectors", href: "/collectors" }]}
        />
        <ErrorState
          title="Collector unavailable"
          message="The collector could not be loaded (API unreachable)."
        />
      </section>
    );
  }

  return (
    <section>
      <PageHeader
        title={collector.name}
        breadcrumbs={[{ label: "Collectors", href: "/collectors" }]}
        description="Collector identity, policy sync, spool health and the live telemetry stream."
      />
      <div className="panel" data-testid="collector-detail">
        <table>
          <tbody>
            <tr>
              <th>Status</th>
              <td data-testid="collector-status">{collector.status}</td>
            </tr>
            <tr>
              <th>Stream</th>
              <td>{collector.connected ? "connected" : "offline"}</td>
            </tr>
            <tr>
              <th>Collector ID</th>
              <td className="muted">{collector.id}</td>
            </tr>
            <tr>
              <th>Site</th>
              <td className="muted">{collector.site_id}</td>
            </tr>
            <tr>
              <th>Agent</th>
              <td>{collector.agent_version ?? "—"}</td>
            </tr>
            <tr>
              <th>Hostname / OS</th>
              <td>
                {collector.hostname ?? "—"} · {collector.os ?? "—"}
              </td>
            </tr>
            <tr>
              <th>Policy</th>
              <td data-testid="collector-policy">
                acked v{collector.policy.acked_version} · latest v
                {collector.policy.max_version}
              </td>
            </tr>
            <tr>
              <th>Spool</th>
              <td data-testid="collector-spool">
                {spoolSummary(collector.reported_stats)}
              </td>
            </tr>
            <tr>
              <th>Certificate expires</th>
              <td>{shortTime(collector.certificate.not_after)}</td>
            </tr>
            <tr>
              <th>Enrolled</th>
              <td className="muted">{shortTime(collector.enrolled_at)}</td>
            </tr>
            <tr>
              <th>Last heartbeat</th>
              <td className="muted">{shortTime(collector.last_heartbeat_at)}</td>
            </tr>
            <tr>
              <th>Last stream</th>
              <td className="muted">{shortTime(collector.last_stream_at)}</td>
            </tr>
          </tbody>
        </table>
      </div>
      {role === "admin" && (
        <div style={{ marginTop: 16 }}>
          <CollectorActions collectorID={collector.id} status={collector.status} />
        </div>
      )}
      <div className="panel" style={{ marginTop: 16 }}>
        <h2 style={{ marginTop: 0 }}>Metrics</h2>
        <MetricChart collectorID={collector.id} />
      </div>
    </section>
  );
}

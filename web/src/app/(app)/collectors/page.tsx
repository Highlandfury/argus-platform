import Link from "next/link";
import { cookies } from "next/headers";

import EnrollCollectorForm from "@/components/EnrollCollectorForm";
import { serverFetch } from "@/lib/api";
import PageHeader from "@/ui/PageHeader";

interface Collector {
  id: string;
  name: string;
  site_id: string;
  status: string;
  agent_version: string | null;
  last_heartbeat_at: string | null;
  enrolled_at: string | null;
}

interface MeResponse {
  user: { role: string };
}

interface Site {
  id: string;
  name: string;
}

function statusClass(status: string): string {
  switch (status) {
    case "active":
      return "status status-active";
    case "revoked":
      return "status status-revoked";
    default:
      return "status status-pending";
  }
}

function shortTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

export default async function CollectorsPage() {
  const cookieHeader = (await cookies()).toString();
  let collectors: Collector[] = [];
  let sites: Site[] = [];
  let role = "";
  try {
    const [meRes, listRes, sitesRes] = await Promise.all([
      serverFetch("/v1/me", cookieHeader),
      serverFetch("/v1/collectors?limit=100", cookieHeader),
      serverFetch("/v1/sites?limit=100", cookieHeader),
    ]);
    if (meRes.ok) {
      role = ((await meRes.json()) as MeResponse).user.role;
    }
    if (listRes.ok) {
      collectors =
        ((await listRes.json()) as { data?: Collector[] }).data ?? [];
    }
    if (sitesRes.ok) {
      sites = ((await sitesRes.json()) as { data?: Site[] }).data ?? [];
    }
  } catch {
    /* API unreachable: render empty state; the shell shows the outage */
  }

  return (
    <section>
      <PageHeader
        title="Collectors"
        description="Edge collectors that poll devices and stream telemetry: enrollment, identity, heartbeat and the secure control stream."
      />
      <div className="panel">
        {collectors.length === 0 ? (
          <p className="muted">
            No collectors enrolled yet. Create an enrollment credential and
            start a collector with it.
          </p>
        ) : (
          <table data-testid="collectors-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Status</th>
                <th>Agent</th>
                <th>Last heartbeat</th>
                <th>Enrolled</th>
              </tr>
            </thead>
            <tbody>
              {collectors.map((c) => (
                <tr key={c.id}>
                  <td>
                    <Link href={`/collectors/${c.id}`}>{c.name}</Link>
                  </td>
                  <td>
                    <span className={statusClass(c.status)}>{c.status}</span>
                  </td>
                  <td className="muted">{c.agent_version ?? "—"}</td>
                  <td className="muted">{shortTime(c.last_heartbeat_at)}</td>
                  <td className="muted">{shortTime(c.enrolled_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {role === "admin" && (
        <div style={{ marginTop: 16 }}>
          <EnrollCollectorForm sites={sites} />
        </div>
      )}
    </section>
  );
}

import { cookies } from "next/headers";

import { serverFetch } from "@/lib/api";

interface Site {
  id: string;
  name: string;
}

export default async function DashboardPage() {
  const cookieHeader = (await cookies()).toString();
  let sites: Site[] = [];
  try {
    const res = await serverFetch("/v1/sites?limit=25", cookieHeader);
    if (res.ok) {
      const body = (await res.json()) as { data?: Site[] };
      sites = body.data ?? [];
    }
  } catch {
    /* API unreachable: render the empty state; the shell shows the outage */
  }

  return (
    <section>
      <h1>Dashboard</h1>
      <div className="panel">
        <h2 style={{ marginTop: 0 }}>Sites</h2>
        {sites.length === 0 ? (
          <p className="muted">No sites visible for this account.</p>
        ) : (
          <table data-testid="sites-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>ID</th>
              </tr>
            </thead>
            <tbody>
              {sites.map((s) => (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td className="muted">{s.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <p className="muted" style={{ marginTop: 16 }}>
        Collectors, metrics, and topology arrive in later milestones (M3+).
      </p>
    </section>
  );
}

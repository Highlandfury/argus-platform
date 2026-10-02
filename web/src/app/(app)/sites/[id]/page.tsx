import Link from "next/link";
import { cookies } from "next/headers";
import { notFound } from "next/navigation";
import { Suspense } from "react";

import SiteDashboard from "@/features/visibility/SiteDashboard";
import { serverFetch } from "@/lib/api";

interface Site {
  id: string;
  name: string;
}

// Site dashboard (M10-S3). Sites have no item endpoint in the M10 API, so the
// shell resolves the site name from the scoped list; a resolved list without
// the id is a 404, while an unreachable API renders the outage state.
export default async function SiteDashboardPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const cookieHeader = (await cookies()).toString();

  let sites: Site[] = [];
  let listed = false;
  try {
    const res = await serverFetch("/v1/sites?limit=100", cookieHeader);
    if (res.ok) {
      listed = true;
      sites = ((await res.json()) as { data?: Site[] }).data ?? [];
    }
  } catch {
    // API unreachable: the outage state below.
  }

  const site = sites.find((s) => s.id === id);
  if (listed && !site) notFound();

  if (!site) {
    return (
      <section>
        <h1>Site</h1>
        <div className="panel">Site unavailable.</div>
      </section>
    );
  }

  return (
    <section>
      <h1>{site.name}</h1>
      <p className="muted">
        <Link href="/">← Dashboard</Link> · site status mix, recent poll-health
        failures and the device table below.
      </p>
      <Suspense fallback={<p className="muted">Loading site dashboard…</p>}>
        <SiteDashboard siteID={site.id} siteName={site.name} />
      </Suspense>
    </section>
  );
}

import { cookies } from "next/headers";

import { serverJSON } from "@/lib/api";
import { ButtonLink } from "@/ui/Button";
import EmptyState from "@/ui/EmptyState";
import ErrorState from "@/ui/ErrorState";
import PageHeader from "@/ui/PageHeader";
import Panel from "@/ui/Panel";

interface Site {
  id: string;
  name: string;
}

interface Page {
  data?: Site[];
  next_cursor?: string | null;
}

// Sites list (Phase 1): the simple, real list from GET /v1/sites with links to
// each site dashboard (/sites/{id}). The site dashboard experience itself is
// unchanged (M10-S3).
export default async function SitesPage() {
  const cookieHeader = (await cookies()).toString();
  const res = await serverJSON<Page>("/v1/sites?limit=100", cookieHeader);
  const sites = res.ok ? (res.data.data ?? []) : [];
  const capped = res.ok && Boolean(res.data.next_cursor);

  return (
    <section>
      <PageHeader
        title="Sites"
        description="Locations and network boundaries. A site dashboard rolls up status mix, recent poll failures and its devices."
        actions={
          <ButtonLink href="/devices" size="sm">
            Devices
          </ButtonLink>
        }
      />

      {!res.ok ? (
        <ErrorState
          title="Sites unavailable"
          message={`The sites API did not respond (status ${res.status || "network"}).`}
          testId="sites-error"
        />
      ) : sites.length === 0 ? (
        <EmptyState
          title="No sites yet"
          description="Sites are created with the organization during onboarding; none are visible to this account."
          testId="sites-empty"
        />
      ) : (
        <Panel
          title="All sites"
          subtitle={capped ? "First 100 sites shown (cursor paging)" : undefined}
          flush
        >
          <table data-testid="sites-list-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Site ID</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sites.map((site) => (
                <tr key={site.id}>
                  <td>
                    <a href={`/sites/${site.id}`}>{site.name}</a>
                  </td>
                  <td className="muted">{site.id}</td>
                  <td style={{ textAlign: "right" }}>
                    <ButtonLink
                      href={`/sites/${site.id}`}
                      size="sm"
                      variant="ghost"
                    >
                      Open dashboard →
                    </ButtonLink>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </section>
  );
}

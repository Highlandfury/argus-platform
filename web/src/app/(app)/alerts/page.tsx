import { cookies } from "next/headers";

import AlertsView from "@/features/alerts/AlertsView";
import MaintenanceWindowsView from "@/features/alerts/MaintenanceWindowsView";
import SilencesView from "@/features/alerts/SilencesView";
import { serverFetch } from "@/lib/api";
import PageHeader from "@/ui/PageHeader";
import Tabs from "@/ui/Tabs";

interface MeResponse {
  user: { role: string };
}

const TAB_DESCRIPTIONS: Record<string, string> = {
  queue:
    "The M11 alert queue: real state, severity, evidence, resource and suppression context. Filters and pagination are URL-driven; the live stream patches the visible rows.",
  maintenance:
    "Planned suppression owner: while a window is active, matching alerts are Suppressed (maintenance) — still recorded and evaluated, never notified.",
  silences:
    "Ad-hoc operator silences with a mandatory reason and a mandatory expiry (at most 30 days). Created from an alert's detail page.",
};

// Alerts workspace (M11-S3b). The queue, maintenance windows and silences are
// URL-driven tabs of one surface: the shell's established IA already groups
// alerting under Observability → Alerts, so no parallel Admin route is
// invented (see M11_EVIDENCE §S3b for the placement decision). Capability-gated
// write surfaces resolve the caller's role server-side; the API still enforces
// every capability.
export default async function AlertsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const requested = Array.isArray(params.tab) ? params.tab[0] : params.tab;
  const active =
    requested === "maintenance" || requested === "silences"
      ? requested
      : "queue";

  const cookieHeader = (await cookies()).toString();
  let role = "";
  try {
    const meRes = await serverFetch("/v1/me", cookieHeader);
    if (meRes.ok) {
      role = ((await meRes.json()) as MeResponse).user.role;
    }
  } catch {
    // The shell renders the outage; the views keep their own error states.
  }
  const canSilence = role === "admin";

  return (
    <section>
      <PageHeader
        title="Alerts"
        description={TAB_DESCRIPTIONS[active]}
        tabs={
          <Tabs
            items={[
              { value: "queue", label: "Queue" },
              { value: "maintenance", label: "Maintenance Windows" },
              { value: "silences", label: "Silences" },
            ]}
            defaultValue="queue"
            ariaLabel="Alerts sections"
            testId="alerts-tabs"
          />
        }
      />
      {active === "queue" && <AlertsView />}
      {active === "maintenance" && (
        <MaintenanceWindowsView canWrite={canSilence} />
      )}
      {active === "silences" && <SilencesView canWrite={canSilence} />}
    </section>
  );
}

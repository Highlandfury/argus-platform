import { cookies } from "next/headers";
import { notFound } from "next/navigation";

import AlertDetailView from "@/features/alerts/AlertDetailView";
import type { AlertDetail } from "@/features/alerts/types";
import { serverFetch } from "@/lib/api";

interface MeResponse {
  user: { role: string };
}

// Alert detail (M11-S3b). The shell resolves the alert server-side so unknown
// or out-of-scope ids render the API's real 404; the client view owns the live
// SSE refresh, the actions and the deliveries panel with their own
// loading/empty/error states. Actions are hidden for read-only roles
// (viewer holds alert.read only) while the API keeps enforcing capabilities.
export default async function AlertDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const cookieHeader = (await cookies()).toString();

  let alert: AlertDetail | null = null;
  let role = "";
  let alertStatus = 0;
  try {
    const [alertRes, meRes] = await Promise.all([
      serverFetch(`/v1/alerts/${encodeURIComponent(id)}`, cookieHeader),
      serverFetch("/v1/me", cookieHeader),
    ]);
    alertStatus = alertRes.status;
    if (alertRes.ok) alert = (await alertRes.json()) as AlertDetail;
    if (meRes.ok) role = ((await meRes.json()) as MeResponse).user.role;
  } catch {
    // API unreachable: the client view renders the outage/retry state.
  }

  if (alertStatus === 404) notFound();

  return (
    <AlertDetailView
      alertId={id}
      initialAlert={alert}
      canAct={role === "admin"}
    />
  );
}

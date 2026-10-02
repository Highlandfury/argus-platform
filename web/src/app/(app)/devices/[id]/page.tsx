import { cookies } from "next/headers";
import { notFound } from "next/navigation";

import DeviceDetail, {
  type Device,
} from "@/features/visibility/DeviceDetail";
import { serverFetch } from "@/lib/api";
import ErrorState from "@/ui/ErrorState";
import PageHeader from "@/ui/PageHeader";

interface MeResponse {
  user: { role: string };
}

interface Site {
  id: string;
  name: string;
}

// Device detail (M10-S3). The shell resolves the device server-side so unknown
// or out-of-scope ids render the real 404; the client component owns the live
// status, identity, interface, chart and check panels with their own
// loading/empty/error states.
export default async function DeviceDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const cookieHeader = (await cookies()).toString();
  const encoded = encodeURIComponent(id);

  let device: Device | null = null;
  let sites: Site[] = [];
  let role = "";
  let deviceStatus = 0;
  try {
    const [deviceRes, sitesRes, meRes] = await Promise.all([
      serverFetch(`/v1/devices/${encoded}`, cookieHeader),
      serverFetch("/v1/sites?limit=100", cookieHeader),
      serverFetch("/v1/me", cookieHeader),
    ]);
    deviceStatus = deviceRes.status;
    if (deviceRes.ok) device = (await deviceRes.json()) as Device;
    if (sitesRes.ok) sites = ((await sitesRes.json()) as { data?: Site[] }).data ?? [];
    if (meRes.ok) role = ((await meRes.json()) as MeResponse).user.role;
  } catch {
    // API unreachable: fall through to the unavailable state below.
  }

  // Enumeration resistance: missing, foreign and out-of-scope devices all come
  // back as 404 from the API, so the shell renders the same 404 page.
  if (deviceStatus === 404) notFound();

  if (!device) {
    return (
      <section>
        <PageHeader
          title="Device"
          breadcrumbs={[{ label: "Devices", href: "/devices" }]}
        />
        <ErrorState
          title="Device unavailable"
          message="The device could not be loaded (API unreachable)."
        />
      </section>
    );
  }

  const siteName = sites.find((s) => s.id === device.site_id)?.name ?? null;
  return (
    <section>
      <DeviceDetail device={device} siteName={siteName} role={role} />
    </section>
  );
}

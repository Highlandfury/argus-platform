import { cookies } from "next/headers";
import { notFound } from "next/navigation";

import InterfaceDetail, {
  type InterfaceDetailData,
} from "@/features/visibility/InterfaceDetail";
import { serverFetch } from "@/lib/api";
import ErrorState from "@/ui/ErrorState";
import PageHeader from "@/ui/PageHeader";

// Interface detail (M10-S3). The shell resolves the interface and its parent
// device server-side (404 for unknown/out-of-scope ids); the client component
// renders identity and the counter charts from the canonical query API.
export default async function InterfaceDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const cookieHeader = (await cookies()).toString();
  const encoded = encodeURIComponent(id);

  let iface: InterfaceDetailData | null = null;
  let deviceName = "";
  let ifaceStatus = 0;
  try {
    const ifaceRes = await serverFetch(`/v1/interfaces/${encoded}`, cookieHeader);
    ifaceStatus = ifaceRes.status;
    if (ifaceRes.ok) {
      iface = (await ifaceRes.json()) as InterfaceDetailData;
      const deviceRes = await serverFetch(
        `/v1/devices/${encodeURIComponent(iface.device_id)}`,
        cookieHeader,
      );
      if (deviceRes.ok) {
        deviceName =
          ((await deviceRes.json()) as { name?: string }).name ?? "device";
      }
    }
  } catch {
    // API unreachable: fall through to the unavailable state below.
  }

  if (ifaceStatus === 404) notFound();

  if (!iface) {
    return (
      <section>
        <PageHeader
          title="Interface"
          breadcrumbs={[
            { label: "Devices", href: "/devices" },
            { label: "Interface" },
          ]}
        />
        <ErrorState
          title="Interface unavailable"
          message="The interface could not be loaded (API unreachable)."
        />
      </section>
    );
  }

  return (
    <section>
      <InterfaceDetail iface={iface} deviceName={deviceName || "device"} />
    </section>
  );
}

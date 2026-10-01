import { cookies } from "next/headers";

import DeviceInventory from "@/features/inventory/DeviceInventory";
import { serverFetch } from "@/lib/api";

interface MeResponse {
  user: { role: string };
}

interface Site {
  id: string;
  name: string;
}

// Devices list + manual add (M7-S4a; the full device detail page is M10). The
// page resolves the caller's role and the site picker options server-side;
// the list itself is a client feature so loading/empty/error states stay
// observable, and the add form is rendered for admins only (the API enforces
// the same rule: admin role + device.write capability + CSRF).
export default async function DevicesPage() {
  const cookieHeader = (await cookies()).toString();
  let sites: Site[] = [];
  let role = "";
  try {
    const [meRes, sitesRes] = await Promise.all([
      serverFetch("/v1/me", cookieHeader),
      serverFetch("/v1/sites?limit=100", cookieHeader),
    ]);
    if (meRes.ok) {
      role = ((await meRes.json()) as MeResponse).user.role;
    }
    if (sitesRes.ok) {
      sites = ((await sitesRes.json()) as { data?: Site[] }).data ?? [];
    }
  } catch {
    // API unreachable: the list renders the outage; keep the picker empty.
  }

  return (
    <section>
      <h1>Devices</h1>
      <DeviceInventory sites={sites} canWrite={role === "admin"} />
    </section>
  );
}

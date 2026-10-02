import { cookies } from "next/headers";

import DeviceGroupsManager from "@/features/inventory/DeviceGroupsManager";
import { serverFetch } from "@/lib/api";

interface MeResponse {
  user: { role: string };
}

// Device groups (M10-S3b-2): CRUD for dynamic groups whose selector is stored
// as JSON. The page resolves the caller's role server-side; the manager keeps
// loading/empty/error states observable and renders read-only for non-admins
// (the API enforces admin + device_group.write + CSRF independently).
export default async function DeviceGroupsPage() {
  const cookieHeader = (await cookies()).toString();
  let role = "";
  try {
    const meRes = await serverFetch("/v1/me", cookieHeader);
    if (meRes.ok) role = ((await meRes.json()) as MeResponse).user.role;
  } catch {
    // API unreachable: the manager renders the outage from its own fetch.
  }

  return (
    <section>
      <h1>Device groups</h1>
      <DeviceGroupsManager canWrite={role === "admin"} />
    </section>
  );
}

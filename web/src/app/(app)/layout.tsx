import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import AppShell, { type Me } from "@/components/shell/AppShell";
import ErrorState from "@/ui/ErrorState";
import Panel from "@/ui/Panel";
import { serverFetch } from "@/lib/api";

function Outage({ message }: { message: string }) {
  return (
    <div className="shell-outage">
      <Panel title="Argus">
        <ErrorState title="API unavailable" message={message} />
      </Panel>
    </div>
  );
}

// (app) layout: resolves the caller's identity/org, then renders the Phase 1
// AppShell (sidebar + topbar + content well). Unauthenticated callers are sent
// to /login; API outages render an explicit outage surface instead of a blank
// shell.
export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const cookieHeader = (await cookies()).toString();
  let res: Response;
  try {
    res = await serverFetch("/v1/me", cookieHeader);
  } catch {
    return <Outage message="API unreachable — is the server running?" />;
  }
  if (res.status === 401) {
    redirect("/login");
  }
  if (!res.ok) {
    return (
      <Outage message={`API unavailable (status ${res.status}). Is the server running?`} />
    );
  }
  const me = (await res.json()) as Me;
  return <AppShell me={me}>{children}</AppShell>;
}

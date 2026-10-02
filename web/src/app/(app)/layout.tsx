import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import LogoutButton from "@/components/LogoutButton";
import { serverFetch } from "@/lib/api";

interface MeResponse {
  user: { id: string; email: string; role: string };
  org: { id: string; slug: string; name: string };
}

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const cookieHeader = (await cookies()).toString();
  let res: Response;
  try {
    res = await serverFetch("/v1/me", cookieHeader);
  } catch {
    return (
      <div className="shell">
        <main className="shell-main">
          <div className="panel">API unreachable — is the server running?</div>
        </main>
      </div>
    );
  }
  if (res.status === 401) {
    redirect("/login");
  }
  if (!res.ok) {
    return (
      <div className="shell">
        <main className="shell-main">
          <div className="panel">
            API unavailable (status {res.status}). Is the server running?
          </div>
        </main>
      </div>
    );
  }
  const me = (await res.json()) as MeResponse;
  return (
    <div className="shell">
      <header className="shell-header">
        <span className="brand">ARGUS</span>
        <nav className="shell-nav">
          <a href="/devices" data-testid="nav-devices">
            Devices
          </a>
          <a href="/device-groups" data-testid="nav-device-groups">
            Device groups
          </a>
          <a href="/credentials" data-testid="nav-credentials">
            Credentials
          </a>
          <a href="/collectors" data-testid="nav-collectors">
            Collectors
          </a>
        </nav>
        <span className="who" data-testid="org-name">
          {me.org.name}
        </span>
        <span className="who">
          {me.user.email} · {me.user.role}
        </span>
        <LogoutButton />
      </header>
      <main className="shell-main">{children}</main>
    </div>
  );
}

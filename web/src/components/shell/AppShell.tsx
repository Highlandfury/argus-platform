"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

import Sidebar from "./Sidebar";
import Topbar from "./Topbar";

export interface Me {
  user: { id: string; email: string; role: string };
  org: { id: string; slug: string; name: string };
}

// AppShell owns the persistent chrome: fixed sidebar, sticky topbar and the
// content well. The sidebar is always visible on desktop; below 900px it
// becomes an off-canvas panel toggled from the topbar (CSS-driven, see
// globals.css). Server-rendered page trees arrive as children.
export default function AppShell({
  me,
  children,
}: {
  me: Me;
  children: ReactNode;
}) {
  const pathname = usePathname();
  const [navOpen, setNavOpen] = useState(false);

  // Close the mobile drawer whenever the route changes.
  useEffect(() => {
    setNavOpen(false);
  }, [pathname]);

  return (
    <div className="app-shell">
      <Sidebar
        pathname={pathname}
        open={navOpen}
        onNavigate={() => setNavOpen(false)}
      />
      {navOpen && (
        <div
          className="sidebar-backdrop"
          aria-hidden="true"
          onClick={() => setNavOpen(false)}
        />
      )}
      <div className="app-main">
        <Topbar
          email={me.user.email}
          role={me.user.role}
          orgName={me.org.name}
          onMenuToggle={() => setNavOpen((value) => !value)}
        />
        <main className="app-content" data-testid="app-content">
          {children}
        </main>
      </div>
    </div>
  );
}

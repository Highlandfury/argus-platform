// Sidebar navigation map. Groups follow the product hierarchy:
// overview first, investigation second, configuration third, admin last.
// `planned` items route to a clearly-labeled ComingSoon page and get a subtle
// hollow marker in the rail; their backend/depth arrives in later phases.
export interface NavItem {
  href: string;
  label: string;
  glyph: string;
  testId?: string;
  planned?: boolean;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Overview",
    items: [
      { href: "/", label: "Dashboard", glyph: "▦", testId: "nav-dashboard" },
      { href: "/sites", label: "Sites", glyph: "◉", testId: "nav-sites" },
      { href: "/devices", label: "Devices", glyph: "▤", testId: "nav-devices" },
      { href: "/topology", label: "Topology", glyph: "⬡", testId: "nav-topology", planned: true },
      { href: "/interfaces", label: "Interfaces", glyph: "⇄", testId: "nav-interfaces", planned: true },
      { href: "/wan", label: "WAN", glyph: "◍", testId: "nav-wan", planned: true },
      { href: "/services", label: "Services", glyph: "⊕", testId: "nav-services", planned: true },
    ],
  },
  {
    label: "Observability",
    items: [
      { href: "/checks", label: "Checks", glyph: "✓", testId: "nav-checks" },
      { href: "/metrics", label: "Metrics", glyph: "∿", testId: "nav-metrics", planned: true },
      { href: "/flows", label: "Flows", glyph: "⇶", testId: "nav-flows", planned: true },
      { href: "/logs", label: "Logs", glyph: "≡", testId: "nav-logs", planned: true },
      { href: "/incidents", label: "Incidents", glyph: "⚠", testId: "nav-incidents", planned: true },
      { href: "/alerts", label: "Alerts", glyph: "◔", testId: "nav-alerts" },
    ],
  },
  {
    label: "Operations",
    items: [
      { href: "/collectors", label: "Collectors", glyph: "◫", testId: "nav-collectors" },
      { href: "/config", label: "Config", glyph: "⚒", testId: "nav-config", planned: true },
      { href: "/credentials", label: "Credentials", glyph: "⚿", testId: "nav-credentials" },
      { href: "/ipam", label: "IPAM", glyph: "⊞", testId: "nav-ipam", planned: true },
    ],
  },
  {
    label: "Admin",
    items: [
      { href: "/device-groups", label: "Device Groups", glyph: "≣", testId: "nav-device-groups" },
      { href: "/users", label: "Users / Roles", glyph: "⚇", testId: "nav-users", planned: true },
      { href: "/settings", label: "Settings", glyph: "⚙", testId: "nav-settings", planned: true },
    ],
  },
];

// isActive marks a nav item for the current pathname. "/" matches exactly;
// other items also stay active on their detail routes (/devices/{id}).
export function isNavActive(pathname: string, href: string): boolean {
  if (href === "/") return pathname === "/";
  return pathname === href || pathname.startsWith(`${href}/`);
}

import Link from "next/link";

import { isNavActive, NAV_GROUPS } from "./nav";

// BrandMark is the Argus product mark: a small radar/eye geometry drawn
// inline (no image assets, no gradients).
export function BrandMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
        <circle cx="8" cy="8" r="6.2" stroke="currentColor" strokeWidth="1.2" opacity="0.55" />
        <circle cx="8" cy="8" r="1.6" fill="currentColor" />
        <path d="M8 1.8 L12.6 11.4" stroke="currentColor" strokeWidth="1.1" opacity="0.9" />
        <circle cx="12.6" cy="11.4" r="1.1" fill="currentColor" />
      </svg>
    </span>
  );
}

export interface SidebarProps {
  pathname: string;
  open: boolean;
  onNavigate: () => void;
}

export default function Sidebar({ pathname, open, onNavigate }: SidebarProps) {
  return (
    <aside
      className={`sidebar${open ? " is-open" : ""}`}
      aria-label="Primary navigation"
      data-testid="sidebar"
    >
      <div className="sidebar-brand">
        <BrandMark />
        <span className="brand-name">
          ARGUS
          <span className="brand-sub">Network Observability</span>
        </span>
      </div>
      <nav className="sidebar-nav">
        {NAV_GROUPS.map((group) => (
          <div className="nav-group" key={group.label}>
            <div className="nav-group-label">{group.label}</div>
            {group.items.map((item) => {
              const active = isNavActive(pathname, item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`nav-item${active ? " is-active" : ""}`}
                  aria-current={active ? "page" : undefined}
                  data-testid={item.testId}
                  data-planned={item.planned ? "true" : undefined}
                  title={item.planned ? `${item.label} — planned` : item.label}
                  onClick={onNavigate}
                >
                  <span className="nav-item-glyph" aria-hidden="true">
                    {item.glyph}
                  </span>
                  <span>{item.label}</span>
                  {item.planned && (
                    <span
                      className="nav-item-dot"
                      title="planned"
                      aria-label="planned"
                    />
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>
      <div className="sidebar-foot">NOC console · Phase 1 shell</div>
    </aside>
  );
}

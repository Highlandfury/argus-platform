"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";

export interface TabItem {
  value: string;
  label: string;
}

export interface TabsProps {
  items: TabItem[];
  /** URL parameter that stores the active tab (default: "tab"). */
  param?: string;
  /** Value treated as the default; it is omitted from the URL. */
  defaultValue?: string;
  ariaLabel?: string;
  testId?: string;
}

// Tabs is URL-driven: each tab is a link that updates the query parameter,
// preserving every other parameter so filters stay put. Server components can
// read the same param to render content.
export default function Tabs({
  items,
  param = "tab",
  defaultValue,
  ariaLabel,
  testId,
}: TabsProps) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const active = searchParams.get(param) ?? defaultValue ?? items[0]?.value;

  function hrefFor(value: string): string {
    const params = new URLSearchParams(searchParams.toString());
    if (value === defaultValue) params.delete(param);
    else params.set(param, value);
    const qs = params.toString();
    return qs ? `${pathname}?${qs}` : pathname;
  }

  return (
    <nav className="ui-tabs" aria-label={ariaLabel} data-testid={testId}>
      {items.map((item) => {
        const isActive = item.value === active;
        return (
          <Link
            key={item.value}
            href={hrefFor(item.value)}
            className={`ui-tab${isActive ? " is-active" : ""}`}
            aria-current={isActive ? "page" : undefined}
            scroll={false}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}

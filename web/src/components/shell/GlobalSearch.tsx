"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

// GlobalSearch is the Phase 1 global entry point: Enter routes to the devices
// list with ?q=<query> (the device inventory already supports URL-driven
// search). The ⌘K command palette is noted as planned but deliberately not
// faked.
export default function GlobalSearch({ initialQuery = "" }: { initialQuery?: string }) {
  const router = useRouter();
  const [query, setQuery] = useState(initialQuery);

  function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = query.trim();
    router.push(trimmed ? `/devices?q=${encodeURIComponent(trimmed)}` : "/devices");
  }

  return (
    <form className="global-search" role="search" onSubmit={onSubmit}>
      <span className="search-icon" aria-hidden="true">
        ⌕
      </span>
      <input
        aria-label="Search devices by name or management IP"
        placeholder="Search devices by name or mgmt IP…"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        data-testid="global-search"
        autoComplete="off"
        spellCheck={false}
      />
      <span
        className="search-kbd"
        title="Command palette (⌘K) is planned; Enter searches devices today"
        aria-hidden="true"
      >
        ⌘K
      </span>
    </form>
  );
}

"use client";

import { useEffect, useRef, useState } from "react";

import LogoutButton from "@/components/LogoutButton";

export interface UserMenuProps {
  email: string;
  role: string;
  orgName: string;
}

// UserMenu is the topbar account menu: identity metadata plus Sign out
// (LogoutButton keeps the `logout` test id and behavior).
export default function UserMenu({ email, role, orgName }: UserMenuProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }
    window.addEventListener("mousedown", onPointerDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onPointerDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="user-menu" ref={rootRef}>
      <button
        type="button"
        className="user-menu-btn"
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
        data-testid="user-menu"
      >
        <span aria-hidden="true">◔</span>
        <span className="user-menu-email">{email}</span>
        <span aria-hidden="true">▾</span>
      </button>
      {open && (
        <div className="user-menu-pop" role="menu">
          <div className="user-menu-meta">
            <strong>{email}</strong>
            <span>
              {role} · {orgName}
            </span>
          </div>
          <LogoutButton />
        </div>
      )}
    </div>
  );
}

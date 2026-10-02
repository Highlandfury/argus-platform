"use client";

import { useEffect } from "react";
import type { ReactNode } from "react";

export interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  side?: "left" | "right";
  footer?: ReactNode;
  children: ReactNode;
  testId?: string;
}

// Drawer is a basic right/left sheet used for secondary flows. Escape and
// overlay clicks close it; no focus trap (basic primitive, no new deps).
export default function Drawer({
  open,
  onClose,
  title,
  side = "right",
  footer,
  children,
  testId,
}: DrawerProps) {
  useEffect(() => {
    if (!open) return;
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div
      className="ui-overlay ui-drawer-wrap"
      data-side={side}
      onClick={onClose}
      data-testid={testId}
    >
      <aside
        className="ui-drawer"
        role="dialog"
        aria-modal="true"
        onClick={(event) => event.stopPropagation()}
      >
        {title !== undefined && (
          <header className="ui-drawer-head">
            <span>{title}</span>
            <button
              type="button"
              className="ui-close"
              aria-label="Close"
              onClick={onClose}
            >
              ✕
            </button>
          </header>
        )}
        <div className="ui-drawer-body">{children}</div>
        {footer !== undefined && <footer className="ui-drawer-foot">{footer}</footer>}
      </aside>
    </div>
  );
}

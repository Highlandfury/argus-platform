"use client";

import { useEffect } from "react";
import type { ReactNode } from "react";

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
  testId?: string;
}

// Dialog is a basic modal. Escape and overlay clicks close it; basic focus
// handling only (no new dependencies).
export default function Dialog({
  open,
  onClose,
  title,
  footer,
  children,
  testId,
}: DialogProps) {
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
      className="ui-overlay ui-dialog-wrap"
      onClick={onClose}
      data-testid={testId}
    >
      <div
        className="ui-dialog"
        role="dialog"
        aria-modal="true"
        onClick={(event) => event.stopPropagation()}
      >
        {title !== undefined && (
          <header className="ui-dialog-head">
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
        <div className="ui-dialog-body">{children}</div>
        {footer !== undefined && <footer className="ui-dialog-foot">{footer}</footer>}
      </div>
    </div>
  );
}

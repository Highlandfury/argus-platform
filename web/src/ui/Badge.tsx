import type { ReactNode } from "react";

export type BadgeVariant =
  | "neutral"
  | "accent"
  | "healthy"
  | "degraded"
  | "down"
  | "unknown"
  | "maintenance"
  | "pending";

export interface BadgeProps {
  variant?: BadgeVariant;
  /** Show a leading dot (still paired with the label text). */
  dot?: boolean;
  title?: string;
  testId?: string;
  className?: string;
  children: ReactNode;
}

// Badge is a compact, text-first label. Variants map to the same status
// semantics as StatusIndicator; no arbitrary per-instance colors.
export default function Badge({
  variant = "neutral",
  dot = false,
  title,
  testId,
  className,
  children,
}: BadgeProps) {
  return (
    <span
      className={`ui-badge${className ? ` ${className}` : ""}`}
      data-variant={variant}
      title={title}
      data-testid={testId}
    >
      {dot && <span className="ui-badge-dot" aria-hidden="true" />}
      {children}
    </span>
  );
}

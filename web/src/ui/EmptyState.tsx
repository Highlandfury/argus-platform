import type { ReactNode } from "react";

export interface EmptyStateProps {
  title: ReactNode;
  description?: ReactNode;
  icon?: ReactNode;
  actions?: ReactNode;
  className?: string;
  testId?: string;
}

// EmptyState is the honest "nothing here yet" surface. It never fabricates
// data; callers point at the real next action or the planning reference.
export default function EmptyState({
  title,
  description,
  icon = "∅",
  actions,
  className,
  testId,
}: EmptyStateProps) {
  return (
    <div
      className={`ui-empty${className ? ` ${className}` : ""}`}
      data-testid={testId}
    >
      <span className="ui-empty-icon" aria-hidden="true">
        {icon}
      </span>
      <h2 className="ui-empty-title">{title}</h2>
      {description !== undefined && (
        <p className="ui-empty-desc">{description}</p>
      )}
      {actions !== undefined && (
        <div className="ui-empty-actions">{actions}</div>
      )}
    </div>
  );
}

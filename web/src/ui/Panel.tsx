import type { ReactNode } from "react";

export interface PanelProps {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  footer?: ReactNode;
  /** Remove body padding (useful for flush tables). */
  flush?: boolean;
  className?: string;
  bodyClassName?: string;
  testId?: string;
  children: ReactNode;
}

// Panel is the one container primitive: 1px border, small radius, a compact
// header with uppercase section title. No nested cards; no giant padding.
export default function Panel({
  title,
  subtitle,
  actions,
  footer,
  flush = false,
  className,
  bodyClassName,
  testId,
  children,
}: PanelProps) {
  const hasHead = title !== undefined || actions !== undefined;
  return (
    <section
      className={`ui-panel${className ? ` ${className}` : ""}`}
      data-testid={testId}
    >
      {hasHead && (
        <header className="ui-panel-head">
          <div>
            {title !== undefined && (
              <h2 className="ui-panel-title">{title}</h2>
            )}
            {subtitle !== undefined && (
              <p className="ui-panel-sub">{subtitle}</p>
            )}
          </div>
          {actions !== undefined && (
            <div className="ui-panel-actions">{actions}</div>
          )}
        </header>
      )}
      <div
        className={`${flush ? "" : "ui-panel-body"}${bodyClassName ? ` ${bodyClassName}` : ""}`}
      >
        {children}
      </div>
      {footer !== undefined && <footer className="ui-panel-foot">{footer}</footer>}
    </section>
  );
}

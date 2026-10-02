import Link from "next/link";
import type { ReactNode } from "react";

export interface Breadcrumb {
  label: string;
  href?: string;
}

export interface PageHeaderProps {
  title: ReactNode;
  description?: ReactNode;
  breadcrumbs?: Breadcrumb[];
  actions?: ReactNode;
  /** URL-driven tabs or other sub-navigation rendered under the title. */
  tabs?: ReactNode;
  testId?: string;
}

// PageHeader gives every route the same hierarchy: optional breadcrumbs, a
// single h1, one-line description, right-aligned actions and optional tabs.
export default function PageHeader({
  title,
  description,
  breadcrumbs,
  actions,
  tabs,
  testId,
}: PageHeaderProps) {
  return (
    <div className="ui-page-header" data-testid={testId}>
      <div className="ui-page-header-main">
        {breadcrumbs && breadcrumbs.length > 0 && (
          <nav className="ui-breadcrumbs" aria-label="Breadcrumb">
            {breadcrumbs.map((crumb, index) => (
              <span key={`${crumb.label}-${index}`}>
                {index > 0 && (
                  <span className="ui-breadcrumb-sep" aria-hidden="true">
                    /
                  </span>
                )}{" "}
                {crumb.href ? (
                  <Link href={crumb.href}>{crumb.label}</Link>
                ) : (
                  <span>{crumb.label}</span>
                )}
              </span>
            ))}
          </nav>
        )}
        <h1 className="ui-page-title">{title}</h1>
        {description !== undefined && (
          <p className="ui-page-desc">{description}</p>
        )}
        {tabs !== undefined && <div className="ui-page-tabs">{tabs}</div>}
      </div>
      {actions !== undefined && <div className="ui-page-actions">{actions}</div>}
    </div>
  );
}

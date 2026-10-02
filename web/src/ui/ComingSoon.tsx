import type { ReactNode } from "react";

import Badge from "./Badge";
import EmptyState from "./EmptyState";

export interface ComingSoonProps {
  title: string;
  /** Plan placement, e.g. "Phase 3 · MVP Step 10" or "V2". */
  milestone: string;
  description: string;
  /** Section reference into docs/FEATURE_HORIZONS.md. */
  horizonsRef: string;
  /** Concrete capabilities planned for this surface. */
  planned?: string[];
  actions?: ReactNode;
  testId?: string;
}

// ComingSoon is the shared placeholder for routes whose backend/experience is
// not built yet. It is deliberately explicit: "planned / not yet available",
// the milestone, and the FEATURE_HORIZONS reference. No mock data.
export default function ComingSoon({
  title,
  milestone,
  description,
  horizonsRef,
  planned,
  actions,
  testId = "coming-soon",
}: ComingSoonProps) {
  return (
    <div data-testid={testId}>
      <EmptyState
        className="ui-coming-soon"
        icon="◌"
        title={
          <span>
            {title}{" "}
            <Badge variant="pending">planned / not yet available</Badge>
          </span>
        }
        description={description}
        actions={
          <>
            <div className="ui-coming-soon-meta">
              <span>{milestone}</span>
              <span aria-hidden="true">·</span>
              <span>FEATURE_HORIZONS.md {horizonsRef}</span>
            </div>
            {planned && planned.length > 0 && (
              <ul className="ui-coming-soon-list">
                {planned.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            )}
            {actions}
          </>
        }
      />
    </div>
  );
}

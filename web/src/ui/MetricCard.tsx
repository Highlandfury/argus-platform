import Link from "next/link";
import type { ReactNode } from "react";

import type { StatusTone } from "./StatusIndicator";

export interface MetricCardProps {
  label: ReactNode;
  value: ReactNode;
  unit?: ReactNode;
  hint?: ReactNode;
  /** Tint the value with a canonical status tone. */
  tone?: StatusTone;
  href?: string;
  title?: string;
  testId?: string;
}

// MetricCard is the dashboard KPI tile: label, tabular value, one-line hint.
// Values are always sourced from real APIs (or "—" with an explicit note);
// the component never implies data that does not exist.
export default function MetricCard({
  label,
  value,
  unit,
  hint,
  tone,
  href,
  title,
  testId,
}: MetricCardProps) {
  const body = (
    <>
      <span className="ui-metric-label">{label}</span>
      <span className="ui-metric-value">
        {value}
        {unit !== undefined && <span className="ui-metric-unit">{unit}</span>}
      </span>
      {hint !== undefined && <span className="ui-metric-hint">{hint}</span>}
    </>
  );

  if (href) {
    return (
      <Link
        href={href}
        className="ui-metric-card"
        data-tone={tone}
        title={title}
        data-testid={testId}
      >
        {body}
      </Link>
    );
  }
  return (
    <div
      className="ui-metric-card"
      data-tone={tone}
      title={title}
      data-testid={testId}
    >
      {body}
    </div>
  );
}

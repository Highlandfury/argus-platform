import type { ReactNode } from "react";

import type { StatusTone } from "./StatusIndicator";

export interface TimelineItem {
  id?: string;
  time: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  tone?: StatusTone;
}

export interface TimelineProps {
  items: TimelineItem[];
  className?: string;
  testId?: string;
}

// Timeline is a compact vertical event rail (alerts, incidents, check
// history). Tones reuse the canonical status semantics.
export default function Timeline({ items, className, testId }: TimelineProps) {
  return (
    <ol
      className={`ui-timeline${className ? ` ${className}` : ""}`}
      data-testid={testId}
    >
      {items.map((item, index) => (
        <li
          key={item.id ?? index}
          className="ui-timeline-item"
          data-tone={item.tone ?? "unknown"}
        >
          <span className="ui-timeline-dot" aria-hidden="true" />
          <div className="ui-timeline-body">
            <div className="ui-timeline-time">{item.time}</div>
            <div className="ui-timeline-title">{item.title}</div>
            {item.description !== undefined && (
              <div className="ui-timeline-desc">{item.description}</div>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}

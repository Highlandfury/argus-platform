import type { CSSProperties } from "react";

export interface SkeletonProps {
  width?: number | string;
  height?: number | string;
  className?: string;
  style?: CSSProperties;
  testId?: string;
}

export default function Skeleton({
  width = "100%",
  height = 12,
  className,
  style,
  testId,
}: SkeletonProps) {
  return (
    <span
      className={`ui-skeleton${className ? ` ${className}` : ""}`}
      style={{ width, height, ...style }}
      aria-hidden="true"
      data-testid={testId}
    />
  );
}

export function SkeletonLines({
  lines = 3,
  testId,
}: {
  lines?: number;
  testId?: string;
}) {
  return (
    <span className="ui-skeleton-lines" aria-hidden="true" data-testid={testId}>
      {Array.from({ length: lines }, (_, index) => (
        <Skeleton
          key={index}
          width={index === lines - 1 ? "60%" : "100%"}
          height={12}
        />
      ))}
    </span>
  );
}

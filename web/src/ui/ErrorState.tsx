import type { ReactNode } from "react";

export interface ErrorStateProps {
  title?: ReactNode;
  message: ReactNode;
  action?: ReactNode;
  testId?: string;
}

// ErrorState renders a failed request/operation with the server-authored
// message where available. It takes no retry handler: callers that need a
// retry pass a client-rendered action element.
export default function ErrorState({
  title = "Request failed",
  message,
  action,
  testId,
}: ErrorStateProps) {
  return (
    <div className="ui-error" role="alert" data-testid={testId}>
      <span className="ui-error-title">{title}</span>
      <span className="ui-error-desc">{message}</span>
      {action !== undefined && <div className="ui-empty-actions">{action}</div>}
    </div>
  );
}

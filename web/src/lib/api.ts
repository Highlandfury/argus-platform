export const API_BASE = process.env.ARGUS_API_BASE ?? "http://127.0.0.1:8080";

// serverFetch issues a same-process fetch from server components, forwarding
// the caller's cookies to the API (the rewrite path is only for browsers).
export async function serverFetch(
  path: string,
  cookieHeader: string,
  init?: RequestInit,
): Promise<Response> {
  return fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { ...(init?.headers ?? {}), cookie: cookieHeader },
    cache: "no-store",
  });
}

// readCSRF reads the double-submit token cookie (client components only).
export function readCSRF(): string {
  if (typeof document === "undefined") return "";
  return (
    document.cookie
      .split("; ")
      .find((c) => c.startsWith("argus_csrf="))
      ?.split("=")[1] ?? ""
  );
}

// problemDetail extracts the problem+json `detail` (or falls back to the
// status) so client fetches render the same server-authored message the
// existing forms show instead of a generic failure string.
export async function problemDetail(
  res: Response,
  fallback?: string,
): Promise<string> {
  const body = (await res.json().catch(() => null)) as
    | { detail?: string }
    | null;
  return body?.detail ?? fallback ?? `request failed (status ${res.status})`;
}

export type FetchResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; error: string };

// fetchJSON is the read-side counterpart to the existing inline fetch blocks:
// same no-store semantics, one uniform error string. Client components only.
export async function fetchJSON<T>(
  url: string,
  init?: RequestInit,
): Promise<FetchResult<T>> {
  try {
    const res = await fetch(url, { cache: "no-store", ...init });
    if (!res.ok) {
      return { ok: false, status: res.status, error: await problemDetail(res) };
    }
    return { ok: true, data: (await res.json()) as T };
  } catch {
    return { ok: false, status: 0, error: "network error" };
  }
}

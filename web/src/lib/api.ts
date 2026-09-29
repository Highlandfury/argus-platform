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

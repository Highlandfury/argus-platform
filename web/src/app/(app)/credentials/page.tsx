import { cookies } from "next/headers";

import CreateCredentialForm from "@/components/CreateCredentialForm";
import RotateCredential from "@/components/RotateCredential";
import { serverFetch } from "@/lib/api";

interface CredentialBinding {
  id: string;
  scope_type: string;
  scope_id: string;
  priority: number;
  created_at: string;
}

interface CredentialMetadata {
  id: string;
  name: string;
  kind: string;
  metadata: Record<string, unknown>;
  rotated_at: string | null;
  created_at: string;
  updated_at: string;
  bindings: CredentialBinding[];
}

interface MeResponse {
  user: { role: string };
}

function shortTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

function metadataSummary(metadata: Record<string, unknown>): string {
  const entries = Object.entries(metadata ?? {});
  if (entries.length === 0) return "—";
  return entries
    .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(", ");
}

function bindingSummary(bindings: CredentialBinding[]): string {
  if (!bindings || bindings.length === 0) return "unbound";
  return bindings
    .map((b) => `${b.scope_type}@${b.priority}`)
    .join(", ");
}

// Credential metadata surface (M7-S4): metadata only. Secrets are write-only
// and submitted once through the create/rotate forms; they are never rendered,
// stored client-side, or returned by the API.
export default async function CredentialsPage() {
  const cookieHeader = (await cookies()).toString();
  let credentials: CredentialMetadata[] = [];
  let role = "";
  let loadError = "";
  try {
    const [listRes, meRes] = await Promise.all([
      serverFetch("/v1/credentials?limit=100", cookieHeader),
      serverFetch("/v1/me", cookieHeader),
    ]);
    if (listRes.ok) {
      credentials =
        ((await listRes.json()) as { data?: CredentialMetadata[] }).data ?? [];
    } else {
      loadError = `credentials unavailable (status ${listRes.status})`;
    }
    if (meRes.ok) {
      role = ((await meRes.json()) as MeResponse).user.role;
    }
  } catch {
    // API unreachable: the shell renders the outage; keep the list empty.
    loadError = "network error";
  }

  return (
    <section>
      <h1>Credentials</h1>
      <div className="panel">
        {loadError ? (
          <p className="error" data-testid="credentials-error">
            {loadError}
          </p>
        ) : credentials.length === 0 ? (
          <p className="muted" data-testid="credentials-empty">
            No credentials yet. Create one below; the secret is sealed and can
            never be read back.
          </p>
        ) : (
          <table data-testid="credentials-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Metadata</th>
                <th>Bindings</th>
                <th>Rotated</th>
                <th>Created</th>
                <th>Updated</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {credentials.map((c) => (
                <tr key={c.id}>
                  <td data-testid={`credential-name-${c.name}`}>{c.name}</td>
                  <td className="muted">{c.kind}</td>
                  <td className="muted">{metadataSummary(c.metadata)}</td>
                  <td className="muted">{bindingSummary(c.bindings)}</td>
                  <td className="muted">{shortTime(c.rotated_at)}</td>
                  <td className="muted">{shortTime(c.created_at)}</td>
                  <td className="muted">{shortTime(c.updated_at)}</td>
                  <td>
                    {role === "admin" && (
                      <RotateCredential credentialID={c.id} name={c.name} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {role === "admin" && (
        <div style={{ marginTop: 16 }}>
          <CreateCredentialForm />
        </div>
      )}
      <p className="muted" style={{ marginTop: 16 }}>
        Secrets are write-only: the API returns metadata only and there is no
        reveal action for any role. Bindings are managed through the API
        (<code>/v1/credentials/&#123;id&#125;/bind</code>) until the M10 surface.
      </p>
    </section>
  );
}

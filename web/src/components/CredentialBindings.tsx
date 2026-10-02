"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { fetchJSON, problemDetail, readCSRF } from "@/lib/api";

interface CredentialBinding {
  id: string;
  scope_type: "org" | "site" | "device_group" | "device" | string;
  scope_id: string;
  priority: number;
  created_at: string;
}

interface CredentialMetadata {
  id: string;
  name: string;
  kind: string;
  bindings?: CredentialBinding[];
}

interface Site {
  id: string;
  name: string;
}

interface Group {
  id: string;
  name: string;
}

// Binding scope types offered by the add-binding form. Device-scope bindings
// stay on the device detail page (DeviceCredentialPanel); existing device
// bindings are still listed and can be unbound here.
const BIND_SCOPE_TYPES = [
  { value: "site", label: "Site" },
  { value: "device_group", label: "Device group" },
  { value: "org", label: "Organization" },
];

// CredentialBindings is the M10-S3b-1 per-credential binding surface on
// /credentials. It lists the binding summaries returned by
// GET /v1/credentials (metadata only, never secrets) and drives
// POST /v1/credentials/{id}/bind|unbind with the session + CSRF pair. The
// organization id/name come from GET /v1/me so "org" is bindable without a
// picker.
export default function CredentialBindings({
  orgID,
  orgName,
}: {
  orgID: string;
  orgName: string;
}) {
  const router = useRouter();
  const [credentials, setCredentials] = useState<CredentialMetadata[] | null>(
    null,
  );
  const [sites, setSites] = useState<Site[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [targetsError, setTargetsError] = useState("");
  const [loadError, setLoadError] = useState("");
  const [forbidden, setForbidden] = useState("");

  const load = useCallback(async () => {
    const [credsRes, sitesRes, groupsRes] = await Promise.all([
      fetchJSON<{ data?: CredentialMetadata[] }>(
        "/api/v1/credentials?limit=100&order=desc",
      ),
      fetchJSON<{ data?: Site[] }>("/api/v1/sites?limit=100"),
      fetchJSON<{ data?: Group[] }>("/api/v1/device-groups?limit=100"),
    ]);
    if (credsRes.ok) {
      setCredentials(credsRes.data.data ?? []);
      setLoadError("");
      setForbidden("");
    } else if (credsRes.status === 403) {
      // The credential surface is org-wide; a scoped caller gets the
      // server-authored forbidden detail instead of a generic failure.
      setForbidden(credsRes.error);
      setCredentials(null);
    } else {
      setLoadError(credsRes.error);
      setCredentials(null);
    }
    if (sitesRes.ok) setSites(sitesRes.data.data ?? []);
    if (groupsRes.ok) setGroups(groupsRes.data.data ?? []);
    setTargetsError(
      !sitesRes.ok || !groupsRes.ok
        ? "Some binding targets could not be loaded; the pickers may be incomplete."
        : "",
    );
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function refresh() {
    await load();
    // Re-render the server-rendered credential table so its binding summary
    // column matches the new state.
    router.refresh();
  }

  const loading = credentials === null && !loadError && !forbidden;

  return (
    <section className="panel" data-testid="credential-bindings-panel">
      <h2 style={{ marginTop: 0 }}>Credential bindings</h2>
      <p className="muted">
        Bind a credential to a site, device group or the whole organization.
        Resolution order is device &gt; device_group &gt; site &gt; org, and
        higher priority wins within one tier. Device-scope bindings are managed
        from the device detail page.
      </p>
      {loading && (
        <p className="muted" data-testid="credential-bindings-loading">
          Loading bindings…
        </p>
      )}
      {forbidden && (
        <p className="error" data-testid="credential-bindings-forbidden">
          {forbidden}
        </p>
      )}
      {loadError && (
        <p className="error" data-testid="credential-bindings-error">
          {loadError}
        </p>
      )}
      {targetsError && (
        <p className="muted" data-testid="credential-bindings-targets-error">
          {targetsError}
        </p>
      )}
      {credentials !== null && credentials.length === 0 && (
        <p className="muted" data-testid="credential-bindings-no-credentials">
          No credentials exist yet. Create one above first.
        </p>
      )}
      {credentials?.map((credential) => (
        <BindingCard
          key={credential.id}
          credential={credential}
          sites={sites}
          groups={groups}
          orgID={orgID}
          orgName={orgName}
          onChanged={refresh}
        />
      ))}
    </section>
  );
}

function BindingCard({
  credential,
  sites,
  groups,
  orgID,
  orgName,
  onChanged,
}: {
  credential: CredentialMetadata;
  sites: Site[];
  groups: Group[];
  orgID: string;
  orgName: string;
  onChanged: () => Promise<void>;
}) {
  const [scopeType, setScopeType] = useState("site");
  const [targetID, setTargetID] = useState("");
  const [priority, setPriority] = useState("0");
  const [busy, setBusy] = useState(false);
  const [unbindBusyID, setUnbindBusyID] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  // Keep the target picker aligned with the selected scope type.
  useEffect(() => {
    if (scopeType === "site") setTargetID(sites[0]?.id ?? "");
    else if (scopeType === "device_group") setTargetID(groups[0]?.id ?? "");
    else setTargetID(orgID);
  }, [scopeType, sites, groups, orgID]);

  const bindings = credential.bindings ?? [];

  function labelFor(type: string, id: string): string {
    if (type === "site") return sites.find((s) => s.id === id)?.name ?? id;
    if (type === "device_group")
      return groups.find((g) => g.id === id)?.name ?? id;
    if (type === "org") return id === orgID ? `${orgName} (this organization)` : id;
    if (type === "device") return `device ${id}`;
    return id;
  }

  async function bind(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setMessage("");
    if (targetID === "") {
      setError("select a target first");
      return;
    }
    const parsedPriority = Number(priority);
    if (!Number.isInteger(parsedPriority)) {
      setError("priority must be an integer");
      return;
    }
    setBusy(true);
    try {
      const res = await fetch(`/api/v1/credentials/${credential.id}/bind`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify({
          scope_type: scopeType,
          scope_id: targetID,
          priority: parsedPriority,
        }),
      });
      if (!res.ok) {
        setError(await problemDetail(res, `bind failed (status ${res.status})`));
        return;
      }
      setMessage(`Bound to ${labelFor(scopeType, targetID)}.`);
      await onChanged();
    } catch {
      setError("network error");
    } finally {
      setBusy(false);
    }
  }

  async function unbind(binding: CredentialBinding) {
    setError("");
    setMessage("");
    setUnbindBusyID(binding.id);
    try {
      const res = await fetch(`/api/v1/credentials/${credential.id}/unbind`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify({
          scope_type: binding.scope_type,
          scope_id: binding.scope_id,
        }),
      });
      if (!res.ok) {
        setError(
          await problemDetail(res, `unbind failed (status ${res.status})`),
        );
        return;
      }
      setMessage(`Unbound ${binding.scope_type} binding.`);
      await onChanged();
    } catch {
      setError("network error");
    } finally {
      setUnbindBusyID(null);
    }
  }

  const siteOptionsAvailable = scopeType === "site" && sites.length > 0;
  const groupOptionsAvailable =
    scopeType === "device_group" && groups.length > 0;
  const targetAvailable =
    scopeType === "org" || siteOptionsAvailable || groupOptionsAvailable;

  return (
    <section
      data-testid={`credential-bindings-${credential.name}`}
      style={{ marginTop: 16, borderTop: "1px solid #2a2f3a", paddingTop: 12 }}
    >
      <h3 className="vis-subhead" style={{ marginTop: 0 }}>
        {credential.name}{" "}
        <span className="muted">({credential.kind})</span>
      </h3>
      {bindings.length === 0 ? (
        <p
          className="muted"
          data-testid={`credential-bindings-empty-${credential.name}`}
        >
          No bindings.
        </p>
      ) : (
        <table data-testid={`credential-bindings-table-${credential.name}`}>
          <thead>
            <tr>
              <th>Scope</th>
              <th>Target</th>
              <th>Priority</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {bindings.map((binding) => (
              <tr
                key={binding.id}
                data-testid={`credential-binding-row-${credential.name}-${binding.scope_type}-${binding.scope_id}`}
              >
                <td>{binding.scope_type}</td>
                <td className="muted">
                  {labelFor(binding.scope_type, binding.scope_id)}
                </td>
                <td>{binding.priority}</td>
                <td>
                  <button
                    type="button"
                    className="btn-sm btn-ghost"
                    data-testid={`credential-binding-unbind-${credential.name}-${binding.scope_type}-${binding.scope_id}`}
                    disabled={unbindBusyID === binding.id}
                    onClick={() => void unbind(binding)}
                  >
                    {unbindBusyID === binding.id ? "Unbinding…" : "Unbind"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <form
        onSubmit={bind}
        data-testid={`credential-binding-form-${credential.name}`}
      >
        <label htmlFor={`credential-binding-scope-${credential.name}`}>
          Bind to scope
        </label>
        <select
          id={`credential-binding-scope-${credential.name}`}
          value={scopeType}
          onChange={(e) => setScopeType(e.target.value)}
          data-testid={`credential-binding-scope-${credential.name}`}
        >
          {BIND_SCOPE_TYPES.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </select>
        <label htmlFor={`credential-binding-target-${credential.name}`}>
          Target
        </label>
        <select
          id={`credential-binding-target-${credential.name}`}
          value={targetID}
          onChange={(e) => setTargetID(e.target.value)}
          data-testid={`credential-binding-target-${credential.name}`}
        >
          {scopeType === "site" &&
            sites.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          {scopeType === "device_group" &&
            groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          {scopeType === "org" && (
            <option value={orgID}>{orgName} (this organization)</option>
          )}
        </select>
        {scopeType === "site" && sites.length === 0 && (
          <p className="muted">No sites are available to bind.</p>
        )}
        {scopeType === "device_group" && groups.length === 0 && (
          <p className="muted">
            No device groups exist yet; create one before binding at this scope.
          </p>
        )}
        <label htmlFor={`credential-binding-priority-${credential.name}`}>
          Priority (optional, default 0)
        </label>
        <input
          id={`credential-binding-priority-${credential.name}`}
          type="number"
          value={priority}
          onChange={(e) => setPriority(e.target.value)}
          data-testid={`credential-binding-priority-${credential.name}`}
        />
        <button
          type="submit"
          className="btn-sm"
          disabled={busy || !targetAvailable}
          data-testid={`credential-binding-submit-${credential.name}`}
        >
          {busy ? "Binding…" : "Bind"}
        </button>
      </form>

      {message && (
        <p
          className="muted"
          data-testid={`credential-binding-result-${credential.name}`}
        >
          {message}
        </p>
      )}
      {error && (
        <p
          className="error"
          data-testid={`credential-binding-error-${credential.name}`}
        >
          {error}
        </p>
      )}
    </section>
  );
}

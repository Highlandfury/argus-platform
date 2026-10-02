"use client";

import Link from "next/link";
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
  bindings: CredentialBinding[];
}

interface BoundCredential {
  credential: CredentialMetadata;
  binding: CredentialBinding;
}

// Dispatch precedence tiers (same ranks as the server resolver:
// internal/modules/credentials/models.go).
const SCOPE_RANK: Record<string, number> = {
  device: 1,
  device_group: 2,
  site: 3,
  org: 4,
};

function rank(binding: CredentialBinding): number {
  return SCOPE_RANK[binding.scope_type] ?? 5;
}

// DeviceCredentialPanel is the M10-S3a SNMP binding surface on the device
// detail page. It lists the credential metadata (bindings included), derives
// the device-scope bindings and the effective credential (device > site >
// org; the device_group tier is not resolvable in this view, matching the
// server resolver's current nil group-membership hook), and drives
// POST /v1/credentials/{id}/bind|unbind with the session + CSRF pair.
// The credential surface is org-wide: a 403 (non-org-wide caller) is rendered
// verbatim instead of a generic failure.
export default function DeviceCredentialPanel({
  deviceID,
  siteID,
  canManage,
}: {
  deviceID: string;
  siteID: string;
  canManage: boolean;
}) {
  const [credentials, setCredentials] = useState<CredentialMetadata[] | null>(
    null,
  );
  const [loadError, setLoadError] = useState("");
  const [forbidden, setForbidden] = useState("");
  const [selectedID, setSelectedID] = useState("");
  const [priority, setPriority] = useState("0");
  const [bindBusy, setBindBusy] = useState(false);
  const [bindMessage, setBindMessage] = useState("");
  const [bindError, setBindError] = useState("");
  const [unbindBusyID, setUnbindBusyID] = useState<string | null>(null);
  const [unbindError, setUnbindError] = useState("");

  const load = useCallback(async () => {
    if (!canManage) return;
    const res = await fetchJSON<{ data?: CredentialMetadata[] }>(
      "/api/v1/credentials?limit=100&order=desc",
    );
    if (res.ok) {
      setCredentials(res.data.data ?? []);
      setLoadError("");
      setForbidden("");
      return;
    }
    if (res.status === 403) {
      setForbidden(res.error);
      setCredentials(null);
      return;
    }
    setLoadError(res.error);
  }, [canManage]);

  useEffect(() => {
    void load();
  }, [load]);

  if (!canManage) {
    return (
      <section className="panel" data-testid="device-credentials-panel">
        <h2 style={{ marginTop: 0 }}>SNMP credentials</h2>
        <p className="muted" data-testid="device-credentials-readonly">
          Managing credential bindings requires the admin role and an org-wide
          scope (<code>credential.write</code>).{" "}
          <Link href="/credentials">View credentials</Link>.
        </p>
      </section>
    );
  }

  const all = credentials ?? [];
  const deviceScoped: BoundCredential[] = [];
  const candidates: BoundCredential[] = [];
  let hasGroupBindings = false;
  for (const credential of all) {
    for (const binding of credential.bindings ?? []) {
      if (binding.scope_type === "device_group") hasGroupBindings = true;
      if (binding.scope_type === "device" && binding.scope_id === deviceID) {
        deviceScoped.push({ credential, binding });
      }
      if (
        (binding.scope_type === "device" && binding.scope_id === deviceID) ||
        (binding.scope_type === "site" && binding.scope_id === siteID) ||
        binding.scope_type === "org"
      ) {
        candidates.push({ credential, binding });
      }
    }
  }
  // Same ordering as credentials.selectEffective: scope rank, then higher
  // priority, then the lowest credential id (UUIDv7 ids are time-sortable,
  // so that is the oldest credential).
  candidates.sort((a, b) => {
    if (rank(a.binding) !== rank(b.binding)) {
      return rank(a.binding) - rank(b.binding);
    }
    if (a.binding.priority !== b.binding.priority) {
      return b.binding.priority - a.binding.priority;
    }
    return a.credential.id < b.credential.id
      ? -1
      : a.credential.id > b.credential.id
        ? 1
        : 0;
  });
  const effective = candidates[0] ?? null;
  const loading = credentials === null && !loadError && !forbidden;

  async function bind(e: React.FormEvent) {
    e.preventDefault();
    setBindError("");
    setBindMessage("");
    if (selectedID === "") {
      setBindError("select a credential first");
      return;
    }
    const parsedPriority = Number(priority);
    if (!Number.isInteger(parsedPriority)) {
      setBindError("priority must be an integer");
      return;
    }
    const selected = all.find((c) => c.id === selectedID);
    setBindBusy(true);
    try {
      const res = await fetch(`/api/v1/credentials/${selectedID}/bind`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify({
          scope_type: "device",
          scope_id: deviceID,
          priority: parsedPriority,
        }),
      });
      if (!res.ok) {
        setBindError(
          await problemDetail(res, `bind failed (status ${res.status})`),
        );
        return;
      }
      setBindMessage(`Bound ${selected?.name ?? "credential"} to this device.`);
      await load();
    } catch {
      setBindError("network error");
    } finally {
      setBindBusy(false);
    }
  }

  async function unbind(credential: CredentialMetadata) {
    setUnbindError("");
    setBindMessage("");
    setUnbindBusyID(credential.id);
    try {
      const res = await fetch(`/api/v1/credentials/${credential.id}/unbind`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": readCSRF(),
        },
        body: JSON.stringify({ scope_type: "device", scope_id: deviceID }),
      });
      if (!res.ok) {
        setUnbindError(
          await problemDetail(res, `unbind failed (status ${res.status})`),
        );
        return;
      }
      setBindMessage(`Unbound ${credential.name} from this device.`);
      await load();
    } catch {
      setUnbindError("network error");
    } finally {
      setUnbindBusyID(null);
    }
  }

  return (
    <section className="panel" data-testid="device-credentials-panel">
      <h2 style={{ marginTop: 0 }}>SNMP credentials</h2>
      <p className="muted">
        Resolution order: device &gt; device_group &gt; site &gt; org, higher
        priority wins within a tier.{" "}
        <Link
          href="/credentials"
          data-testid="device-credentials-create-link"
        >
          Create an SNMP credential
        </Link>
        .
      </p>

      {loading && (
        <p className="muted" data-testid="device-credentials-loading">
          Loading credentials…
        </p>
      )}
      {forbidden && (
        <p className="error" data-testid="device-credentials-forbidden">
          {forbidden}
        </p>
      )}
      {loadError && (
        <p className="error" data-testid="device-credentials-error">
          {loadError}
        </p>
      )}

      {credentials !== null && (
        <>
          <h3 className="vis-subhead">Bound to this device</h3>
          {deviceScoped.length === 0 ? (
            <p className="muted" data-testid="device-credentials-empty">
              No credential is bound directly to this device.
            </p>
          ) : (
            <table data-testid="device-credentials-table">
              <thead>
                <tr>
                  <th>Credential</th>
                  <th>Kind</th>
                  <th>Priority</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {deviceScoped.map(({ credential, binding }) => (
                  <tr
                    key={binding.id}
                    data-testid={`device-credential-row-${credential.name}`}
                  >
                    <td>{credential.name}</td>
                    <td className="muted">{credential.kind}</td>
                    <td>{binding.priority}</td>
                    <td>
                      <button
                        type="button"
                        className="btn-sm btn-ghost"
                        data-testid={`device-credential-unbind-${credential.name}`}
                        disabled={unbindBusyID === credential.id}
                        onClick={() => void unbind(credential)}
                      >
                        {unbindBusyID === credential.id
                          ? "Unbinding…"
                          : "Unbind"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <h3 className="vis-subhead">Effective for this device</h3>
          {effective ? (
            <p data-testid="device-credentials-effective">
              <strong>{effective.credential.name}</strong>{" "}
              <span className="muted">
                ({effective.credential.kind}, via {effective.binding.scope_type}{" "}
                binding, priority {effective.binding.priority})
              </span>
            </p>
          ) : (
            <p
              className="muted"
              data-testid="device-credentials-effective-empty"
            >
              No effective credential — SNMP polls for this device will fail
              until one is bound.
            </p>
          )}
          {hasGroupBindings && (
            <p className="muted" data-testid="device-credentials-group-note">
              Device-group bindings exist in this organization; group
              membership is not resolvable in this view (the current server
              resolver does not evaluate the device_group tier either), so the
              effective result above is provisional.
            </p>
          )}

          <h3 className="vis-subhead">Bind a credential</h3>
          {all.length === 0 ? (
            <p className="muted" data-testid="device-credentials-no-credentials">
              No credentials exist yet.{" "}
              <Link href="/credentials">Create an SNMP credential</Link> first.
            </p>
          ) : (
            <form onSubmit={bind} data-testid="device-credentials-bind-form">
              <label htmlFor="device-credential-select">Credential</label>
              <select
                id="device-credential-select"
                value={selectedID}
                onChange={(e) => setSelectedID(e.target.value)}
                data-testid="device-credentials-bind-select"
              >
                <option value="">Select a credential…</option>
                {all.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.kind})
                  </option>
                ))}
              </select>
              <label htmlFor="device-credential-priority">
                Priority (optional, default 0)
              </label>
              <input
                id="device-credential-priority"
                type="number"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                data-testid="device-credentials-bind-priority"
              />
              <button
                type="submit"
                className="btn-sm"
                disabled={bindBusy || selectedID === ""}
                data-testid="device-credentials-bind-submit"
              >
                {bindBusy ? "Binding…" : "Bind to device"}
              </button>
            </form>
          )}

          {bindMessage && (
            <p className="muted" data-testid="device-credentials-bind-result">
              {bindMessage}
            </p>
          )}
          {bindError && (
            <p className="error" data-testid="device-credentials-bind-error">
              {bindError}
            </p>
          )}
          {unbindError && (
            <p className="error" data-testid="device-credentials-unbind-error">
              {unbindError}
            </p>
          )}
        </>
      )}
    </section>
  );
}

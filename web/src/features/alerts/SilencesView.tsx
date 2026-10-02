"use client";

import { useEffect, useState } from "react";

import { fetchJSON, problemDetail, readCSRF } from "@/lib/api";
import Badge from "@/ui/Badge";
import Button, { ButtonLink } from "@/ui/Button";
import Dialog from "@/ui/Dialog";
import EmptyState from "@/ui/EmptyState";
import ErrorState from "@/ui/ErrorState";
import Panel from "@/ui/Panel";
import Skeleton from "@/ui/Skeleton";

import {
  shortId,
  shortTime,
  silenceStatus,
  silenceTargetSummary,
} from "./format";
import {
  type DeviceRef,
  type Silence,
  type SilencePage,
  type SiteRef,
} from "./types";

const PAGE_LIMIT = 25;

// SilencesView is the M11-S3b operator-silence list: ad-hoc exact matchers
// (alert id / fingerprint / scope), mandatory reason and mandatory <= 30 day
// expiry. It is a tab of /alerts so the queue, the detail dialog and the
// silence list stay one workspace.
export default function SilencesView({ canWrite }: { canWrite: boolean }) {
  const [silences, setSilences] = useState<Silence[] | null>(null);
  const [nextCursor, setNextCursor] = useState("");
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [sites, setSites] = useState<SiteRef[]>([]);
  const [devices, setDevices] = useState<DeviceRef[]>([]);

  const [pendingDelete, setPendingDelete] = useState<Silence | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setSilences(null);
      setError("");
      const res = await fetchJSON<SilencePage>(
        `/api/v1/silences?limit=${PAGE_LIMIT}`,
      );
      if (cancelled) return;
      if (res.ok) {
        setSilences(res.data.data ?? []);
        setNextCursor(res.data.next_cursor ?? "");
        setHasMore(res.data.has_more ?? false);
      } else {
        setError(res.error);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [reloadToken]);

  useEffect(() => {
    let cancelled = false;
    async function loadNames() {
      const [sitesRes, devicesRes] = await Promise.all([
        fetchJSON<{ data?: SiteRef[] }>("/api/v1/sites?limit=100"),
        fetchJSON<{ data?: DeviceRef[] }>("/api/v1/devices?limit=100&order=desc"),
      ]);
      if (cancelled) return;
      if (sitesRes.ok) setSites(sitesRes.data.data ?? []);
      if (devicesRes.ok) setDevices(devicesRes.data.data ?? []);
    }
    void loadNames();
    return () => {
      cancelled = true;
    };
  }, []);

  const siteNames = new Map(sites.map((site) => [site.id, site.name]));
  const deviceNames = new Map(
    devices.map((device) => [device.id, device.name]),
  );

  async function deleteSilence(): Promise<void> {
    if (!pendingDelete) return;
    setDeleting(true);
    setDeleteError("");
    try {
      const res = await fetch(
        `/api/v1/silences/${encodeURIComponent(pendingDelete.id)}`,
        {
          method: "DELETE",
          headers: { "X-CSRF-Token": readCSRF() },
        },
      );
      if (!res.ok && res.status !== 204) {
        setDeleteError(await problemDetail(res));
        return;
      }
      setNotice("Silence deleted. Matching firing alerts re-notify at the next evaluation.");
      setPendingDelete(null);
      setReloadToken((token) => token + 1);
    } catch {
      setDeleteError("network error");
    } finally {
      setDeleting(false);
    }
  }

  async function loadMore() {
    if (nextCursor === "" || loadingMore) return;
    setLoadingMore(true);
    try {
      const res = await fetchJSON<SilencePage>(
        `/api/v1/silences?limit=${PAGE_LIMIT}&cursor=${encodeURIComponent(
          nextCursor,
        )}`,
      );
      if (res.ok) {
        setSilences((rows) => [...(rows ?? []), ...(res.data.data ?? [])]);
        setNextCursor(res.data.next_cursor ?? "");
        setHasMore(res.data.has_more ?? false);
      } else {
        setError(res.error);
      }
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <section data-testid="silences-view">
      <Panel
        title="Silences"
        subtitle="Operator silences with a mandatory reason and a mandatory expiry (at most 30 days). Matching alerts stay Suppressed (silence): recorded and evaluated, never notified, until the silence ends."
        actions={
          <ButtonLink href="/alerts" size="sm" variant="secondary">
            Open the alert queue
          </ButtonLink>
        }
        testId="silences-panel"
      >
        {notice !== "" && (
          <p className="muted" data-testid="silences-notice">
            {notice}
          </p>
        )}
        {error !== "" && (
          <ErrorState
            title="Silences unavailable"
            message={error}
            action={
              <Button
                size="sm"
                variant="secondary"
                onClick={() => setReloadToken((token) => token + 1)}
              >
                Try again
              </Button>
            }
            testId="silences-error"
          />
        )}
        {error === "" && silences === null && (
          <div data-testid="silences-loading" aria-busy="true">
            <Skeleton height={14} width="85%" />
            <div style={{ height: 8 }} />
            <Skeleton height={14} width="70%" />
          </div>
        )}
        {error === "" && silences !== null && silences.length === 0 && (
          <EmptyState
            title="No silences"
            description="Silences are created from an alert's detail page (Silence action) and expire automatically at their bounds."
            testId="silences-empty"
          />
        )}
        {error === "" && silences !== null && silences.length > 0 && (
          <>
            <div className="alert-table-wrap">
              <table data-testid="silences-table">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Reason</th>
                    <th>Target</th>
                    <th>Starts</th>
                    <th>Ends</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {silences.map((silence) => {
                    const status = silenceStatus(silence);
                    return (
                      <tr
                        key={silence.id}
                        data-testid={`silences-row-${silence.id}`}
                        data-active={silence.active ? "true" : "false"}
                      >
                        <td>
                          <Badge
                            variant={status.variant}
                            testId={`silence-status-${silence.id}`}
                          >
                            {status.label}
                          </Badge>
                        </td>
                        <td data-testid={`silence-reason-${silence.id}`}>
                          {silence.reason}
                        </td>
                        <td
                          className="muted"
                          data-testid={`silence-target-${silence.id}`}
                        >
                          {silenceTargetSummary(
                            silence.match,
                            siteNames,
                            deviceNames,
                          )}
                        </td>
                        <td className="muted">{shortTime(silence.starts_at)}</td>
                        <td className="muted">{shortTime(silence.ends_at)}</td>
                        <td style={{ textAlign: "right" }}>
                          {canWrite && (
                            <Button
                              size="sm"
                              variant="danger"
                              onClick={() => {
                                setDeleteError("");
                                setPendingDelete(silence);
                              }}
                              data-testid={`silence-delete-${silence.id}`}
                            >
                              Delete
                            </Button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {hasMore && (
              <div className="btn-row" style={{ marginTop: 12 }}>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={loadingMore}
                  onClick={() => void loadMore()}
                  data-testid="silences-load-more"
                >
                  {loadingMore ? "Loading…" : "Load more"}
                </Button>
              </div>
            )}
          </>
        )}
        <p className="muted alert-note" style={{ marginTop: 12 }}>
          The API enforces the 30-day expiry bound and org-wide scope for
          fingerprint-only silences; out-of-scope targets are denied
          server-side.
        </p>
      </Panel>

      <Dialog
        open={pendingDelete !== null}
        onClose={() => setPendingDelete(null)}
        title="Delete silence"
        testId="silence-delete-dialog"
        footer={
          <>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setPendingDelete(null)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              variant="danger"
              disabled={deleting}
              onClick={() => void deleteSilence()}
              data-testid="silence-delete-confirm"
            >
              {deleting ? "Deleting…" : "Delete"}
            </Button>
          </>
        }
      >
        <p className="muted">
          Delete the silence for{" "}
          <strong>
            {pendingDelete
              ? silenceTargetSummary(pendingDelete.match, siteNames, deviceNames)
              : ""}
          </strong>{" "}
          ({pendingDelete ? shortId(pendingDelete.id) : ""})? Firing alerts
          re-notify at the next evaluation once it is gone.
        </p>
        {deleteError !== "" && (
          <p className="error" data-testid="silence-delete-error">
            {deleteError}
          </p>
        )}
      </Dialog>
    </section>
  );
}

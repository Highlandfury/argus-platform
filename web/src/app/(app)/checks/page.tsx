import ChecksView from "@/features/checks/ChecksView";

// Checks (M10-S3b-3): org-wide on-demand check ledger + bounded recent poll
// failures. Reads only (`device.read`); scope is enforced server-side, so the
// page needs no role resolution.
export default function ChecksPage() {
  return (
    <section>
      <h1>Checks</h1>
      <ChecksView />
    </section>
  );
}

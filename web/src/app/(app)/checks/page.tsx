import ChecksView from "@/features/checks/ChecksView";
import PageHeader from "@/ui/PageHeader";

// Checks (M10-S3b-3): org-wide on-demand check ledger + bounded recent poll
// failures. Reads only (`device.read`); scope is enforced server-side, so the
// page needs no role resolution.
export default function ChecksPage() {
  return (
    <section>
      <PageHeader
        title="Checks"
        description="On-demand checks and the bounded recent poll-failure feed from across the organization."
      />
      <ChecksView />
    </section>
  );
}

import ComingSoon from "@/ui/ComingSoon";
import { ButtonLink } from "@/ui/Button";

export default function InterfacesPage() {
  return (
    <ComingSoon
      title="Interfaces"
      milestone="Phase 3+ (Step 10 surfaces)"
      description="There is no org-wide interface inventory yet. Per-device interface registers and counter charts are real today: open a device and follow its Interfaces table."
      horizonsRef="§2 (item 4), §4 (item 10)"
      planned={[
        "Org-wide interface search and utilization overview",
        "Optics/PoE and baseline comparison (V2 depth)",
        "Topology-linked neighbor context",
      ]}
      actions={
        <ButtonLink href="/devices" size="sm" variant="primary">
          Find interfaces on a device
        </ButtonLink>
      }
    />
  );
}

import ComingSoon from "@/ui/ComingSoon";

export default function TopologyPage() {
  return (
    <ComingSoon
      title="Topology"
      milestone="Phase 3 · MVP Step 10"
      description="Automatic topology is not built yet. Until it lands, neighbor and path knowledge comes from the device inventory, interface registers and on-demand checks."
      horizonsRef="§4 (items 10, 11)"
      planned={[
        "LLDP/CDP/ARP/MAC-derived edges with confidence and evidence",
        "Interactive site map",
        "Dependency suppression and root-cause grouping (MVP Step 11)",
      ]}
    />
  );
}

import ComingSoon from "@/ui/ComingSoon";

export default function WanPage() {
  return (
    <ComingSoon
      title="WAN"
      milestone="Phase 3 · MVP Step 13 (v1)"
      description="Multi-WAN intelligence, per-circuit health and ISP reporting arrive with Step 13. ICMP reachability today is the poll-health rollup on devices and checks."
      horizonsRef="§3 (items 8, 9, 27)"
      planned={[
        "Circuits and probe suites",
        "Explainable per-circuit health score (V2 depth)",
        "ISP availability reports and SLA math (v1 in Phase 3)",
      ]}
    />
  );
}

import ComingSoon from "@/ui/ComingSoon";
import { ButtonLink } from "@/ui/Button";

export default function MetricsPage() {
  return (
    <ComingSoon
      title="Metrics"
      milestone="Time-series engine live (M8); workspace later"
      description="The M8 time-series engine and the collector metric chart are real today — the chart lives on each collector's detail page. An org-wide metric explorer/dashboard surface is not built yet."
      horizonsRef="§2 (items 4, 49)"
      planned={[
        "Metric explorer with cardinality/retention awareness",
        "Interface utilization heat strips and baseline comparison (V2)",
        "Role dashboards and exports (V2)",
      ]}
      actions={
        <ButtonLink href="/collectors" size="sm" variant="primary">
          Open collector metrics
        </ButtonLink>
      }
    />
  );
}

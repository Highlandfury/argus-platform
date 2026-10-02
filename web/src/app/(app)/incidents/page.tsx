import ComingSoon from "@/ui/ComingSoon";

export default function IncidentsPage() {
  return (
    <ComingSoon
      title="Incidents"
      milestone="V2 · canonical item 14"
      description="Incident management (timeline, impact, MTTx) is V2. The M11 alert engine is the upstream signal; incidents will group and explain alerts rather than duplicate them."
      horizonsRef="§5 (items 12, 14)"
      planned={[
        "Incident timeline with evidence links",
        "Impact and MTTx rollups",
        "RCA v1 with observed/calculated/inferred/unknown discipline",
      ]}
    />
  );
}

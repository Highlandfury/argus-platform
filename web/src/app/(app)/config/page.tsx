import ComingSoon from "@/ui/ComingSoon";

export default function ConfigPage() {
  return (
    <ComingSoon
      title="Config"
      milestone="V2 · canonical items 16, 17"
      description="Configuration backup/version/diff is V2 (read-only, 4-6 vendors). No configuration is read or stored today."
      horizonsRef="§6 (items 16, 17)"
      planned={[
        "Read-only config backup and version history",
        "Diff and drift detection",
        "Change correlation with degradation (needs 16/17)",
      ]}
    />
  );
}

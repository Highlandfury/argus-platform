import ComingSoon from "@/ui/ComingSoon";

export default function LogsPage() {
  return (
    <ComingSoon
      title="Logs"
      milestone="V2 (audit viewer); event bus deferred (G2)"
      description="Structured audit rows are recorded today, but there is no log viewer yet. The internal event bus (NATS) was deliberately deferred until a second async consumer exists."
      horizonsRef="§7 (item 42), §2 (item 50)"
      planned={[
        "Database-backed audit table and viewer",
        "Event/log search with retention awareness",
        "Change correlation once config backup/diff lands (V2)",
      ]}
    />
  );
}

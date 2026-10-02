import ComingSoon from "@/ui/ComingSoon";

export default function AlertsPage() {
  return (
    <ComingSoon
      title="Alerts"
      milestone="Backend M11-S1 landed; UI is M11-S3 (Phase 8 owns the full experience)"
      description="The alert engine core is live: versioned rules, the in-process evaluator and the alerts lifecycle API (GET /v1/alerts with filter[state]/filter[severity]). The topbar badge already shows the live active count. The queue/acknowledge/snooze/silence experience is not built yet."
      horizonsRef="§5 (items 12, 13)"
      planned={[
        "Active alert queue with severity and dedup context",
        "Acknowledge / snooze / resolve / comment actions",
        "Maintenance windows and silences (M11-S3)",
      ]}
    />
  );
}

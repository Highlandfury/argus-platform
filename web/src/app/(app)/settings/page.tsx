import ComingSoon from "@/ui/ComingSoon";

export default function SettingsPage() {
  return (
    <ComingSoon
      title="Settings"
      milestone="Later phases (org/site settings, notification channels)"
      description="Organization and per-site settings, retention configuration and notification channels do not have a management surface yet. Retention windows are enforced by the platform today and documented in the runbook."
      horizonsRef="§7 (items 37, 48), §8"
      planned={[
        "Organization/site profile settings",
        "Notification channels (M11-S2 lands the engine)",
        "Retention and quota visibility",
      ]}
    />
  );
}

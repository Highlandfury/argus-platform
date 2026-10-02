import ComingSoon from "@/ui/ComingSoon";

export default function ServicesPage() {
  return (
    <ComingSoon
      title="Services"
      milestone="V2 (item 21); HTTP/TLS checks v1 in Phase 3 Step 12"
      description="Website/application synthetic monitoring is a V2 surface. Phase 3 Step 12 adds HTTP(S)/TLS/DNS diagnostics with structured evidence; transaction scripts come later."
      horizonsRef="§3 (items 20, 21)"
      planned={[
        "Synthetic transaction scripts (login/search/pay)",
        "DNS resolver health, NXDOMAIN/SERVFAIL and record drift",
        "Service availability views over grouped checks",
      ]}
    />
  );
}

import ComingSoon from "@/ui/ComingSoon";

export default function IpamPage() {
  return (
    <ComingSoon
      title="IPAM"
      milestone="V2 · canonical item 24"
      description="IP address management (“IPAM full-lite”) is V2. Management addresses are inventory attributes today, not a managed allocation plan."
      horizonsRef="§1 (item 24)"
      planned={[
        "Subnets, ranges and utilization",
        "Address assignment history and conflicts",
        "Discovery-driven reconciliation",
      ]}
    />
  );
}

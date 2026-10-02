import ComingSoon from "@/ui/ComingSoon";

export default function FlowsPage() {
  return (
    <ComingSoon
      title="Flows"
      milestone="V3 · canonical item 5"
      description="Flow ingestion (NetFlow/sFlow/IPFIX) and top-talker analysis are V3. Nothing here is mocked or approximated from existing counters."
      horizonsRef="§2 (item 5)"
      planned={[
        "Flow ingestion with explicit caps/truncation",
        "Top talkers and application breakdowns",
        "Forensic packet capture (opt-in, V3)",
      ]}
    />
  );
}

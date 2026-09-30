import DevicesList from "@/features/inventory/DevicesList";

// Devices list (M7-S4 skeleton; the full device detail page is M10). The list
// itself is a client feature so loading/empty/error states stay observable.
export default function DevicesPage() {
  return (
    <section>
      <h1>Devices</h1>
      <div className="panel">
        <DevicesList />
      </div>
    </section>
  );
}

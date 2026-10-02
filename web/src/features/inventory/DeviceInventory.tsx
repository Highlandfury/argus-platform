"use client";

import { useState } from "react";

import AddDeviceForm from "@/components/AddDeviceForm";

import DevicesList from "./DevicesList";

interface Site {
  id: string;
  name: string;
}

// DeviceInventory is the client half of /devices: the list stays an
// independent fetch (loading/empty/error states), and a successful manual add
// bumps refreshKey so the new device appears without a full page reload.
export default function DeviceInventory({
  sites,
  canWrite,
}: {
  sites: Site[];
  canWrite: boolean;
}) {
  const [refreshKey, setRefreshKey] = useState(0);
  return (
    <>
      <div className="panel">
        <DevicesList refreshKey={refreshKey} canWrite={canWrite} />
      </div>
      {canWrite && (
        <div style={{ marginTop: 16 }}>
          <AddDeviceForm
            sites={sites}
            onCreated={() => setRefreshKey((k) => k + 1)}
          />
        </div>
      )}
    </>
  );
}

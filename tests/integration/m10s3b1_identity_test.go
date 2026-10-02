package integration

// M10-S3b-1: identity-window mutations on an existing device — POST
// /v1/devices/{id}/identities (open) and POST
// /v1/devices/{id}/identities/{historyId}/close (close). Covers the canonical
// window lifecycle, idempotent repeats, deterministic 409 conflicts, format
// validation, historical reuse, cross-tenant 404 uniformity, and audit
// evidence (device.identity_add / device.identity_close).

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/argus-platform/argus/internal/modules/inventory"
)

func TestInventoryIdentityAddAndClose(t *testing.T) {
	env := newInventoryEnv(t, "inv-idadd-"+newUUID()[:8])
	deviceID := env.createDevice(t, "idadd-1", nil)

	// Create-time identity values are validated per type: the field error is
	// indexed (identities[i].value), matching the create request shape.
	badCreate, err := json.Marshal(map[string]any{
		"site_id": env.siteID, "name": "idadd-bad", "kind": "switch",
		"identities": []map[string]string{{"type": "mac", "value": "not-a-mac"}},
	})
	must(t, err)
	res := env.do(t, http.MethodPost, "/v1/devices", string(badCreate))
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	createErrs, _ := res.Body["errors"].([]any)
	if len(createErrs) != 1 {
		t.Fatalf("create identity format errors = %v", res.Body["errors"])
	}
	if first, _ := createErrs[0].(map[string]any); first["field"] != "identities[0].value" || first["code"] != "invalid" {
		t.Fatalf("create identity field error = %v", createErrs[0])
	}

	// Add validation: unknown type, blank value and per-type formats.
	for _, tc := range []struct {
		name, body, field string
	}{
		{"unknown_type", `{"type":"bogus","value":"x"}`, "type"},
		{"blank_value", `{"type":"mac","value":"  "}`, "value"},
		{"bad_mac", `{"type":"mac","value":"not-a-mac"}`, "value"},
		{"bad_mgmt_ip", `{"type":"mgmt_ip","value":"not-an-ip"}`, "value"},
	} {
		t.Run("validation_"+tc.name, func(t *testing.T) {
			res := env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/identities", tc.body)
			requireProblem(t, res, http.StatusBadRequest, "validation.failed")
			errs, _ := res.Body["errors"].([]any)
			if len(errs) != 1 {
				t.Fatalf("errors = %v", res.Body["errors"])
			}
			if first, _ := errs[0].(map[string]any); first["field"] != tc.field {
				t.Fatalf("field = %v, want %s (body %v)", first["field"], tc.field, res.Body)
			}
		})
	}

	// Add a MAC identity: canonicalized lowercase value, manual source, open
	// window (last_seen_at null), and the device_id is echoed.
	res = env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/identities", `{"type":"mac","value":"AA:BB:CC:DD:EE:71"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("add identity: status %d body %v", res.Status, res.Body)
	}
	rowID, _ := res.Body["id"].(string)
	if rowID == "" {
		t.Fatalf("add identity: missing id: %v", res.Body)
	}
	if res.Body["device_id"] != deviceID || res.Body["identifier_type"] != "mac" ||
		res.Body["identifier_value"] != "aa:bb:cc:dd:ee:71" || res.Body["source"] != "manual" ||
		res.Body["last_seen_at"] != nil {
		t.Fatalf("add identity payload = %v", res.Body)
	}

	// The open window is visible in the identity history.
	res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID+"/identity-history", "")
	if res.Status != http.StatusOK {
		t.Fatalf("identity history: status %d body %v", res.Status, res.Body)
	}
	found := false
	for _, row := range dataList(t, res.Body) {
		if row["id"] == rowID {
			found = true
			if row["identifier_value"] != "aa:bb:cc:dd:ee:71" || row["last_seen_at"] != nil {
				t.Fatalf("history row = %v", row)
			}
		}
	}
	if !found {
		t.Fatalf("added identity row %s not in history: %v", rowID, res.Body)
	}

	// Idempotent repeat on the same device: same open row, no duplicate.
	res = env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/identities", `{"type":"mac","value":"aa:bb:cc:dd:ee:71"}`)
	if res.Status != http.StatusCreated || res.Body["id"] != rowID {
		t.Fatalf("idempotent add: status %d body %v", res.Status, res.Body)
	}
	if opens := openRowsOf(identityRowsFor(t, env.orgID, deviceID), "mac"); len(opens) != 1 {
		t.Fatalf("idempotent add left %d open mac windows, want 1", len(opens))
	}

	// The same key on another live device is a deterministic conflict.
	device2 := env.createDevice(t, "idadd-2", nil)
	res = env.do(t, http.MethodPost, "/v1/devices/"+device2+"/identities", `{"type":"mac","value":"AA:BB:CC:DD:EE:71"}`)
	requireProblem(t, res, http.StatusConflict, "device.identity_conflict")

	// Close the window: stamped, no longer open.
	res = env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/identities/"+rowID+"/close", "")
	if res.Status != http.StatusOK || res.Body["id"] != rowID || res.Body["last_seen_at"] == nil {
		t.Fatalf("close identity: status %d body %v", res.Status, res.Body)
	}
	if opens := openRowsOf(identityRowsFor(t, env.orgID, deviceID), "mac"); len(opens) != 0 {
		t.Fatalf("closed window still open: %+v", opens)
	}

	// Repeat close is idempotent: the same (already closed) row is returned.
	res = env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/identities/"+rowID+"/close", "")
	if res.Status != http.StatusOK || res.Body["id"] != rowID || res.Body["last_seen_at"] == nil {
		t.Fatalf("idempotent close: status %d body %v", res.Status, res.Body)
	}

	// Unknown history rows are a 404 with the identity code.
	res = env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/identities/"+newUUID()+"/close", "")
	requireProblem(t, res, http.StatusNotFound, "device.identity_not_found")

	// Audit evidence: exactly one add (the idempotent repeat is not
	// re-audited) and one close, carrying actor/org/resource context.
	adds := env.audit.find(inventory.ActionDeviceIdentityAdd)
	if len(adds) != 1 {
		t.Fatalf("identity add audit events = %d, want 1: %+v", len(adds), adds)
	}
	if adds[0].ResourceType != "device" || adds[0].ResourceID.String() != deviceID ||
		adds[0].ActorID.String() == "" || adds[0].OrgID.String() != env.orgID ||
		adds[0].Data["identifier_type"] != "mac" || adds[0].Data["identifier_value"] != "aa:bb:cc:dd:ee:71" {
		t.Fatalf("identity add audit event = %+v", adds[0])
	}
	closes := env.audit.find(inventory.ActionDeviceIdentityClose)
	if len(closes) != 1 {
		t.Fatalf("identity close audit events = %d, want 1: %+v", len(closes), closes)
	}
	if closes[0].ResourceID.String() != deviceID || closes[0].Data["identity_history_id"] != rowID {
		t.Fatalf("identity close audit event = %+v", closes[0])
	}

	// A row of another device cannot be closed through this device.
	otherAdd := env.do(t, http.MethodPost, "/v1/devices/"+device2+"/identities", `{"type":"hostname","value":"idadd-2"}`)
	if otherAdd.Status != http.StatusCreated {
		t.Fatalf("device2 identity add: status %d body %v", otherAdd.Status, otherAdd.Body)
	}
	otherRowID, _ := otherAdd.Body["id"].(string)
	res = env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/identities/"+otherRowID+"/close", "")
	requireProblem(t, res, http.StatusNotFound, "device.identity_not_found")

	// Historical reuse: the closed value can be claimed by another device.
	res = env.do(t, http.MethodPost, "/v1/devices/"+device2+"/identities", `{"type":"mac","value":"aa:bb:cc:dd:ee:71"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("reclaim closed identity: status %d body %v", res.Status, res.Body)
	}

	// Cross-tenant calls are uniformly 404 (RLS hides the foreign device).
	envB := newInventoryEnv(t, "inv-idadd-b-"+newUUID()[:8])
	res = envB.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/identities", `{"type":"hostname","value":"foreign"}`)
	requireProblem(t, res, http.StatusNotFound, "device.not_found")
	res = envB.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/identities/"+rowID+"/close", "")
	requireProblem(t, res, http.StatusNotFound, "device.not_found")

	// The identity uniqueness invariant holds org-wide after the whole flow.
	if n := duplicateOpenWindows(t, env.orgID); n != 0 {
		t.Fatalf("org has %d duplicated open identity keys", n)
	}
}

package integration

// M7-S3 (Phase 2): inventory HTTP API acceptance — device/interface/group
// CRUD, cursor pagination, problem+json validation, soft delete, and manual
// merge/split with identity-history reparenting and audit evidence
// (P2-AC-01..03, P2-D7). The S-17 additions at the bottom back the security
// suite authz/tenant-isolation probes.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/inventory"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/security"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// recordingAudit captures inventory audit events in-process (the production
// sink is SlogAudit; the interface is the seam the canonical audit_logs table
// will plug into).
type recordingAudit struct {
	mu     sync.Mutex
	events []inventory.AuditEvent
}

func (r *recordingAudit) Record(ev inventory.AuditEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingAudit) find(action string) []inventory.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []inventory.AuditEvent
	for _, ev := range r.events {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

// inventoryEnv is one logged-in tenant with the inventory API wired and the
// audit sink observable.
type inventoryEnv struct {
	srv    *httptest.Server
	client *http.Client
	slug   string
	orgID  string
	siteID string
	csrf   string
	audit  *recordingAudit
}

func newInventoryEnv(t *testing.T, slug string) *inventoryEnv {
	t.Helper()
	seed := seedLoginUser(t, slug, "HQ-"+slug)

	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identity.New(appPool, authPool, tenancySvc)
	must(t, err)
	rec := &recordingAudit{}
	router := api.NewRouter(api.Options{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Telemetry: telemetry.New("it-inv", "0", "0"),
		Version:   "it",
		Commit:    "it",
		Identity:  identitySvc,
		Tenancy:   tenancySvc,
		Inventory: inventory.New(appPool, rec),
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	must(t, err)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", loginBody(slug, "it-password"), nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login: status %d body %v", res.Status, res.Body)
	}
	csrf := cookieByName(res, "argus_csrf")
	if csrf == nil {
		t.Fatal("login did not set argus_csrf")
	}
	return &inventoryEnv{
		srv:    srv,
		client: client,
		slug:   slug,
		orgID:  seed.OrgID,
		siteID: seed.SiteID,
		csrf:   csrf.Value,
		audit:  rec,
	}
}

// do performs an authenticated request carrying the session's CSRF token.
func (e *inventoryEnv) do(t *testing.T, method, path, body string) apiResponse {
	t.Helper()
	return doRequest(t, e.client, method, e.srv.URL+path, body, map[string]string{"X-CSRF-Token": e.csrf})
}

// dataList extracts body["data"] as a list of objects.
func dataList(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()
	raw, ok := body["data"].([]any)
	if !ok {
		t.Fatalf("body has no data array: %v", body)
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		obj, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("data item is not an object: %v", item)
		}
		out = append(out, obj)
	}
	return out
}

// createDevice posts a manual device and returns its id.
func (e *inventoryEnv) createDevice(t *testing.T, name string, extra map[string]any) string {
	t.Helper()
	body := map[string]any{"site_id": e.siteID, "name": name, "kind": "switch"}
	for k, v := range extra {
		body[k] = v
	}
	raw, err := json.Marshal(body)
	must(t, err)
	res := e.do(t, http.MethodPost, "/v1/devices", string(raw))
	if res.Status != http.StatusCreated {
		t.Fatalf("create device %s: status %d body %v", name, res.Status, res.Body)
	}
	id, _ := res.Body["id"].(string)
	if id == "" {
		t.Fatalf("create device %s: missing id: %v", name, res.Body)
	}
	return id
}

func requireProblem(t *testing.T, res apiResponse, status int, code string) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("status = %d, want %d (body %v)", res.Status, status, res.Body)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
		t.Fatalf("content type = %q, want application/problem+json", ct)
	}
	if res.Body["code"] != code {
		t.Fatalf("code = %v, want %s (body %v)", res.Body["code"], code, res.Body)
	}
	if res.Body["status"] != float64(status) {
		t.Fatalf("problem status = %v, want %d", res.Body["status"], status)
	}
	if res.Body["request_id"] == "" || res.Body["request_id"] == nil {
		t.Fatalf("problem missing request_id: %v", res.Body)
	}
}

// TestInventoryDeviceCRUD covers the /devices, /interfaces and /device-groups
// lifecycle: validation shape, pagination, filtering, soft delete, and audit
// events for every mutation.
func TestInventoryDeviceCRUD(t *testing.T) {
	env := newInventoryEnv(t, "inv-crud-"+newUUID()[:8])

	// Empty list.
	res := env.do(t, http.MethodGet, "/v1/devices", "")
	if res.Status != http.StatusOK {
		t.Fatalf("empty list: status %d", res.Status)
	}
	if got := dataList(t, res.Body); len(got) != 0 {
		t.Fatalf("empty list returned %d devices", len(got))
	}
	if res.Body["has_more"] != false {
		t.Fatalf("empty list has_more = %v", res.Body["has_more"])
	}

	// Validation failure: problem+json with field errors.
	res = env.do(t, http.MethodPost, "/v1/devices", `{}`)
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	if errs, ok := res.Body["errors"].([]any); !ok || len(errs) == 0 {
		t.Fatalf("validation problem lacks errors[]: %v", res.Body)
	}

	// Create with identity attributes.
	deviceID := env.createDevice(t, "core-sw-01", map[string]any{
		"serial":        "SN-CORE-01",
		"sys_object_id": "1.3.6.1.4.1.9.1.1",
		"mgmt_ip":       "10.20.0.1",
		"metadata":      map[string]any{"rack": "A1"},
		"identities": []map[string]string{
			{"type": "mac", "value": "aa:bb:cc:dd:ee:01"},
			{"type": "hostname", "value": "core-sw-01"},
		},
	})
	res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID, "")
	if res.Status != http.StatusOK || res.Body["name"] != "core-sw-01" || res.Body["status"] != "new" {
		t.Fatalf("device detail: status %d body %v", res.Status, res.Body)
	}
	if res.Body["serial"] != "SN-CORE-01" || res.Body["mgmt_ip"] != "10.20.0.1" {
		t.Fatalf("device identity columns missing: %v", res.Body)
	}

	// Duplicate live name within the site is a named conflict.
	dup, err := json.Marshal(map[string]any{"site_id": env.siteID, "name": "core-sw-01", "kind": "switch"})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices", string(dup))
	requireProblem(t, res, http.StatusConflict, "device.name_conflict")

	// Identity history: serial/sysObjectID/mgmt_ip recorded automatically plus
	// the explicit mac/hostname entries.
	res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID+"/identity-history", "")
	if res.Status != http.StatusOK {
		t.Fatalf("identity history: status %d body %v", res.Status, res.Body)
	}
	identities := map[string]string{}
	for _, row := range dataList(t, res.Body) {
		identities[row["identifier_type"].(string)] = row["identifier_value"].(string)
	}
	for typ, want := range map[string]string{
		"serial": "SN-CORE-01", "sys_object_id": "1.3.6.1.4.1.9.1.1", "mgmt_ip": "10.20.0.1",
		"mac": "aa:bb:cc:dd:ee:01", "hostname": "core-sw-01",
	} {
		if identities[typ] != want {
			t.Fatalf("identity %s = %q, want %q (all: %v)", typ, identities[typ], want, identities)
		}
	}

	// PATCH: omitted fields are unchanged.
	res = env.do(t, http.MethodPatch, "/v1/devices/"+deviceID, `{"name":"core-sw-01a"}`)
	if res.Status != http.StatusOK || res.Body["name"] != "core-sw-01a" || res.Body["kind"] != "switch" || res.Body["serial"] != "SN-CORE-01" {
		t.Fatalf("patch name: status %d body %v", res.Status, res.Body)
	}
	// PATCH: explicit null clears a nullable column.
	res = env.do(t, http.MethodPatch, "/v1/devices/"+deviceID, `{"status":"down","serial":null,"metadata":{"rack":"A2"}}`)
	if res.Status != http.StatusOK || res.Body["status"] != "down" || res.Body["serial"] != nil {
		t.Fatalf("patch clear serial: status %d body %v", res.Status, res.Body)
	}
	if meta, ok := res.Body["metadata"].(map[string]any); !ok || meta["rack"] != "A2" {
		t.Fatalf("metadata not replaced: %v", res.Body["metadata"])
	}
	// PATCH: unknown fields are rejected.
	res = env.do(t, http.MethodPatch, "/v1/devices/"+deviceID, `{"identity":[]}`)
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")

	// Cursor pagination: walk with limit=1 until has_more is false.
	for _, name := range []string{"pager-1", "pager-2", "pager-3"} {
		env.createDevice(t, name, nil)
	}
	seen := map[string]bool{}
	cursor := ""
	for page := 0; ; page++ {
		if page > 10 {
			t.Fatal("pagination did not terminate")
		}
		path := "/v1/devices?limit=1"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		res = env.do(t, http.MethodGet, path, "")
		if res.Status != http.StatusOK {
			t.Fatalf("page %d: status %d body %v", page, res.Status, res.Body)
		}
		rows := dataList(t, res.Body)
		if len(rows) != 1 {
			t.Fatalf("page %d: %d rows, want 1", page, len(rows))
		}
		seen[rows[0]["name"].(string)] = true
		if res.Body["has_more"] != true {
			break
		}
		next, _ := res.Body["next_cursor"].(string)
		if next == "" {
			t.Fatal("has_more=true without next_cursor")
		}
		cursor = next
	}
	if len(seen) != 4 {
		t.Fatalf("pagination saw %d devices, want 4 (%v)", len(seen), seen)
	}
	// Filters.
	res = env.do(t, http.MethodGet, "/v1/devices?filter[site_id]="+env.siteID, "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 4 {
		t.Fatalf("site filter: status %d body %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/devices?filter[status]=down", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("status filter: status %d body %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/devices?filter[status]=bogus", "")
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")

	// Interfaces: create, duplicate if_index conflict, update, list, delete.
	res = env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/interfaces",
		`{"if_index":1,"if_name":"Gi1/0/1","mac":"AA:BB:CC:00:00:01","speed_bps":1000000000}`)
	if res.Status != http.StatusCreated || res.Body["role"] != "unknown" || res.Body["monitored"] != true {
		t.Fatalf("create interface: status %d body %v", res.Status, res.Body)
	}
	interfaceID, _ := res.Body["id"].(string)
	res = env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/interfaces", `{"if_index":1,"if_name":"Gi1/0/2"}`)
	requireProblem(t, res, http.StatusConflict, "interface.if_index_conflict")
	res = env.do(t, http.MethodPatch, "/v1/interfaces/"+interfaceID,
		`{"description":"uplink to core","role":"uplink","monitored":false}`)
	if res.Status != http.StatusOK || res.Body["description"] != "uplink to core" || res.Body["monitored"] != false {
		t.Fatalf("patch interface: status %d body %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID+"/interfaces", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("list interfaces: status %d body %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/interfaces/"+interfaceID, "")
	if res.Status != http.StatusOK || res.Body["role"] != "uplink" {
		t.Fatalf("interface detail: status %d body %v", res.Status, res.Body)
	}
	if res = env.do(t, http.MethodDelete, "/v1/interfaces/"+interfaceID, ""); res.Status != http.StatusNoContent {
		t.Fatalf("delete interface: status %d body %v", res.Status, res.Body)
	}
	if res = env.do(t, http.MethodGet, "/v1/interfaces/"+interfaceID, ""); res.Status != http.StatusNotFound {
		t.Fatalf("deleted interface still visible: %d", res.Status)
	}

	// Device groups CRUD.
	res = env.do(t, http.MethodPost, "/v1/device-groups", `{"name":"core","selector":{"kinds":["switch"]}}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("create group: status %d body %v", res.Status, res.Body)
	}
	groupID, _ := res.Body["id"].(string)
	res = env.do(t, http.MethodPost, "/v1/device-groups", `{"name":"core"}`)
	requireProblem(t, res, http.StatusConflict, "device_group.name_conflict")
	res = env.do(t, http.MethodPatch, "/v1/device-groups/"+groupID, `{"selector":{"kinds":["router"]}}`)
	if res.Status != http.StatusOK {
		t.Fatalf("patch group: status %d body %v", res.Status, res.Body)
	}
	if sel, ok := res.Body["selector"].(map[string]any); !ok || len(sel["kinds"].([]any)) != 1 || sel["kinds"].([]any)[0] != "router" {
		t.Fatalf("group selector = %v", res.Body["selector"])
	}
	res = env.do(t, http.MethodGet, "/v1/device-groups/"+groupID, "")
	if res.Status != http.StatusOK {
		t.Fatalf("get group: status %d", res.Status)
	}
	if res = env.do(t, http.MethodDelete, "/v1/device-groups/"+groupID, ""); res.Status != http.StatusNoContent {
		t.Fatalf("delete group: status %d", res.Status)
	}
	if res = env.do(t, http.MethodGet, "/v1/device-groups/"+groupID, ""); res.Status != http.StatusNotFound {
		t.Fatalf("deleted group still visible: %d", res.Status)
	}

	// Soft delete: hidden by default, visible to auditors, name freed.
	res = env.do(t, http.MethodDelete, "/v1/devices/"+deviceID, "")
	if res.Status != http.StatusNoContent {
		t.Fatalf("delete device: status %d body %v", res.Status, res.Body)
	}
	if res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID, ""); res.Status != http.StatusNotFound {
		t.Fatalf("deleted device still visible: %d", res.Status)
	}
	res = env.do(t, http.MethodGet, "/v1/devices?include_deleted=true", "")
	foundDeleted := false
	for _, d := range dataList(t, res.Body) {
		if d["id"] == deviceID {
			foundDeleted = true
			if d["deleted_at"] == nil {
				t.Fatal("include_deleted row has null deleted_at")
			}
		}
	}
	if !foundDeleted {
		t.Fatal("include_deleted=true did not return the soft-deleted device")
	}
	if res = env.do(t, http.MethodDelete, "/v1/devices/"+deviceID, ""); res.Status != http.StatusNotFound {
		t.Fatalf("second delete: status %d, want 404", res.Status)
	}

	// Audit evidence for every mutation family.
	for _, action := range []string{
		inventory.ActionDeviceCreate, inventory.ActionDeviceUpdate, inventory.ActionDeviceDelete,
		inventory.ActionInterfaceCreate, inventory.ActionInterfaceUpdate, inventory.ActionInterfaceDelete,
		inventory.ActionGroupCreate, inventory.ActionGroupUpdate, inventory.ActionGroupDelete,
	} {
		if len(env.audit.find(action)) == 0 {
			t.Errorf("missing audit event %s", action)
		}
	}
	if evs := env.audit.find(inventory.ActionDeviceDelete); evs[0].ActorID.String() == "" || evs[0].OrgID.String() != env.orgID {
		t.Errorf("audit actor/org missing: %+v", evs[0])
	}
}

// TestInventoryMergeSplit covers P2-D7: merge re-points identity history and
// interfaces to the target, soft-deletes sources, and writes audit events;
// split detaches identity rows into a new device.
func TestInventoryMergeSplit(t *testing.T) {
	env := newInventoryEnv(t, "inv-merge-"+newUUID()[:8])

	targetID := env.createDevice(t, "merge-tgt", map[string]any{"serial": "SN-TGT"})
	src1ID := env.createDevice(t, "merge-src-1", map[string]any{
		"serial":     "SN-SRC-1",
		"identities": []map[string]string{{"type": "hostname", "value": "merge-src-1"}},
	})
	src2ID := env.createDevice(t, "merge-src-2", map[string]any{
		"identities": []map[string]string{{"type": "mac", "value": "aa:bb:cc:00:00:02"}},
	})
	res := env.do(t, http.MethodPost, "/v1/devices/"+src1ID+"/interfaces", `{"if_index":1,"if_name":"Gi1/0/1"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("source interface: status %d body %v", res.Status, res.Body)
	}

	mergeBody, err := json.Marshal(map[string]any{
		"source_device_ids": []string{src1ID, src2ID},
		"reason":            "duplicate discovery",
	})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+targetID+"/merge", string(mergeBody))
	if res.Status != http.StatusOK || res.Body["id"] != targetID {
		t.Fatalf("merge: status %d body %v", res.Status, res.Body)
	}

	// Sources are soft-deleted (404 on read, visible to auditors).
	for _, id := range []string{src1ID, src2ID} {
		if res = env.do(t, http.MethodGet, "/v1/devices/"+id, ""); res.Status != http.StatusNotFound {
			t.Fatalf("merged source %s still live: %d", id, res.Status)
		}
	}
	res = env.do(t, http.MethodGet, "/v1/devices?include_deleted=true", "")
	deletedSources := 0
	for _, d := range dataList(t, res.Body) {
		if d["id"] == src1ID || d["id"] == src2ID {
			if d["deleted_at"] == nil {
				t.Fatalf("merged source %v not marked deleted", d["id"])
			}
			deletedSources++
		}
	}
	if deletedSources != 2 {
		t.Fatalf("expected 2 merged sources in auditor view, got %d", deletedSources)
	}

	// Identity history was reparented to the target.
	res = env.do(t, http.MethodGet, "/v1/devices/"+targetID+"/identity-history", "")
	if res.Status != http.StatusOK {
		t.Fatalf("target identity history: status %d", res.Status)
	}
	targetIdentities := map[string]string{}
	rowByValue := map[string]string{}
	for _, row := range dataList(t, res.Body) {
		val := row["identifier_value"].(string)
		targetIdentities[val] = row["device_id"].(string)
		rowByValue[val], _ = row["id"].(string)
	}
	for _, want := range []string{"SN-TGT", "SN-SRC-1", "merge-src-1", "aa:bb:cc:00:00:02"} {
		if targetIdentities[want] != targetID {
			t.Fatalf("identity %q not reparented to target (all: %v)", want, targetIdentities)
		}
	}
	if res = env.do(t, http.MethodGet, "/v1/devices/"+src1ID+"/identity-history", ""); res.Status != http.StatusNotFound {
		t.Fatalf("identity history of merged source: status %d, want 404", res.Status)
	}

	// Interfaces moved to the target.
	res = env.do(t, http.MethodGet, "/v1/devices/"+targetID+"/interfaces", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("target interfaces: status %d body %v", res.Status, res.Body)
	}
	if dataList(t, res.Body)[0]["device_id"] != targetID {
		t.Fatalf("source interface not reparented: %v", dataList(t, res.Body)[0])
	}

	// Merge audit event.
	evs := env.audit.find(inventory.ActionDeviceMerge)
	if len(evs) != 1 {
		t.Fatalf("merge audit events = %d, want 1", len(evs))
	}
	if evs[0].ResourceID.String() != targetID || evs[0].Reason != "duplicate discovery" {
		t.Fatalf("merge audit event = %+v", evs[0])
	}
	gotSources, _ := evs[0].Data["source_device_ids"].([]string)
	if len(gotSources) != 2 || gotSources[0] != src1ID || gotSources[1] != src2ID {
		t.Fatalf("merge audit source ids = %v", evs[0].Data["source_device_ids"])
	}

	// Split: detach the serial identity row into a new device.
	serialRowID := rowByValue["SN-SRC-1"]
	if serialRowID == "" {
		t.Fatal("serial identity row not found on target")
	}
	splitBody, err := json.Marshal(map[string]any{
		"identity_history_ids": []string{serialRowID},
		"name":                 "merge-split-1",
		"kind":                 "router",
		"reason":               "asset swap-out",
	})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+targetID+"/split", string(splitBody))
	if res.Status != http.StatusCreated {
		t.Fatalf("split: status %d body %v", res.Status, res.Body)
	}
	newID, _ := res.Body["id"].(string)
	if newID == "" || newID == targetID {
		t.Fatalf("split returned bad device id: %v", res.Body)
	}
	if res.Body["serial"] != "SN-SRC-1" || res.Body["kind"] != "router" {
		t.Fatalf("split device columns not derived from detached keys: %v", res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/devices/"+newID+"/identity-history", "")
	newRows := dataList(t, res.Body)
	if len(newRows) != 1 || newRows[0]["id"] != serialRowID || newRows[0]["device_id"] != newID {
		t.Fatalf("split identity rows = %v", newRows)
	}
	res = env.do(t, http.MethodGet, "/v1/devices/"+targetID+"/identity-history", "")
	for _, row := range dataList(t, res.Body) {
		if row["id"] == serialRowID {
			t.Fatal("split row still attached to the source device")
		}
	}
	splitEvents := env.audit.find(inventory.ActionDeviceSplit)
	if len(splitEvents) != 1 || splitEvents[0].ResourceID.String() != newID {
		t.Fatalf("split audit events = %+v", splitEvents)
	}
	if splitEvents[0].Data["source_device_id"] != targetID {
		t.Fatalf("split audit source = %v", splitEvents[0].Data)
	}

	// Conflict: merging devices whose interfaces collide on if_index is 409
	// and leaves both devices untouched.
	c1 := env.createDevice(t, "conflict-1", nil)
	c2 := env.createDevice(t, "conflict-2", map[string]any{
		"identities": []map[string]string{{"type": "hostname", "value": "conflict-2"}},
	})
	for _, id := range []string{c1, c2} {
		res = env.do(t, http.MethodPost, "/v1/devices/"+id+"/interfaces", `{"if_index":7,"if_name":"Te1/1/1"}`)
		if res.Status != http.StatusCreated {
			t.Fatalf("conflict interface: status %d body %v", res.Status, res.Body)
		}
	}
	conflictBody, err := json.Marshal(map[string]any{"source_device_ids": []string{c2}})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+c1+"/merge", string(conflictBody))
	requireProblem(t, res, http.StatusConflict, "device.merge_conflict")
	for _, id := range []string{c1, c2} {
		if res = env.do(t, http.MethodGet, "/v1/devices/"+id, ""); res.Status != http.StatusOK {
			t.Fatalf("merge conflict mutated device %s: status %d", id, res.Status)
		}
	}

	// Validation: self-merge, unknown source, and detached rows of another
	// device are rejected.
	selfBody, err := json.Marshal(map[string]any{"source_device_ids": []string{c1}})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+c1+"/merge", string(selfBody))
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	unknownBody, err := json.Marshal(map[string]any{"source_device_ids": []string{newUUID()}})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+c1+"/merge", string(unknownBody))
	requireProblem(t, res, http.StatusNotFound, "device.not_found")
	res = env.do(t, http.MethodGet, "/v1/devices/"+c2+"/identity-history", "")
	c2Row := dataList(t, res.Body)[0]["id"].(string)
	foreignRows, err := json.Marshal(map[string]any{
		"identity_history_ids": []string{c2Row}, "name": "should-not-exist",
	})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+c1+"/split", string(foreignRows))
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
}

// seedViewerUser inserts a viewer-role login into an existing org.
func seedViewerUser(t *testing.T, env *inventoryEnv) string {
	t.Helper()
	email := env.slug + "-viewer@dev.local"
	hash, err := security.HashPassword("it-password")
	must(t, err)
	_, err = ownerPool.Exec(context.Background(),
		`INSERT INTO users (id, org_id, email, password_hash, role) VALUES ($1, $2, $3, $4, 'viewer')`,
		newUUID(), env.orgID, email, hash)
	must(t, err)
	return email
}

// TestInventoryAuthzS17: unauthenticated requests are 401; viewers can read
// but cannot mutate inventory.
func TestInventoryAuthzS17(t *testing.T) {
	env := newInventoryEnv(t, "inv-authz-"+newUUID()[:8])
	deviceID := env.createDevice(t, "authz-dev", nil)
	res := env.do(t, http.MethodPost, "/v1/device-groups", `{"name":"authz-group"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("group create: status %d body %v", res.Status, res.Body)
	}
	groupID, _ := res.Body["id"].(string)

	// Unauthenticated: 401 before CSRF (session middleware is outer).
	anon := &http.Client{Timeout: 10 * time.Second}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/devices"},
		{http.MethodPost, "/v1/devices"},
		{http.MethodDelete, "/v1/devices/" + deviceID},
		{http.MethodGet, "/v1/device-groups"},
	} {
		res = doRequest(t, anon, tc.method, env.srv.URL+tc.path, "", nil)
		requireProblem(t, res, http.StatusUnauthorized, "auth.unauthenticated")
	}

	// Viewer: reads allowed, writes forbidden.
	viewerEmail := seedViewerUser(t, env)
	jar, err := cookiejar.New(nil)
	must(t, err)
	viewer := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	login, err := json.Marshal(map[string]string{
		"org_slug": env.slug, "email": viewerEmail, "password": "it-password",
	})
	must(t, err)
	res = doRequest(t, viewer, http.MethodPost, env.srv.URL+"/v1/auth/login", string(login), nil)
	if res.Status != http.StatusOK {
		t.Fatalf("viewer login: status %d body %v", res.Status, res.Body)
	}
	viewerCSRF := cookieByName(res, "argus_csrf")
	if viewerCSRF == nil {
		t.Fatal("viewer login did not set argus_csrf")
	}
	viewerHeaders := map[string]string{"X-CSRF-Token": viewerCSRF.Value}
	if res = doRequest(t, viewer, http.MethodGet, env.srv.URL+"/v1/devices", "", nil); res.Status != http.StatusOK {
		t.Fatalf("viewer list: status %d", res.Status)
	}
	if res = doRequest(t, viewer, http.MethodGet, env.srv.URL+"/v1/devices/"+deviceID, "", nil); res.Status != http.StatusOK {
		t.Fatalf("viewer device detail: status %d", res.Status)
	}
	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"create_device", http.MethodPost, "/v1/devices", `{"site_id":"` + env.siteID + `","name":"viewer-dev","kind":"switch"}`},
		{"update_device", http.MethodPatch, "/v1/devices/" + deviceID, `{"name":"viewer-rename"}`},
		{"delete_device", http.MethodDelete, "/v1/devices/" + deviceID, ""},
		{"merge_device", http.MethodPost, "/v1/devices/" + deviceID + "/merge", `{"source_device_ids":["` + newUUID() + `"]}`},
		{"split_device", http.MethodPost, "/v1/devices/" + deviceID + "/split", `{"identity_history_ids":["` + newUUID() + `"],"name":"x"}`},
		{"create_interface", http.MethodPost, "/v1/devices/" + deviceID + "/interfaces", `{"if_index":9,"if_name":"Gi9"}`},
		{"create_group", http.MethodPost, "/v1/device-groups", `{"name":"viewer-group"}`},
		{"delete_group", http.MethodDelete, "/v1/device-groups/" + groupID, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res = doRequest(t, viewer, tc.method, env.srv.URL+tc.path, tc.body, viewerHeaders)
			requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
		})
	}

	// The device is unchanged after the denied attempts.
	res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID, "")
	if res.Status != http.StatusOK || res.Body["name"] != "authz-dev" {
		t.Fatalf("admin device changed by viewer attempts: %d %v", res.Status, res.Body)
	}
}

// TestInventoryTenantIsolationS17: org B cannot see or modify org A's devices,
// groups, or identity history; foreign sites are rejected on create.
func TestInventoryTenantIsolationS17(t *testing.T) {
	a := newInventoryEnv(t, "inv-iso-a-"+newUUID()[:8])
	b := newInventoryEnv(t, "inv-iso-b-"+newUUID()[:8])

	deviceID := a.createDevice(t, "tenant-a-dev", map[string]any{
		"serial":     "SN-TENANT-A",
		"identities": []map[string]string{{"type": "hostname", "value": "tenant-a-dev"}},
	})
	res := a.do(t, http.MethodPost, "/v1/device-groups", `{"name":"tenant-a-group"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("A group create: status %d body %v", res.Status, res.Body)
	}
	groupID, _ := res.Body["id"].(string)

	// B's list never contains A's rows.
	res = b.do(t, http.MethodGet, "/v1/devices", "")
	if res.Status != http.StatusOK {
		t.Fatalf("B list: status %d", res.Status)
	}
	payload := toJSON(t, res.Body)
	if strings.Contains(payload, deviceID) || strings.Contains(payload, "tenant-a-dev") {
		t.Fatalf("B sees A's device: %s", payload)
	}
	res = b.do(t, http.MethodGet, "/v1/device-groups", "")
	if res.Status != http.StatusOK || strings.Contains(toJSON(t, res.Body), groupID) {
		t.Fatalf("B sees A's group: %d %s", res.Status, toJSON(t, res.Body))
	}

	// Point reads/mutations on A's ids are 404 (no existence oracle).
	for _, tc := range []struct {
		name, method, path, body, code string
	}{
		{"read_device", http.MethodGet, "/v1/devices/" + deviceID, "", "device.not_found"},
		{"read_identity", http.MethodGet, "/v1/devices/" + deviceID + "/identity-history", "", "device.not_found"},
		{"update_device", http.MethodPatch, "/v1/devices/" + deviceID, `{"name":"hacked"}`, "device.not_found"},
		{"delete_device", http.MethodDelete, "/v1/devices/" + deviceID, "", "device.not_found"},
		{"read_group", http.MethodGet, "/v1/device-groups/" + groupID, "", "device_group.not_found"},
		{"update_group", http.MethodPatch, "/v1/device-groups/" + groupID, `{"name":"hacked"}`, "device_group.not_found"},
		{"delete_group", http.MethodDelete, "/v1/device-groups/" + groupID, "", "device_group.not_found"},
		{"list_interfaces", http.MethodGet, "/v1/devices/" + deviceID + "/interfaces", "", "device.not_found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res = b.do(t, tc.method, tc.path, tc.body)
			requireProblem(t, res, http.StatusNotFound, tc.code)
		})
	}

	// B cannot merge A's device into its own device or split with A's rows.
	bDevice := b.createDevice(t, "tenant-b-dev", nil)
	mergeBody, err := json.Marshal(map[string]any{"source_device_ids": []string{deviceID}})
	must(t, err)
	res = b.do(t, http.MethodPost, "/v1/devices/"+bDevice+"/merge", string(mergeBody))
	requireProblem(t, res, http.StatusNotFound, "device.not_found")

	res = a.do(t, http.MethodGet, "/v1/devices/"+deviceID+"/identity-history", "")
	aRowID := dataList(t, res.Body)[0]["id"].(string)
	splitBody, err := json.Marshal(map[string]any{"identity_history_ids": []string{aRowID}, "name": "stolen"})
	must(t, err)
	res = b.do(t, http.MethodPost, "/v1/devices/"+bDevice+"/split", string(splitBody))
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")

	// B cannot create a device in A's site.
	foreign, err := json.Marshal(map[string]any{"site_id": a.siteID, "name": "foreign-site-dev", "kind": "switch"})
	must(t, err)
	res = b.do(t, http.MethodPost, "/v1/devices", string(foreign))
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")

	// A's device is intact.
	res = a.do(t, http.MethodGet, "/v1/devices/"+deviceID, "")
	if res.Status != http.StatusOK || res.Body["name"] != "tenant-a-dev" || res.Body["serial"] != "SN-TENANT-A" {
		t.Fatalf("A's device mutated by B: %d %v", res.Status, res.Body)
	}
}

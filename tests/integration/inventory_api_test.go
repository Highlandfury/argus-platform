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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/inventory"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/database"
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

// ---------------------------------------------------------------------------
// M7-S3 remediation helpers: users with roles, server-side scope bindings,
// direct-DB identity inspection.
// ---------------------------------------------------------------------------

// seedUserWithRole inserts a login user with the given role and returns its id
// and email.
func seedUserWithRole(t *testing.T, env *inventoryEnv, role string) (string, string) {
	t.Helper()
	id := newUUID()
	email := env.slug + "-" + role + "-" + id[:8] + "@dev.local"
	hash, err := security.HashPassword("it-password")
	must(t, err)
	_, err = ownerPool.Exec(context.Background(),
		`INSERT INTO users (id, org_id, email, password_hash, role) VALUES ($1, $2, $3, $4, $5)`,
		id, env.orgID, email, hash, role)
	must(t, err)
	return id, email
}

// bindScope inserts one user_scope_bindings row through the app path (RLS).
func bindScope(t *testing.T, orgID, userID, scopeType, scopeID string) {
	t.Helper()
	err := database.WithTenant(context.Background(), appPool, mustUUID(t, orgID), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO user_scope_bindings (id, org_id, user_id, scope_type, scope_id) VALUES ($1, $2, $3, $4, $5)`,
			newUUID(), orgID, userID, scopeType, scopeID)
		return err
	})
	must(t, err)
}

// loginAs logs in an existing user on a fresh client and returns the client
// plus its CSRF token.
func loginAs(t *testing.T, env *inventoryEnv, email string) (*http.Client, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	must(t, err)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	body, err := json.Marshal(map[string]string{
		"org_slug": env.slug, "email": email, "password": "it-password",
	})
	must(t, err)
	res := doRequest(t, client, http.MethodPost, env.srv.URL+"/v1/auth/login", string(body), nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login %s: status %d body %v", email, res.Status, res.Body)
	}
	csrf := cookieByName(res, "argus_csrf")
	if csrf == nil {
		t.Fatalf("login %s did not set argus_csrf", email)
	}
	return client, csrf.Value
}

// createSite inserts an extra site into the env's org and returns its id.
func createSite(t *testing.T, orgID, name string) string {
	t.Helper()
	id := newUUID()
	err := database.WithTenant(context.Background(), appPool, mustUUID(t, orgID), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO sites (id, org_id, name) VALUES ($1, $2, $3)`, id, orgID, name)
		return err
	})
	must(t, err)
	return id
}

// identityRowDB is one device_identity_history row as stored in the database.
type identityRowDB struct {
	Type      string
	Value     string
	FirstSeen time.Time
	LastSeen  *time.Time
}

func (r identityRowDB) open() bool { return r.LastSeen == nil }

// identityRowsFor loads a device's identity history from the database.
func identityRowsFor(t *testing.T, orgID, deviceID string) []identityRowDB {
	t.Helper()
	var out []identityRowDB
	err := database.WithTenant(context.Background(), appPool, mustUUID(t, orgID), func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT identifier_type, identifier_value, first_seen_at, last_seen_at
			 FROM device_identity_history WHERE device_id = $1 ORDER BY first_seen_at, id`, deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r identityRowDB
			if err := rows.Scan(&r.Type, &r.Value, &r.FirstSeen, &r.LastSeen); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	must(t, err)
	return out
}

// identityRowID returns the id of the device's open identity row for a key.
func identityRowID(t *testing.T, orgID, deviceID, typ, value string) string {
	t.Helper()
	var id string
	err := database.WithTenant(context.Background(), appPool, mustUUID(t, orgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id::text FROM device_identity_history
			 WHERE device_id = $1 AND identifier_type = $2 AND identifier_value = $3 AND last_seen_at IS NULL
			 ORDER BY id LIMIT 1`, deviceID, typ, value).Scan(&id)
	})
	must(t, err)
	if id == "" {
		t.Fatalf("open identity %s=%s not found for device %s", typ, value, deviceID)
	}
	return id
}

// duplicateOpenWindows counts (org, type, value) keys with more than one open
// window in the org. The 000011 partial unique index keeps this at zero.
func duplicateOpenWindows(t *testing.T, orgID string) int {
	t.Helper()
	var n int
	err := database.WithTenant(context.Background(), appPool, mustUUID(t, orgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM (
				SELECT 1 FROM device_identity_history WHERE last_seen_at IS NULL
				GROUP BY org_id, identifier_type, identifier_value HAVING count(*) > 1
			) dup`).Scan(&n)
	})
	must(t, err)
	return n
}

func openRowsOf(rows []identityRowDB, typ string) []identityRowDB {
	var out []identityRowDB
	for _, r := range rows {
		if r.Type == typ && r.open() {
			out = append(out, r)
		}
	}
	return out
}

// TestInventoryCapabilityEnforcement (security suite S-18): unauthenticated
// inventory access is 401; a viewer session holds the read capabilities but
// every write-class capability is denied with deterministic 403 problem+json.
func TestInventoryCapabilityEnforcement(t *testing.T) {
	env := newInventoryEnv(t, "inv-cap-"+newUUID()[:8])
	deviceID := env.createDevice(t, "cap-dev", map[string]any{"serial": "SN-CAP-1"})
	res := env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/interfaces", `{"if_index":1,"if_name":"Gi1/0/1"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("interface create: status %d body %v", res.Status, res.Body)
	}
	interfaceID, _ := res.Body["id"].(string)
	res = env.do(t, http.MethodPost, "/v1/device-groups", `{"name":"cap-group"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("group create: status %d body %v", res.Status, res.Body)
	}
	groupID, _ := res.Body["id"].(string)

	// Unauthenticated: 401 for reads and writes.
	anon := &http.Client{Timeout: 10 * time.Second}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/v1/devices"},
		{http.MethodGet, "/v1/devices/" + deviceID},
		{http.MethodGet, "/v1/devices/" + deviceID + "/identity-history"},
		{http.MethodGet, "/v1/devices/" + deviceID + "/interfaces"},
		{http.MethodGet, "/v1/device-groups"},
		{http.MethodPost, "/v1/devices"},
	} {
		res = doRequest(t, anon, tc.method, env.srv.URL+tc.path, "", nil)
		requireProblem(t, res, http.StatusUnauthorized, "auth.unauthenticated")
	}

	// Viewer: read capabilities are granted.
	_, viewerEmail := seedUserWithRole(t, env, "viewer")
	viewer, viewerCSRF := loginAs(t, env, viewerEmail)
	viewerHeaders := map[string]string{"X-CSRF-Token": viewerCSRF}
	for _, tc := range []struct{ name, path string }{
		{"devices", "/v1/devices"},
		{"device", "/v1/devices/" + deviceID},
		{"identity_history", "/v1/devices/" + deviceID + "/identity-history"},
		{"device_interfaces", "/v1/devices/" + deviceID + "/interfaces"},
		{"interface", "/v1/interfaces/" + interfaceID},
		{"groups", "/v1/device-groups"},
		{"group", "/v1/device-groups/" + groupID},
	} {
		t.Run("viewer_read_"+tc.name, func(t *testing.T) {
			res := doRequest(t, viewer, http.MethodGet, env.srv.URL+tc.path, "", nil)
			if res.Status != http.StatusOK {
				t.Fatalf("status %d body %v", res.Status, res.Body)
			}
		})
	}

	// Viewer: every write-class capability is denied (403 auth.forbidden).
	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"create_device", http.MethodPost, "/v1/devices", `{"site_id":"` + env.siteID + `","name":"cap-viewer","kind":"switch"}`},
		{"update_device", http.MethodPatch, "/v1/devices/" + deviceID, `{"name":"cap-v2"}`},
		{"delete_device", http.MethodDelete, "/v1/devices/" + deviceID, ""},
		{"merge_device", http.MethodPost, "/v1/devices/" + deviceID + "/merge", `{"source_device_ids":["` + newUUID() + `"]}`},
		{"split_device", http.MethodPost, "/v1/devices/" + deviceID + "/split", `{"identity_history_ids":["` + newUUID() + `"],"name":"x"}`},
		{"create_interface", http.MethodPost, "/v1/devices/" + deviceID + "/interfaces", `{"if_index":2,"if_name":"Gi2"}`},
		{"update_interface", http.MethodPatch, "/v1/interfaces/" + interfaceID, `{"description":"x"}`},
		{"delete_interface", http.MethodDelete, "/v1/interfaces/" + interfaceID, ""},
		{"create_group", http.MethodPost, "/v1/device-groups", `{"name":"cap-group-2"}`},
		{"update_group", http.MethodPatch, "/v1/device-groups/" + groupID, `{"name":"cap-group-3"}`},
		{"delete_group", http.MethodDelete, "/v1/device-groups/" + groupID, ""},
	} {
		t.Run("viewer_write_"+tc.name, func(t *testing.T) {
			res := doRequest(t, viewer, tc.method, env.srv.URL+tc.path, tc.body, viewerHeaders)
			requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
		})
	}

	// Nothing changed under the denied attempts.
	res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID, "")
	if res.Status != http.StatusOK || res.Body["name"] != "cap-dev" {
		t.Fatalf("device mutated by denied viewer attempts: %d %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/interfaces/"+interfaceID, "")
	if res.Status != http.StatusOK {
		t.Fatal("interface deleted by denied viewer attempt")
	}
	res = env.do(t, http.MethodGet, "/v1/device-groups/"+groupID, "")
	if res.Status != http.StatusOK || res.Body["name"] != "cap-group" {
		t.Fatal("group mutated by denied viewer attempts")
	}
}

// TestInventoryScopeEnforcement (security suite S-19): a user WITH scope
// bindings is restricted to the bound subtrees — collection filters narrow,
// conflicting filters are 403, item access outside scope is 404, and creates
// require the parent in scope.
func TestInventoryScopeEnforcement(t *testing.T) {
	env := newInventoryEnv(t, "inv-scope-"+newUUID()[:8])
	site2 := createSite(t, env.orgID, "S2-"+env.slug)
	d1 := env.createDevice(t, "scope-d1", map[string]any{"serial": "SN-SCOPE-1"})
	body, err := json.Marshal(map[string]any{"site_id": site2, "name": "scope-d2", "kind": "switch"})
	must(t, err)
	res := env.do(t, http.MethodPost, "/v1/devices", string(body))
	if res.Status != http.StatusCreated {
		t.Fatalf("site2 device create: status %d body %v", res.Status, res.Body)
	}
	d2, _ := res.Body["id"].(string)
	res = env.do(t, http.MethodPost, "/v1/device-groups", `{"name":"scope-group-1"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("group create: status %d", res.Status)
	}
	group1, _ := res.Body["id"].(string)
	res = env.do(t, http.MethodPost, "/v1/device-groups", `{"name":"scope-group-2"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("group create: status %d", res.Status)
	}
	group2, _ := res.Body["id"].(string)

	// Site-bound admin: capabilities intact, scope restricted to site2.
	adminID, adminEmail := seedUserWithRole(t, env, "admin")
	bindScope(t, env.orgID, adminID, "site", site2)
	client, csrf := loginAs(t, env, adminEmail)
	headers := map[string]string{"X-CSRF-Token": csrf}
	do := func(method, path, body string) apiResponse {
		return doRequest(t, client, method, env.srv.URL+path, body, headers)
	}

	res = do(http.MethodGet, "/v1/devices", "")
	if res.Status != http.StatusOK {
		t.Fatalf("scoped list: status %d body %v", res.Status, res.Body)
	}
	rows := dataList(t, res.Body)
	if len(rows) != 1 || rows[0]["id"] != d2 {
		t.Fatalf("site-bound list = %v, want only device %s", rows, d2)
	}
	if res = do(http.MethodGet, "/v1/devices/"+d2, ""); res.Status != http.StatusOK {
		t.Fatalf("scoped in-scope device: status %d body %v", res.Status, res.Body)
	}
	if res = do(http.MethodGet, "/v1/devices/"+d1, ""); res.Status != http.StatusNotFound {
		t.Fatalf("scoped out-of-scope device read: status %d body %v", res.Status, res.Body)
	}
	if res = do(http.MethodPatch, "/v1/devices/"+d1, `{"name":"hacked"}`); res.Status != http.StatusNotFound {
		t.Fatalf("scoped out-of-scope patch: status %d body %v", res.Status, res.Body)
	}
	if res = do(http.MethodDelete, "/v1/devices/"+d1, ""); res.Status != http.StatusNotFound {
		t.Fatalf("scoped out-of-scope delete: status %d body %v", res.Status, res.Body)
	}
	if res = do(http.MethodGet, "/v1/devices/"+d1+"/identity-history", ""); res.Status != http.StatusNotFound {
		t.Fatalf("scoped out-of-scope identity history: status %d", res.Status)
	}
	if res = do(http.MethodGet, "/v1/devices/"+d1+"/interfaces", ""); res.Status != http.StatusNotFound {
		t.Fatalf("scoped out-of-scope interface list: status %d", res.Status)
	}
	if res = do(http.MethodPost, "/v1/devices/"+d1+"/interfaces", `{"if_index":5,"if_name":"Gi5"}`); res.Status != http.StatusNotFound {
		t.Fatalf("scoped out-of-scope interface create: status %d", res.Status)
	}

	// Conflicting collection filter is 403; matching filter narrows.
	if res = do(http.MethodGet, "/v1/devices?filter[site_id]="+env.siteID, ""); res.Status != http.StatusForbidden {
		t.Fatalf("conflicting site filter: status %d body %v", res.Status, res.Body)
	}
	if res = do(http.MethodGet, "/v1/devices?filter[site_id]="+site2, ""); res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("matching site filter: status %d body %v", res.Status, res.Body)
	}

	// Creates require the parent site in scope (403 scope denial).
	foreignCreate, err := json.Marshal(map[string]any{"site_id": env.siteID, "name": "scope-foreign", "kind": "switch"})
	must(t, err)
	if res = do(http.MethodPost, "/v1/devices", string(foreignCreate)); res.Status != http.StatusForbidden {
		t.Fatalf("out-of-scope create: status %d body %v", res.Status, res.Body)
	}
	inScopeCreate, err := json.Marshal(map[string]any{"site_id": site2, "name": "scope-in", "kind": "switch"})
	must(t, err)
	if res = do(http.MethodPost, "/v1/devices", string(inScopeCreate)); res.Status != http.StatusCreated {
		t.Fatalf("in-scope create: status %d body %v", res.Status, res.Body)
	}

	// Merge/split: out-of-scope target or source is 404.
	mergeBody, err := json.Marshal(map[string]any{"source_device_ids": []string{d1}})
	must(t, err)
	if res = do(http.MethodPost, "/v1/devices/"+d2+"/merge", string(mergeBody)); res.Status != http.StatusNotFound {
		t.Fatalf("merge out-of-scope source: status %d body %v", res.Status, res.Body)
	}
	swapBody, err := json.Marshal(map[string]any{"source_device_ids": []string{d2}})
	must(t, err)
	if res = do(http.MethodPost, "/v1/devices/"+d1+"/merge", string(swapBody)); res.Status != http.StatusNotFound {
		t.Fatalf("merge out-of-scope target: status %d body %v", res.Status, res.Body)
	}
	if res = do(http.MethodPost, "/v1/devices/"+d1+"/split", `{"identity_history_ids":["`+newUUID()+`"],"name":"x"}`); res.Status != http.StatusNotFound {
		t.Fatalf("split out-of-scope source: status %d body %v", res.Status, res.Body)
	}

	// Destination scope on PATCH (M7-S3 review finding): moving a device to
	// a site outside the caller's bindings is denied and mutates nothing.
	deniedMove, err := json.Marshal(map[string]any{"site_id": env.siteID, "serial": "SN-SCOPE-HACK"})
	must(t, err)
	if res = do(http.MethodPatch, "/v1/devices/"+d2, string(deniedMove)); res.Status != http.StatusForbidden {
		t.Fatalf("out-of-scope destination patch: status %d body %v", res.Status, res.Body)
	}
	res = do(http.MethodGet, "/v1/devices/"+d2, "")
	if res.Status != http.StatusOK || res.Body["site_id"] != site2 {
		t.Fatalf("denied destination patch changed site: %d %v", res.Status, res.Body)
	}
	if res.Body["serial"] == "SN-SCOPE-HACK" {
		t.Fatalf("denied destination patch changed identity: %v", res.Body)
	}
	var openHack int
	err = ownerPool.QueryRow(context.Background(),
		`SELECT count(*) FROM device_identity_history
		 WHERE device_id = $1::uuid AND identifier_type = 'serial'
		   AND identifier_value = 'SN-SCOPE-HACK' AND last_seen_at IS NULL`,
		mustUUID(t, d2)).Scan(&openHack)
	must(t, err)
	if openHack != 0 {
		t.Fatalf("denied destination patch left %d open identity window(s)", openHack)
	}

	// A destination site also within scope is allowed: bind a third site and
	// move the device there.
	site3 := createSite(t, env.orgID, "S3-"+env.slug)
	bindScope(t, env.orgID, adminID, "site", site3)
	moveOK, err := json.Marshal(map[string]any{"site_id": site3})
	must(t, err)
	if res = do(http.MethodPatch, "/v1/devices/"+d2, string(moveOK)); res.Status != http.StatusOK {
		t.Fatalf("in-scope destination patch: status %d body %v", res.Status, res.Body)
	}
	if res = do(http.MethodGet, "/v1/devices/"+d2, ""); res.Status != http.StatusOK || res.Body["site_id"] != site3 {
		t.Fatalf("in-scope move did not persist: %d %v", res.Status, res.Body)
	}

	// Device groups are governed by org/device_group bindings only.
	if res = do(http.MethodGet, "/v1/device-groups", ""); res.Status != http.StatusOK || len(dataList(t, res.Body)) != 0 {
		t.Fatalf("site-bound group list: status %d body %v", res.Status, res.Body)
	}
	if res = do(http.MethodGet, "/v1/device-groups/"+group1, ""); res.Status != http.StatusNotFound {
		t.Fatalf("site-bound group read: status %d", res.Status)
	}
	if res = do(http.MethodPost, "/v1/device-groups", `{"name":"scope-denied"}`); res.Status != http.StatusForbidden {
		t.Fatalf("site-bound group create: status %d body %v", res.Status, res.Body)
	}
	if res = do(http.MethodPatch, "/v1/device-groups/"+group1, `{"name":"nope"}`); res.Status != http.StatusNotFound {
		t.Fatalf("site-bound group update: status %d", res.Status)
	}
	if res = do(http.MethodDelete, "/v1/device-groups/"+group1, ""); res.Status != http.StatusNotFound {
		t.Fatalf("site-bound group delete: status %d", res.Status)
	}

	// Device-group-bound admin: only the bound group is visible; device
	// membership resolution is deferred (documented limitation).
	groupUserID, groupEmail := seedUserWithRole(t, env, "admin")
	bindScope(t, env.orgID, groupUserID, "device_group", group1)
	client2, csrf2 := loginAs(t, env, groupEmail)
	headers2 := map[string]string{"X-CSRF-Token": csrf2}
	do2 := func(method, path, body string) apiResponse {
		return doRequest(t, client2, method, env.srv.URL+path, body, headers2)
	}
	if res = do2(http.MethodGet, "/v1/device-groups/"+group1, ""); res.Status != http.StatusOK {
		t.Fatalf("group-bound in-scope group: status %d body %v", res.Status, res.Body)
	}
	if res = do2(http.MethodGet, "/v1/device-groups/"+group2, ""); res.Status != http.StatusNotFound {
		t.Fatalf("group-bound out-of-scope group: status %d", res.Status)
	}
	res = do2(http.MethodGet, "/v1/device-groups", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("group-bound list: status %d body %v", res.Status, res.Body)
	}
	if res = do2(http.MethodGet, "/v1/devices", ""); res.Status != http.StatusOK || len(dataList(t, res.Body)) != 0 {
		t.Fatalf("group-bound device list: status %d body %v", res.Status, res.Body)
	}
	if res = do2(http.MethodGet, "/v1/devices/"+d2, ""); res.Status != http.StatusNotFound {
		t.Fatalf("group-bound device read: status %d", res.Status)
	}
	if res = do2(http.MethodPost, "/v1/device-groups", `{"name":"group-bound-create"}`); res.Status != http.StatusForbidden {
		t.Fatalf("group-bound group create: status %d body %v", res.Status, res.Body)
	}
	if res = do2(http.MethodPatch, "/v1/device-groups/"+group1, `{"selector":{"kinds":["router"]}}`); res.Status != http.StatusOK {
		t.Fatalf("group-bound group update: status %d body %v", res.Status, res.Body)
	}

	// A caller with NO bindings keeps org-wide access (the original admin).
	res = env.do(t, http.MethodGet, "/v1/devices", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) < 2 {
		t.Fatalf("unrestricted admin list: status %d body %v", res.Status, res.Body)
	}
}

// TestInventoryIdentityUniqueness (P2-AC-01): duplicate open identity windows
// are rejected by the database with device.identity_conflict, closed history
// may repeat, soft delete closes windows for re-claiming, and cross-tenant
// duplicates are allowed (org-wide uniqueness scope).
func TestInventoryIdentityUniqueness(t *testing.T) {
	env := newInventoryEnv(t, "inv-uniq-"+newUUID()[:8])
	deviceID := env.createDevice(t, "uniq-1", map[string]any{
		"serial":        "SN-U1",
		"sys_object_id": "1.3.6.1.4.1.9.1.1",
		"mgmt_ip":       "10.9.0.1",
		"identities": []map[string]string{
			{"type": "mac", "value": "aa:bb:cc:00:00:01"},
			{"type": "hostname", "value": "uniq-1"},
		},
	})

	for _, tc := range []struct {
		name  string
		extra map[string]any
	}{
		{"serial", map[string]any{"serial": "SN-U1"}},
		{"sys_object_id", map[string]any{"sys_object_id": "1.3.6.1.4.1.9.1.1"}},
		{"mgmt_ip", map[string]any{"mgmt_ip": "10.9.0.1"}},
		{"mac", map[string]any{"identities": []map[string]string{{"type": "mac", "value": "AA:BB:CC:00:00:01"}}}},
		{"hostname", map[string]any{"identities": []map[string]string{{"type": "hostname", "value": "uniq-1"}}}},
	} {
		t.Run("duplicate_"+tc.name, func(t *testing.T) {
			body := map[string]any{"site_id": env.siteID, "name": "dup-" + tc.name, "kind": "switch"}
			for k, v := range tc.extra {
				body[k] = v
			}
			raw, err := json.Marshal(body)
			must(t, err)
			res := env.do(t, http.MethodPost, "/v1/devices", string(raw))
			requireProblem(t, res, http.StatusConflict, "device.identity_conflict")
		})
	}

	// PATCHing onto a foreign open identity is 409 and leaves the row intact.
	dev2 := env.createDevice(t, "uniq-2", map[string]any{"serial": "SN-U2"})
	res := env.do(t, http.MethodPatch, "/v1/devices/"+dev2, `{"serial":"SN-U1"}`)
	requireProblem(t, res, http.StatusConflict, "device.identity_conflict")
	res = env.do(t, http.MethodGet, "/v1/devices/"+dev2, "")
	if res.Status != http.StatusOK || res.Body["serial"] != "SN-U2" {
		t.Fatalf("conflicting patch mutated device: %d %v", res.Status, res.Body)
	}
	rowsDev2 := identityRowsFor(t, env.orgID, dev2)
	if opens := openRowsOf(rowsDev2, "serial"); len(opens) != 1 || opens[0].Value != "SN-U2" {
		t.Fatalf("conflicting patch left device2 history inconsistent: %+v", rowsDev2)
	}

	// Historical reuse: closing SN-U1 frees it.
	res = env.do(t, http.MethodPatch, "/v1/devices/"+deviceID, `{"serial":"SN-U1X"}`)
	if res.Status != http.StatusOK {
		t.Fatalf("identity patch: status %d body %v", res.Status, res.Body)
	}
	reused := env.createDevice(t, "uniq-reuse", map[string]any{"serial": "SN-U1"})
	_ = reused

	// Soft delete closes open windows so identities can be re-claimed.
	if res = env.do(t, http.MethodDelete, "/v1/devices/"+dev2, ""); res.Status != http.StatusNoContent {
		t.Fatalf("delete device2: status %d body %v", res.Status, res.Body)
	}
	for _, r := range identityRowsFor(t, env.orgID, dev2) {
		if r.open() {
			t.Fatalf("soft-deleted device still has an open identity window: %+v", r)
		}
	}
	env.createDevice(t, "uniq-reclaim", map[string]any{"serial": "SN-U2"})

	// Cross-tenant duplicates are allowed (uniqueness is org-wide).
	envB := newInventoryEnv(t, "inv-uniq-b-"+newUUID()[:8])
	envB.createDevice(t, "uniq-b", map[string]any{"serial": "SN-U1"})

	// Concurrent creation of the same serial: the DB unique index must reject
	// exactly one of the two requests.
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			raw, _ := json.Marshal(map[string]any{
				"site_id": env.siteID, "name": "conc-" + strconv.Itoa(i), "kind": "switch", "serial": "SN-CONC",
			})
			req, err := http.NewRequest(http.MethodPost, env.srv.URL+"/v1/devices", strings.NewReader(string(raw)))
			if err != nil {
				statuses <- -1
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", env.csrf)
			resp, err := env.client.Do(req)
			if err != nil {
				statuses <- -1
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			statuses <- resp.StatusCode
		}(i)
	}
	wg.Wait()
	close(statuses)
	created, conflicted := 0, 0
	for s := range statuses {
		switch s {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicted++
		default:
			t.Fatalf("concurrent duplicate create: unexpected status %d", s)
		}
	}
	if created != 1 || conflicted != 1 {
		t.Fatalf("concurrent duplicate create: created=%d conflict=%d, want 1/1", created, conflicted)
	}

	// No duplicate open windows anywhere in the org.
	if n := duplicateOpenWindows(t, env.orgID); n != 0 {
		t.Fatalf("org has %d duplicated open identity keys", n)
	}
}

// TestInventoryIdentityPatchLifecycle (P2-AC-02): a PATCH of a canonical
// identity column closes the old open window and opens the new one in one
// transaction with the same server timestamp; same-value PATCH is a no-op;
// explicit null closes without opening; omitted fields are untouched.
func TestInventoryIdentityPatchLifecycle(t *testing.T) {
	env := newInventoryEnv(t, "inv-life-"+newUUID()[:8])
	deviceID := env.createDevice(t, "life-dev", map[string]any{
		"serial":        "SN-L1",
		"sys_object_id": "1.3.6.1.4.1.9.1.2",
		"mgmt_ip":       "10.9.1.1",
	})

	rows := identityRowsFor(t, env.orgID, deviceID)
	if len(rows) != 3 {
		t.Fatalf("baseline identity rows = %d, want 3 (%+v)", len(rows), rows)
	}

	// Change serial: old closed, new open, same transaction timestamp.
	res := env.do(t, http.MethodPatch, "/v1/devices/"+deviceID, `{"serial":"SN-L2"}`)
	if res.Status != http.StatusOK || res.Body["serial"] != "SN-L2" {
		t.Fatalf("serial patch: status %d body %v", res.Status, res.Body)
	}
	rows = identityRowsFor(t, env.orgID, deviceID)
	var oldSerial, newSerial *identityRowDB
	for i := range rows {
		switch {
		case rows[i].Type == "serial" && rows[i].Value == "SN-L1":
			oldSerial = &rows[i]
		case rows[i].Type == "serial" && rows[i].Value == "SN-L2":
			newSerial = &rows[i]
		}
	}
	if oldSerial == nil || newSerial == nil {
		t.Fatalf("serial transition rows missing: %+v", rows)
	}
	if oldSerial.open() {
		t.Fatal("old serial window still open after PATCH")
	}
	if !newSerial.open() {
		t.Fatal("new serial window not open after PATCH")
	}
	if !oldSerial.LastSeen.Equal(newSerial.FirstSeen) {
		t.Fatalf("transition timestamps differ: old last_seen=%v new first_seen=%v (must be one tx now())",
			oldSerial.LastSeen, newSerial.FirstSeen)
	}

	// Same-value PATCH: no redundant row, history stable.
	res = env.do(t, http.MethodPatch, "/v1/devices/"+deviceID, `{"serial":"SN-L2"}`)
	if res.Status != http.StatusOK {
		t.Fatalf("same-value patch: status %d", res.Status)
	}
	rowsSame := identityRowsFor(t, env.orgID, deviceID)
	if len(rowsSame) != len(rows) {
		t.Fatalf("same-value PATCH added history rows: %d -> %d", len(rows), len(rowsSame))
	}
	if opens := openRowsOf(rowsSame, "serial"); len(opens) != 1 || !opens[0].open() {
		t.Fatalf("same-value PATCH disturbed the open window: %+v", opens)
	}

	// Omitted field: untouched.
	res = env.do(t, http.MethodPatch, "/v1/devices/"+deviceID, `{"name":"life-dev-2"}`)
	if res.Status != http.StatusOK || res.Body["serial"] != "SN-L2" {
		t.Fatalf("omitted-field patch: status %d body %v", res.Status, res.Body)
	}
	if got := identityRowsFor(t, env.orgID, deviceID); len(got) != len(rows) {
		t.Fatalf("omitted-field PATCH changed history: %d -> %d", len(rows), len(got))
	}

	// Explicit null: close without opening; column becomes NULL.
	res = env.do(t, http.MethodPatch, "/v1/devices/"+deviceID, `{"serial":null}`)
	if res.Status != http.StatusOK || res.Body["serial"] != nil {
		t.Fatalf("null serial patch: status %d body %v", res.Status, res.Body)
	}
	rowsNull := identityRowsFor(t, env.orgID, deviceID)
	if opens := openRowsOf(rowsNull, "serial"); len(opens) != 0 {
		t.Fatalf("null PATCH left an open serial window: %+v", opens)
	}
	if len(rowsNull) != len(rows) {
		t.Fatalf("null PATCH must close, not add, rows: %d -> %d", len(rows), len(rowsNull))
	}

	// mgmt_ip transition uses canonical (host) values.
	res = env.do(t, http.MethodPatch, "/v1/devices/"+deviceID, `{"mgmt_ip":"10.9.1.2"}`)
	if res.Status != http.StatusOK || res.Body["mgmt_ip"] != "10.9.1.2" {
		t.Fatalf("mgmt_ip patch: status %d body %v", res.Status, res.Body)
	}
	rowsIP := identityRowsFor(t, env.orgID, deviceID)
	if opens := openRowsOf(rowsIP, "mgmt_ip"); len(opens) != 1 || opens[0].Value != "10.9.1.2" {
		t.Fatalf("mgmt_ip open window = %+v", opens)
	}

	// Multi-field PATCH shares one transaction timestamp.
	res = env.do(t, http.MethodPatch, "/v1/devices/"+deviceID, `{"sys_object_id":"1.3.6.1.4.1.9.1.3","mgmt_ip":null}`)
	if res.Status != http.StatusOK {
		t.Fatalf("multi-field patch: status %d body %v", res.Status, res.Body)
	}
	rowsMulti := identityRowsFor(t, env.orgID, deviceID)
	var closedIP, openSys *identityRowDB
	for i := range rowsMulti {
		switch {
		case rowsMulti[i].Type == "mgmt_ip" && rowsMulti[i].Value == "10.9.1.2":
			closedIP = &rowsMulti[i]
		case rowsMulti[i].Type == "sys_object_id" && rowsMulti[i].Value == "1.3.6.1.4.1.9.1.3":
			openSys = &rowsMulti[i]
		}
	}
	if closedIP == nil || closedIP.open() || openSys == nil {
		t.Fatalf("multi-field transition rows missing: %+v", rowsMulti)
	}
	if !closedIP.LastSeen.Equal(openSys.FirstSeen) {
		t.Fatalf("multi-field transition timestamps differ: %v vs %v", closedIP.LastSeen, openSys.FirstSeen)
	}
}

// TestInventoryMergeSplitIdentityRegressions (P2-D7): identity-history lifecycle
// is preserved across manual merge/split — open windows move, exactly one open
// window per key remains, soft deletes and history stay correct.
func TestInventoryMergeSplitIdentityRegressions(t *testing.T) {
	env := newInventoryEnv(t, "inv-reg-"+newUUID()[:8])

	// create -> patch identity -> merge.
	a := env.createDevice(t, "reg-a", map[string]any{"serial": "SN-A1"})
	b := env.createDevice(t, "reg-b", map[string]any{"serial": "SN-B1"})
	res := env.do(t, http.MethodPatch, "/v1/devices/"+a, `{"serial":"SN-A2"}`)
	if res.Status != http.StatusOK {
		t.Fatalf("patch A: status %d body %v", res.Status, res.Body)
	}
	mergeBody, err := json.Marshal(map[string]any{"source_device_ids": []string{b}})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+a+"/merge", string(mergeBody))
	if res.Status != http.StatusOK {
		t.Fatalf("merge B into A: status %d body %v", res.Status, res.Body)
	}
	rowsA := identityRowsFor(t, env.orgID, a)
	if opens := openRowsOf(rowsA, "serial"); len(opens) != 2 {
		t.Fatalf("merged device serial windows = %+v, want SN-A2 + SN-B1 open", opens)
	}
	if n := duplicateOpenWindows(t, env.orgID); n != 0 {
		t.Fatalf("merge produced %d duplicate open keys", n)
	}
	if res = env.do(t, http.MethodGet, "/v1/devices/"+b, ""); res.Status != http.StatusNotFound {
		t.Fatalf("merged source still live: %d", res.Status)
	}

	// create -> merge -> split: split a reparented identity into a new device.
	c := env.createDevice(t, "reg-c", map[string]any{"serial": "SN-C1"})
	d := env.createDevice(t, "reg-d", map[string]any{"serial": "SN-D1", "identities": []map[string]string{{"type": "hostname", "value": "reg-d"}}})
	mergeB2, err := json.Marshal(map[string]any{"source_device_ids": []string{d}})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+c+"/merge", string(mergeB2))
	if res.Status != http.StatusOK {
		t.Fatalf("merge D into C: status %d body %v", res.Status, res.Body)
	}
	dRow := identityRowID(t, env.orgID, c, "serial", "SN-D1")
	splitB, err := json.Marshal(map[string]any{"identity_history_ids": []string{dRow}, "name": "reg-e", "reason": "split back"})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+c+"/split", string(splitB))
	if res.Status != http.StatusCreated {
		t.Fatalf("split D identity: status %d body %v", res.Status, res.Body)
	}
	if res.Body["serial"] != "SN-D1" {
		t.Fatalf("split device canonical serial = %v", res.Body["serial"])
	}
	// C keeps its own open serial and loses only the detached window.
	rowsC := identityRowsFor(t, env.orgID, c)
	if opens := openRowsOf(rowsC, "serial"); len(opens) != 1 || opens[0].Value != "SN-C1" {
		t.Fatalf("source serial windows after split = %+v", opens)
	}
	if n := duplicateOpenWindows(t, env.orgID); n != 0 {
		t.Fatalf("split produced %d duplicate open keys", n)
	}

	// patch identity -> split: the moved OPEN window becomes the new device's
	// canonical identity and the source column is cleared to stay consistent.
	f := env.createDevice(t, "reg-f", map[string]any{"serial": "SN-F1"})
	res = env.do(t, http.MethodPatch, "/v1/devices/"+f, `{"serial":"SN-F2"}`)
	if res.Status != http.StatusOK {
		t.Fatalf("patch F: status %d body %v", res.Status, res.Body)
	}
	fRow := identityRowID(t, env.orgID, f, "serial", "SN-F2")
	splitF, err := json.Marshal(map[string]any{"identity_history_ids": []string{fRow}, "name": "reg-g"})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+f+"/split", string(splitF))
	if res.Status != http.StatusCreated {
		t.Fatalf("patch->split: status %d body %v", res.Status, res.Body)
	}
	g, _ := res.Body["id"].(string)
	res = env.do(t, http.MethodGet, "/v1/devices/"+f, "")
	if res.Status != http.StatusOK || res.Body["serial"] != nil {
		t.Fatalf("source serial must be cleared after moving its open window: %d %v", res.Status, res.Body)
	}
	rowsF := identityRowsFor(t, env.orgID, f)
	if opens := openRowsOf(rowsF, "serial"); len(opens) != 0 {
		t.Fatalf("source still has open serial windows: %+v", opens)
	}
	// SN-F2 is now open on the new device; SN-F1 is closed history and reusable.
	res = env.do(t, http.MethodPost, "/v1/devices", `{"site_id":"`+env.siteID+`","name":"no-f2","kind":"switch","serial":"SN-F2"}`)
	requireProblem(t, res, http.StatusConflict, "device.identity_conflict")
	env.createDevice(t, "yes-f1", map[string]any{"serial": "SN-F1"})
	_ = g

	// duplicate identity -> merge: a rejected duplicate is repaired by merging.
	h := env.createDevice(t, "reg-h", map[string]any{"serial": "SN-H1"})
	i := env.createDevice(t, "reg-i", map[string]any{"serial": "SN-I1"})
	res = env.do(t, http.MethodPatch, "/v1/devices/"+i, `{"serial":"SN-H1"}`)
	requireProblem(t, res, http.StatusConflict, "device.identity_conflict")
	mergeH, err := json.Marshal(map[string]any{"source_device_ids": []string{i}})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+h+"/merge", string(mergeH))
	if res.Status != http.StatusOK {
		t.Fatalf("duplicate->merge: status %d body %v", res.Status, res.Body)
	}
	if opens := openRowsOf(identityRowsFor(t, env.orgID, h), "serial"); len(opens) != 2 {
		t.Fatalf("merged serial windows = %+v, want SN-H1 + SN-I1", opens)
	}

	// duplicate identity -> split: splitting keeps exactly one owner per key.
	j := env.createDevice(t, "reg-j", map[string]any{
		"serial":     "SN-J1",
		"identities": []map[string]string{{"type": "hostname", "value": "reg-j"}},
	})
	jRow := identityRowID(t, env.orgID, j, "hostname", "reg-j")
	splitJ, err := json.Marshal(map[string]any{"identity_history_ids": []string{jRow}, "name": "reg-k"})
	must(t, err)
	res = env.do(t, http.MethodPost, "/v1/devices/"+j+"/split", string(splitJ))
	if res.Status != http.StatusCreated {
		t.Fatalf("duplicate->split: status %d body %v", res.Status, res.Body)
	}
	k, _ := res.Body["id"].(string)
	res = env.do(t, http.MethodPost, "/v1/devices", `{"site_id":"`+env.siteID+`","name":"no-host","kind":"switch","identities":[{"type":"hostname","value":"reg-j"}]}`)
	requireProblem(t, res, http.StatusConflict, "device.identity_conflict")
	res = env.do(t, http.MethodPost, "/v1/devices", `{"site_id":"`+env.siteID+`","name":"no-j-serial","kind":"switch","serial":"SN-J1"}`)
	requireProblem(t, res, http.StatusConflict, "device.identity_conflict")
	_ = k

	if n := duplicateOpenWindows(t, env.orgID); n != 0 {
		t.Fatalf("regression flows produced %d duplicate open keys", n)
	}
}

// TestInventoryCSRFEnforcement (security suite S-20): capabilities are in
// ADDITION to CSRF — every inventory mutation still requires the double-submit
// header, and rejected requests leave no state behind.
func TestInventoryCSRFEnforcement(t *testing.T) {
	env := newInventoryEnv(t, "inv-csrf-"+newUUID()[:8])
	deviceID := env.createDevice(t, "csrf-dev", map[string]any{"serial": "SN-CSRF-1"})
	res := env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/interfaces", `{"if_index":1,"if_name":"Gi1"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("interface create: status %d", res.Status)
	}
	interfaceID, _ := res.Body["id"].(string)
	res = env.do(t, http.MethodPost, "/v1/device-groups", `{"name":"csrf-group"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("group create: status %d", res.Status)
	}
	groupID, _ := res.Body["id"].(string)

	for _, tc := range []struct {
		name, method, path, body string
	}{
		{"create_device", http.MethodPost, "/v1/devices", `{"site_id":"` + env.siteID + `","name":"csrf-x","kind":"switch"}`},
		{"update_device", http.MethodPatch, "/v1/devices/" + deviceID, `{"name":"csrf-hacked"}`},
		{"delete_device", http.MethodDelete, "/v1/devices/" + deviceID, ""},
		{"merge_device", http.MethodPost, "/v1/devices/" + deviceID + "/merge", `{"source_device_ids":["` + newUUID() + `"]}`},
		{"split_device", http.MethodPost, "/v1/devices/" + deviceID + "/split", `{"identity_history_ids":["` + newUUID() + `"],"name":"x"}`},
		{"create_interface", http.MethodPost, "/v1/devices/" + deviceID + "/interfaces", `{"if_index":2,"if_name":"Gi2"}`},
		{"update_interface", http.MethodPatch, "/v1/interfaces/" + interfaceID, `{"description":"x"}`},
		{"delete_interface", http.MethodDelete, "/v1/interfaces/" + interfaceID, ""},
		{"create_group", http.MethodPost, "/v1/device-groups", `{"name":"csrf-group-2"}`},
		{"update_group", http.MethodPatch, "/v1/device-groups/" + groupID, `{"name":"csrf-group-3"}`},
		{"delete_group", http.MethodDelete, "/v1/device-groups/" + groupID, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No X-CSRF-Token header at all: session is valid, so CSRF is the
			// rejecting layer (403 auth.csrf) before capability/handler.
			res := doRequest(t, env.client, tc.method, env.srv.URL+tc.path, tc.body, nil)
			requireProblem(t, res, http.StatusForbidden, "auth.csrf")
		})
	}
	// State untouched.
	res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID, "")
	if res.Status != http.StatusOK || res.Body["name"] != "csrf-dev" {
		t.Fatalf("CSRF-less attempt mutated the device: %d %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/interfaces/"+interfaceID, "")
	if res.Status != http.StatusOK {
		t.Fatal("CSRF-less attempt deleted the interface")
	}
	// With CSRF the same mutation succeeds.
	res = env.do(t, http.MethodPatch, "/v1/devices/"+deviceID, `{"name":"csrf-ok"}`)
	if res.Status != http.StatusOK || res.Body["name"] != "csrf-ok" {
		t.Fatalf("CSRF-protected patch: status %d body %v", res.Status, res.Body)
	}
}

// TestInventoryCrossTenantS21 (security suite S-21): cross-tenant reads and
// mutations on devices, interfaces, and groups are 404 with the same response
// shape as genuinely missing rows (enumeration resistance).
func TestInventoryCrossTenantS21(t *testing.T) {
	a := newInventoryEnv(t, "inv-xt-a-"+newUUID()[:8])
	b := newInventoryEnv(t, "inv-xt-b-"+newUUID()[:8])

	aDevice := a.createDevice(t, "xt-a-dev", map[string]any{"serial": "SN-XT-A"})
	res := a.do(t, http.MethodPost, "/v1/devices/"+aDevice+"/interfaces", `{"if_index":1,"if_name":"Gi1"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("A interface create: status %d body %v", res.Status, res.Body)
	}
	aInterface, _ := res.Body["id"].(string)
	res = a.do(t, http.MethodPost, "/v1/device-groups", `{"name":"xt-a-group"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("A group create: status %d", res.Status)
	}
	aGroup, _ := res.Body["id"].(string)

	bDevice := b.createDevice(t, "xt-b-dev", nil)

	// Cross-tenant interface mutations are 404 (A's interface is invisible).
	for _, tc := range []struct {
		name, method, path, body, code string
	}{
		{"read_interface", http.MethodGet, "/v1/interfaces/" + aInterface, "", "interface.not_found"},
		{"update_interface", http.MethodPatch, "/v1/interfaces/" + aInterface, `{"description":"hacked"}`, "interface.not_found"},
		{"delete_interface", http.MethodDelete, "/v1/interfaces/" + aInterface, "", "interface.not_found"},
		{"read_device", http.MethodGet, "/v1/devices/" + aDevice, "", "device.not_found"},
		{"read_group", http.MethodGet, "/v1/device-groups/" + aGroup, "", "device_group.not_found"},
		{"merge_target", http.MethodPost, "/v1/devices/" + aDevice + "/merge", `{"source_device_ids":["` + bDevice + `"]}`, "device.not_found"},
		{"split_source", http.MethodPost, "/v1/devices/" + aDevice + "/split", `{"identity_history_ids":["` + newUUID() + `"],"name":"x"}`, "device.not_found"},
	} {
		t.Run("cross_tenant_"+tc.name, func(t *testing.T) {
			res := b.do(t, tc.method, tc.path, tc.body)
			requireProblem(t, res, http.StatusNotFound, tc.code)
		})
	}

	// Enumeration resistance: a foreign interface id and a random id produce
	// the same status, code, and detail.
	foreign := b.do(t, http.MethodGet, "/v1/interfaces/"+aInterface, "")
	missing := b.do(t, http.MethodGet, "/v1/interfaces/"+newUUID(), "")
	if foreign.Status != missing.Status || foreign.Body["code"] != missing.Body["code"] ||
		foreign.Body["detail"] != missing.Body["detail"] {
		t.Fatalf("foreign vs missing interface response differs:\nforeign: %v\nmissing: %v", foreign.Body, missing.Body)
	}

	// B cannot merge A's device as a source.
	mergeBody, err := json.Marshal(map[string]any{"source_device_ids": []string{aDevice}})
	must(t, err)
	res = b.do(t, http.MethodPost, "/v1/devices/"+bDevice+"/merge", string(mergeBody))
	requireProblem(t, res, http.StatusNotFound, "device.not_found")

	// B cannot split with A's identity rows (rows are invisible -> validation
	// failure, matching the missing-row response exactly).
	res = a.do(t, http.MethodGet, "/v1/devices/"+aDevice+"/identity-history", "")
	aRowID := dataList(t, res.Body)[0]["id"].(string)
	foreignRows, err := json.Marshal(map[string]any{"identity_history_ids": []string{aRowID}, "name": "stolen"})
	must(t, err)
	foreignSplit := b.do(t, http.MethodPost, "/v1/devices/"+bDevice+"/split", string(foreignRows))
	missingRows, err := json.Marshal(map[string]any{"identity_history_ids": []string{newUUID()}, "name": "stolen"})
	must(t, err)
	missingSplit := b.do(t, http.MethodPost, "/v1/devices/"+bDevice+"/split", string(missingRows))
	if foreignSplit.Status != missingSplit.Status || foreignSplit.Body["code"] != missingSplit.Body["code"] ||
		foreignSplit.Body["detail"] != missingSplit.Body["detail"] {
		t.Fatalf("foreign vs missing split rows differ:\nforeign: %v\nmissing: %v", foreignSplit.Body, missingSplit.Body)
	}

	// A's rows are intact.
	res = a.do(t, http.MethodGet, "/v1/devices/"+aDevice, "")
	if res.Status != http.StatusOK || res.Body["serial"] != "SN-XT-A" {
		t.Fatalf("A's device mutated by B: %d %v", res.Status, res.Body)
	}
	res = a.do(t, http.MethodGet, "/v1/interfaces/"+aInterface, "")
	if res.Status != http.StatusOK || res.Body["description"] != nil {
		t.Fatalf("A's interface mutated by B: %d %v", res.Status, res.Body)
	}
}

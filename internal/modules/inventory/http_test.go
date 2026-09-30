package inventory

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeDevicePatchPresenceSemantics(t *testing.T) {
	body := `{"name":"sw1","status":"down","serial":null,"metadata":{"role":"core"},"site_id":"11111111-1111-7111-8111-111111111111"}`
	req := httptest.NewRequest(http.MethodPatch, "/v1/devices/x", strings.NewReader(body))
	rec := httptest.NewRecorder()
	p, ok := decodeDevicePatch(rec, req)
	if !ok {
		t.Fatalf("valid patch rejected: %s", rec.Body.String())
	}
	if !p.HasName || p.Name != "sw1" {
		t.Fatalf("name patch = %+v", p)
	}
	if !p.HasStatus || p.Status != "down" {
		t.Fatalf("status patch = %+v", p)
	}
	if !p.Serial.Set || p.Serial.Value != nil {
		t.Fatalf("serial null must clear the column: %+v", p.Serial)
	}
	if !p.HasMetadata || !validJSONObject(p.Metadata) {
		t.Fatalf("metadata patch = %q", p.Metadata)
	}
	if !p.HasSiteID {
		t.Fatalf("site_id patch missing: %+v", p)
	}
	// Fields not present must not be flagged as set.
	if p.HasKind || p.HasPollProfile || p.Firmware.Set || p.MgmtIP.Set || p.SysObjectID.Set {
		t.Fatalf("omitted fields marked present: %+v", p)
	}
}

func TestDecodeDevicePatchRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"unknown_field", `{"nope":1}`},
		{"bad_status", `{"status":"broken"}`},
		{"bad_mgmt_ip", `{"mgmt_ip":"999.1.1.1"}`},
		{"null_name", `{"name":null}`},
		{"null_metadata", `{"metadata":null}`},
		{"array_metadata", `{"metadata":[1,2]}`},
		{"bad_site", `{"site_id":"not-a-uuid"}`},
		{"not_json", `{`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPatch, "/v1/devices/x", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			if _, ok := decodeDevicePatch(rec, req); ok {
				t.Fatalf("patch %q accepted, want 400", tc.body)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
				t.Fatalf("content type = %q, want problem+json", ct)
			}
		})
	}
}

func TestDecodeInterfacePatchRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"unknown_field", `{"device_id":"11111111-1111-7111-8111-111111111111"}`},
		{"bad_role", `{"role":"boss"}`},
		{"bad_mac", `{"mac":"not-a-mac"}`},
		{"negative_mtu", `{"mtu":-1}`},
		{"bad_monitored", `{"monitored":"yes"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPatch, "/v1/interfaces/x", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			if _, ok := decodeInterfacePatch(rec, req); ok {
				t.Fatalf("patch %q accepted, want 400", tc.body)
			}
		})
	}
}

func TestDevicePayloadMetadataIsEmbeddedObject(t *testing.T) {
	d := Device{Metadata: json.RawMessage(`{"role":"core"}`)}
	raw, err := json.Marshal(devicePayload(d))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		Metadata map[string]any `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Metadata["role"] != "core" {
		t.Fatalf("metadata = %v", got.Metadata)
	}
}

func TestParseLimitBounds(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		want  int
		valid bool
	}{
		{"", 25, true},
		{"1", 1, true},
		{"100", 100, true},
		{"0", 0, false},
		{"101", 0, false},
		{"abc", 0, false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/v1/devices?limit="+tc.raw, nil)
		if tc.raw == "" {
			req = httptest.NewRequest(http.MethodGet, "/v1/devices", nil)
		}
		got, ok := parseLimit(req)
		if ok != tc.valid || (ok && got != tc.want) {
			t.Fatalf("limit=%q: got (%d,%v), want (%d,%v)", tc.raw, got, ok, tc.want, tc.valid)
		}
	}
}

func TestIdentityTypesMatchSchemaCheck(t *testing.T) {
	// Guard against drift with the 000008 CHECK constraint.
	want := map[string]bool{
		"serial": true, "chassis_id": true, "sys_object_id": true,
		"mac": true, "hostname": true, "mgmt_ip": true,
	}
	if len(IdentityTypes) != len(want) {
		t.Fatalf("IdentityTypes = %v", IdentityTypes)
	}
	for _, typ := range IdentityTypes {
		if !want[typ] {
			t.Fatalf("unexpected identity type %q", typ)
		}
	}
}

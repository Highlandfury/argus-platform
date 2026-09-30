package credentials

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValidateCreateRequest(t *testing.T) {
	valid := createRequest{Name: "core", Kind: "snmp_v2c", Secret: "community"} //nolint:gosec // test value
	if errs := validateCreateRequest(valid); len(errs) != 0 {
		t.Fatalf("valid create rejected: %+v", errs)
	}
	withMeta := valid
	withMeta.Metadata = json.RawMessage(`{"username":"ops"}`)
	if errs := validateCreateRequest(withMeta); len(errs) != 0 {
		t.Fatalf("valid metadata rejected: %+v", errs)
	}

	cases := []struct {
		name  string
		req   createRequest
		field string
	}{
		{"blank_name", createRequest{Name: "   ", Kind: "snmp_v2c", Secret: "SENTINEL-XYZ"}, "name"},
		{"long_name", createRequest{Name: strings.Repeat("a", 201), Kind: "snmp_v2c", Secret: "SENTINEL-XYZ"}, "name"},
		{"blank_kind", createRequest{Name: "core", Kind: " ", Secret: "SENTINEL-XYZ"}, "kind"},
		{"empty_secret", createRequest{Name: "core", Kind: "snmp_v2c"}, "secret"},
		{"bad_metadata", func() createRequest {
			r := valid
			r.Metadata = json.RawMessage(`[1,2]`)
			return r
		}(), "metadata"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateCreateRequest(tc.req)
			if len(errs) == 0 {
				t.Fatalf("request accepted, want field error on %s", tc.field)
			}
			found := false
			for _, e := range errs {
				if e.Field == tc.field {
					found = true
				}
				if strings.Contains(e.Message, tc.req.Secret) && tc.req.Secret != "" {
					t.Fatalf("field error echoes the secret: %+v", e)
				}
			}
			if !found {
				t.Fatalf("field errors %+v missing %s", errs, tc.field)
			}
		})
	}
}

func TestValidateBindingRequest(t *testing.T) {
	scopeID := uuid.New().String()
	priority := 10
	req := httptest.NewRequest(http.MethodPost, "/v1/credentials/x/bind", nil)
	rec := httptest.NewRecorder()
	if _, ok := validateBindingRequest(rec, req, "site", scopeID, &priority, "bind"); !ok {
		t.Fatalf("valid bind rejected: %s", rec.Body.String())
	}

	for _, tc := range []struct {
		name      string
		scopeType string
		scopeID   string
		priority  *int
		field     string
	}{
		{"bad_scope_type", "building", scopeID, nil, "scope_type"},
		{"empty_scope_type", "", scopeID, nil, "scope_type"},
		{"bad_scope_id", "site", "not-a-uuid", nil, "scope_id"},
		{"priority_overflow", "site", scopeID, intPtr(1 << 40), "priority"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/credentials/x/bind", nil)
			rec := httptest.NewRecorder()
			if _, ok := validateBindingRequest(rec, req, tc.scopeType, tc.scopeID, tc.priority, "bind"); ok {
				t.Fatalf("invalid bind accepted (%s)", tc.name)
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
				t.Fatalf("content type = %q", ct)
			}
			var body struct {
				Errors []struct {
					Field string `json:"field"`
				} `json:"errors"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("problem body: %v", err)
			}
			found := false
			for _, e := range body.Errors {
				if e.Field == tc.field {
					found = true
				}
			}
			if !found {
				t.Fatalf("errors %+v missing %s", body.Errors, tc.field)
			}
		})
	}
}

// TestValidJSONObject pins the metadata gate shared with the inventory
// conventions.
func TestValidJSONObject(t *testing.T) {
	for _, ok := range []string{`{}`, `{"a":1}`} {
		if !validJSONObject(json.RawMessage(ok)) {
			t.Fatalf("%s rejected", ok)
		}
	}
	for _, bad := range []string{``, `null`, `[]`, `"x"`, `{`} {
		if validJSONObject(json.RawMessage(bad)) {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func intPtr(n int) *int { return &n }

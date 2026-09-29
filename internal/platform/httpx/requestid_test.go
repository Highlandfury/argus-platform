package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestIDPolicy(t *testing.T) {
	valid := []string{"abc123", "req-42_1.2:3+4", strings.Repeat("a", maxRequestIDLen)}
	for _, id := range valid {
		if !ValidRequestID(id) {
			t.Fatalf("%q must be accepted", id)
		}
	}
	invalid := []string{"", strings.Repeat("a", maxRequestIDLen+1), "has space", "new\nline", "control\x01char", "quote\"", "brace{}", "semi;colon"}
	for _, id := range invalid {
		if ValidRequestID(id) {
			t.Fatalf("%q must be rejected", id)
		}
	}
}

// TestRequestIDInjectionProtection covers the hostile-input matrix: invalid
// or oversized caller IDs are replaced, echoed consistently, and can never
// reach logs as multi-field/multi-line payloads.
func TestRequestIDInjectionProtection(t *testing.T) {
	cases := []struct {
		name    string
		header  string
		replace bool
	}{
		{"missing", "", true},
		{"normal", "caller-id-1", false},
		{"repeated", "caller-id-1", false},
		{"malformed", "bad id with spaces", true},
		{"newline-injection", "ok\n{\"level\":\"ERROR\"}", true},
		{"excessive", strings.Repeat("x", 4096), true},
		{"control-chars", "a\x00\x1fb", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen string
			handler := RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				seen = RequestIDFrom(r.Context())
			}))
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if tc.header != "" {
				req.Header.Set("X-Request-ID", tc.header)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if seen == "" {
				t.Fatal("no request id in context")
			}
			if got := rr.Header().Get("X-Request-ID"); got != seen {
				t.Fatalf("echoed id %q != context id %q", got, seen)
			}
			if tc.replace {
				if seen == tc.header {
					t.Fatalf("invalid id was accepted verbatim")
				}
				if !ValidRequestID(seen) {
					t.Fatalf("generated id %q fails the policy", seen)
				}
			} else if seen != tc.header {
				t.Fatalf("valid id not preserved: %q", seen)
			}
			// The stored ID must never carry newlines/control bytes.
			if strings.ContainsAny(seen, "\n\r\x00") {
				t.Fatalf("unsafe id reached the context: %q", seen)
			}
		})
	}
}

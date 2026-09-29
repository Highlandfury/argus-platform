package httpx

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteProblem(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/things", nil)
	req = req.WithContext(context.WithValue(req.Context(), requestIDKey{}, "req-42"))

	WriteProblem(rec, req, http.StatusUnprocessableEntity, "validation.failed", "2 fields invalid",
		FieldError{Field: "mgmt_ip", Code: "format.ipv4", Message: "not a valid IPv4 address"})

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("unexpected content type: %q", ct)
	}
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if p.Code != "validation.failed" || p.Status != 422 || p.RequestID != "req-42" {
		t.Fatalf("unexpected problem: %+v", p)
	}
	if len(p.Errors) != 1 || p.Errors[0].Field != "mgmt_ip" {
		t.Fatalf("unexpected field errors: %+v", p.Errors)
	}
	if !strings.HasPrefix(p.Type, TypeBase) {
		t.Fatalf("type should be namespaced: %q", p.Type)
	}
}

func TestRequestIDGeneratesAndPropagates(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if seen == "" {
		t.Fatal("expected generated request id in context")
	}
	if rec.Header().Get("X-Request-ID") != seen {
		t.Fatal("response header must echo the request id")
	}
}

func TestRequestIDEchoesCaller(t *testing.T) {
	h := RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if got := RequestIDFrom(r.Context()); got != "caller-provided" {
			t.Fatalf("context id = %q", got)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "caller-provided")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("X-Request-ID") != "caller-provided" {
		t.Fatal("response must echo caller-provided id")
	}
}

// Package httpx holds HTTP plumbing shared by all modules: RFC 9457 problem
// responses, request correlation IDs, and access logging.
package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// Problem is the RFC 9457 problem-details payload used for every API error.
type Problem struct {
	Type      string       `json:"type"`
	Title     string       `json:"title"`
	Status    int          `json:"status"`
	Detail    string       `json:"detail,omitempty"`
	Code      string       `json:"code"`
	Errors    []FieldError `json:"errors,omitempty"`
	RequestID string       `json:"request_id,omitempty"`
}

// FieldError describes one validation failure inside Problem.Errors.
type FieldError struct {
	Field   string `json:"field"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// TypeBase is the URI prefix for machine-readable error types.
const TypeBase = "https://docs.argus.local/errors/"

// WriteProblem writes an RFC 9457 problem+json response. The request ID is
// taken from the request context when available.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string, fieldErrs ...FieldError) {
	p := Problem{
		Type:      TypeBase + code,
		Title:     http.StatusText(status),
		Status:    status,
		Detail:    detail,
		Code:      code,
		RequestID: RequestIDFrom(r.Context()),
	}
	if len(fieldErrs) > 0 {
		p.Errors = fieldErrs
	}
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

type requestIDKey struct{}

// RequestID ensures every request carries an X-Request-ID: it reuses a caller
// supplied value or generates a 128-bit random one, stores it in the context,
// and echoes it on the response.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || len(id) > 128 {
			buf := make([]byte, 16)
			if _, err := rand.Read(buf); err != nil {
				id = "unavailable"
			} else {
				id = hex.EncodeToString(buf)
			}
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// RequestIDFrom extracts the correlation ID from the context.
func RequestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

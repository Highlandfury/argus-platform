package httpx

import (
	"encoding/json"
	"net/http"
)

// PublicUser / PublicOrg / MePayload are the stable JSON shapes shared by the
// identity and tenancy HTTP handlers (and mirrored in openapi/argus.v1.yaml).
type PublicUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

// PublicOrg is the public organization projection.
type PublicOrg struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// MePayload is the /v1/me response (also returned by a successful login).
type MePayload struct {
	User PublicUser `json:"user"`
	Org  PublicOrg  `json:"org"`
}

// WriteJSON writes a JSON response with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Package credentials owns the write-only device credential API surface
// (M7-S4): metadata list/detail, create, rotate, and scope bind/unbind, plus
// the M9 dispatch resolver boundary.
//
// Plaintext secrets exist only transiently in process memory: they are sealed
// by the SecretsVault (M7-S2, envelope encryption with the canonical
// encryption context) on the way in, and can only be materialized through the
// internal resolver (resolver.go) for future collector dispatch — never over
// HTTP. The persistence models in this file carry the envelope columns; the
// API-safe metadata projection deliberately cannot (models_test.go pins this).
//
// Every store call runs inside one database.WithTenant transaction, so RLS
// (device_credentials_tenant, credential_bindings_tenant) enforces isolation
// even when a query forgets an org filter.
package credentials

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/secrets"
)

// Credential is one device_credentials row including the sealed envelope. It
// is the persistence model and MUST NOT be serialized to API clients (use
// CredentialMetadata).
type Credential struct {
	ID                uuid.UUID
	OrgID             uuid.UUID
	Name              string
	Kind              string
	DataEnc           []byte
	KMSKeyID          string
	KeyVersion        int
	EncryptionContext json.RawMessage
	Metadata          json.RawMessage
	RotatedAt         *time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Envelope rebuilds the SecretsVault envelope from this row's columns. The
// vault's Open verifies the encryption context against the key material, so a
// mixed-up row fails closed.
func (c Credential) Envelope() (secrets.Envelope, error) {
	ctx, err := secrets.ParseContext(c.EncryptionContext)
	if err != nil {
		return secrets.Envelope{}, err
	}
	return secrets.Envelope{
		DataEnc:           c.DataEnc,
		KMSKeyID:          c.KMSKeyID,
		KeyVersion:        c.KeyVersion,
		EncryptionContext: ctx,
	}, nil
}

// Binding is one credential_bindings row: a credential applies to a scope
// (org | site | device_group | device) at a priority (higher wins at dispatch;
// see resolver.go for the precedence and tie-break rules).
type Binding struct {
	ID           uuid.UUID
	OrgID        uuid.UUID
	CredentialID uuid.UUID
	ScopeType    string
	ScopeID      uuid.UUID
	Priority     int
	CreatedAt    time.Time
}

// BindingSummary is the API-safe projection of one binding.
type BindingSummary struct {
	ID        string `json:"id"`
	ScopeType string `json:"scope_type"`
	ScopeID   string `json:"scope_id"`
	Priority  int    `json:"priority"`
	CreatedAt string `json:"created_at"`
}

// CredentialMetadata is the API-safe projection of a credential: identity,
// descriptor metadata, and binding summaries only. The envelope columns
// (data_enc, kms_key_id, key_version, encryption_context) and any plaintext
// are structurally absent; the JSON has no secret-read field of any kind.
type CredentialMetadata struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Kind      string           `json:"kind"`
	Metadata  json.RawMessage  `json:"metadata"`
	RotatedAt *string          `json:"rotated_at"`
	CreatedAt string           `json:"created_at"`
	UpdatedAt string           `json:"updated_at"`
	Bindings  []BindingSummary `json:"bindings"`
}

// ProjectCredential builds the API-safe metadata projection. It never copies
// envelope or key material.
func ProjectCredential(c Credential, bindings []Binding) CredentialMetadata {
	meta := c.Metadata
	if len(meta) == 0 {
		meta = json.RawMessage(`{}`)
	}
	out := CredentialMetadata{
		ID:        c.ID.String(),
		Name:      c.Name,
		Kind:      c.Kind,
		Metadata:  meta,
		RotatedAt: rfc3339Ptr(c.RotatedAt),
		CreatedAt: c.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: c.UpdatedAt.UTC().Format(time.RFC3339),
		Bindings:  make([]BindingSummary, 0, len(bindings)),
	}
	for _, b := range bindings {
		out.Bindings = append(out.Bindings, ProjectBinding(b))
	}
	return out
}

// ProjectBinding builds the API-safe projection of one binding.
func ProjectBinding(b Binding) BindingSummary {
	return BindingSummary{
		ID:        b.ID.String(),
		ScopeType: b.ScopeType,
		ScopeID:   b.ScopeID.String(),
		Priority:  b.Priority,
		CreatedAt: b.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func rfc3339Ptr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// ScopeTypes lists the scope types a binding may target. The values are the
// canonical scope vocabulary shared with the authorization layer
// (internal/platform/authz) and match the credential_bindings CHECK constraint
// (migration 000009).
var ScopeTypes = []string{"org", "site", "device_group", "device"}

// IsScopeType reports whether name is a bindable scope type.
func IsScopeType(name string) bool {
	for _, s := range ScopeTypes {
		if s == name {
			return true
		}
	}
	return false
}

// scopeRank is the dispatch precedence tier of a scope type: direct device
// bindings beat group bindings, which beat site bindings, which beat org
// bindings. Unknown scope types rank last (fail closed: they never win).
func scopeRank(scopeType string) int {
	switch scopeType {
	case "device":
		return 1
	case "device_group":
		return 2
	case "site":
		return 3
	case "org":
		return 4
	}
	return 5
}

// candidate is one (credential, binding) pair applicable to a device.
type candidate struct {
	Credential Credential
	Binding    Binding
}

// EffectiveCredential is the resolver's decision: the credential that applies
// to a device and where it was bound. Version is the stored envelope
// key_version (encryption_context.version) at resolution time; collector
// materialization binds it into the authenticated ciphertext context so a
// record cannot be replayed across envelope generations.
type EffectiveCredential struct {
	CredentialID uuid.UUID
	Name         string
	Kind         string
	Version      int
	ScopeType    string
	ScopeID      uuid.UUID
	Priority     int
}

// selectEffective picks the winning candidate. Canonical rules (docs/14 §24.5,
// docs/11 §21.1): the most specific scope wins (device > device_group > site >
// org), and within one scope level the higher priority wins. The canonical docs
// do not define a same-priority tie-break; this implementation picks the lowest
// credential id — UUIDv7 ids are time-sortable, so this is the oldest
// credential, a deterministic and stable rule (documented in M7_EVIDENCE.md).
// Candidates with an unknown scope type are ignored (fail closed).
func selectEffective(candidates []candidate) (EffectiveCredential, bool) {
	known := candidates[:0]
	for _, c := range candidates {
		if scopeRank(c.Binding.ScopeType) < 5 {
			known = append(known, c)
		}
	}
	if len(known) == 0 {
		return EffectiveCredential{}, false
	}
	sort.SliceStable(known, func(i, j int) bool {
		a, b := known[i], known[j]
		if ra, rb := scopeRank(a.Binding.ScopeType), scopeRank(b.Binding.ScopeType); ra != rb {
			return ra < rb
		}
		if a.Binding.Priority != b.Binding.Priority {
			return a.Binding.Priority > b.Binding.Priority
		}
		return bytes.Compare(a.Binding.CredentialID[:], b.Binding.CredentialID[:]) < 0
	})
	win := known[0]
	return EffectiveCredential{
		CredentialID: win.Credential.ID,
		Name:         win.Credential.Name,
		Kind:         win.Credential.Kind,
		Version:      win.Credential.KeyVersion,
		ScopeType:    win.Binding.ScopeType,
		ScopeID:      win.Binding.ScopeID,
		Priority:     win.Binding.Priority,
	}, true
}

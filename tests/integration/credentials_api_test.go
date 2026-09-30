package integration

// M7-S4 (Phase 2): credentials API acceptance — write-only lifecycle
// (create/list/detail/rotate), scope binding (bind/unbind with server-side
// target validation), the M9 resolver boundary, envelope rotation, audit
// evidence, and secret-leak scans (P2-AC-04/05). The S-22..S-25 additions at
// the bottom back the security suite probes (capability, CSRF, cross-tenant,
// scope restriction).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/modules/credentials"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/secrets"
	"github.com/argus-platform/argus/internal/platform/security"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// recordingCredentialAudit captures credential audit events in-process (the
// production sink is credentials.SlogAudit).
type recordingCredentialAudit struct {
	mu     sync.Mutex
	events []credentials.AuditEvent
}

func (r *recordingCredentialAudit) Record(ev credentials.AuditEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingCredentialAudit) all() []credentials.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]credentials.AuditEvent(nil), r.events...)
}

func (r *recordingCredentialAudit) find(action string) []credentials.AuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []credentials.AuditEvent
	for _, ev := range r.events {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

func (r *recordingCredentialAudit) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// credentialEnv is one logged-in tenant with the credentials API wired, the
// audit sink observable, and the server log captured for leak scans.
type credentialEnv struct {
	srv         *httptest.Server
	client      *http.Client
	slug        string
	orgID       string
	siteID      string
	userID      string
	csrf        string
	audit       *recordingCredentialAudit
	logs        *bytes.Buffer
	vault       secrets.SecretsVault
	keyPath     string
	firstCredID string // lazy fixture for cross-tenant probes
}

func newCredentialEnv(t *testing.T, slug string) *credentialEnv {
	t.Helper()
	seed := seedLoginUser(t, slug, "HQ-"+slug)

	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identity.New(appPool, authPool, tenancySvc)
	must(t, err)

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	keyPath := filepath.Join(t.TempDir(), "master.key")
	kek, err := secrets.LoadOrCreateLocalKMS(secrets.LocalConfig{
		Path: keyPath, KeyID: "it-credentials", AllowGenerate: true, Logger: logger,
	})
	must(t, err)
	vault := secrets.New(kek)
	rec := &recordingCredentialAudit{}
	router := api.NewRouter(api.Options{
		Logger:      logger,
		Telemetry:   telemetry.New("it-credentials", "0", "0"),
		Version:     "it",
		Commit:      "it",
		Identity:    identitySvc,
		Tenancy:     tenancySvc,
		Credentials: credentials.New(appPool, vault, rec),
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
	return &credentialEnv{
		srv:     srv,
		client:  client,
		slug:    slug,
		orgID:   seed.OrgID,
		siteID:  seed.SiteID,
		userID:  seed.UserID,
		csrf:    csrf.Value,
		audit:   rec,
		logs:    &logs,
		vault:   vault,
		keyPath: keyPath,
	}
}

// do performs an authenticated request carrying the session's CSRF token.
func (e *credentialEnv) do(t *testing.T, method, path, body string) apiResponse {
	t.Helper()
	return doRequest(t, e.client, method, e.srv.URL+path, body, map[string]string{"X-CSRF-Token": e.csrf})
}

// create posts a credential and returns its id.
func (e *credentialEnv) create(t *testing.T, name, kind, secret string, metadata map[string]any) string {
	t.Helper()
	payload := map[string]any{"name": name, "kind": kind, "secret": secret}
	if metadata != nil {
		payload["metadata"] = metadata
	}
	raw, err := json.Marshal(payload)
	must(t, err)
	res := e.do(t, http.MethodPost, "/v1/credentials", string(raw))
	if res.Status != http.StatusCreated {
		t.Fatalf("create credential %s: status %d body %v", name, res.Status, res.Body)
	}
	id, _ := res.Body["id"].(string)
	if id == "" {
		t.Fatalf("create credential %s: missing id: %v", name, res.Body)
	}
	return id
}

// bind posts a binding and returns the binding id.
func (e *credentialEnv) bind(t *testing.T, credentialID, scopeType, scopeID string, priority int) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"scope_type": scopeType, "scope_id": scopeID, "priority": priority})
	must(t, err)
	res := e.do(t, http.MethodPost, "/v1/credentials/"+credentialID+"/bind", string(raw))
	if res.Status != http.StatusCreated {
		t.Fatalf("bind %s to %s/%s: status %d body %v", credentialID, scopeType, scopeID, res.Status, res.Body)
	}
	id, _ := res.Body["id"].(string)
	if id == "" {
		t.Fatalf("bind returned no id: %v", res.Body)
	}
	return id
}

// createDeviceRowCred inserts a live device through the app path and returns
// its id (the credentials suite only needs the row for binding/resolution).
func createDeviceRowCred(t *testing.T, orgID, siteID, name string) string {
	t.Helper()
	id := newUUID()
	err := database.WithTenant(context.Background(), appPool, mustUUID(t, orgID), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO devices (id, org_id, site_id, name, kind) VALUES ($1, $2, $3, $4, 'switch')`,
			id, orgID, siteID, name)
		return err
	})
	must(t, err)
	return id
}

// createGroupRowCred inserts a device group through the app path.
func createGroupRowCred(t *testing.T, orgID, name string) string {
	t.Helper()
	id := newUUID()
	err := database.WithTenant(context.Background(), appPool, mustUUID(t, orgID), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO device_groups (id, org_id, name) VALUES ($1, $2, $3)`, id, orgID, name)
		return err
	})
	must(t, err)
	return id
}

// credentialEnvelopeRow loads one credential's stored envelope through the
// owner pool (owner bypasses RLS; the API paths under test never do).
func credentialEnvelopeRow(t *testing.T, credentialID string) (secrets.Envelope, []byte) {
	t.Helper()
	var (
		dataEnc    []byte
		kmsKeyID   string
		keyVersion int
		rawContext []byte
	)
	must(t, ownerPool.QueryRow(context.Background(),
		`SELECT data_enc, kms_key_id, key_version, encryption_context
		 FROM device_credentials WHERE id = $1`, credentialID).
		Scan(&dataEnc, &kmsKeyID, &keyVersion, &rawContext))
	storedCtx, err := secrets.ParseContext(rawContext)
	must(t, err)
	return secrets.Envelope{
		DataEnc:           dataEnc,
		KMSKeyID:          kmsKeyID,
		KeyVersion:        keyVersion,
		EncryptionContext: storedCtx,
	}, dataEnc
}

// credentialRotatedAt reads the rotated_at column (nil before the first rotate).
func credentialRotatedAt(t *testing.T, credentialID string) *time.Time {
	t.Helper()
	var rotatedAt *time.Time
	must(t, ownerPool.QueryRow(context.Background(),
		`SELECT rotated_at FROM device_credentials WHERE id = $1`, credentialID).Scan(&rotatedAt))
	return rotatedAt
}

// credentialDump returns a full JSON dump of every device_credentials row for
// at-rest leak scans.
func credentialDump(t *testing.T) string {
	t.Helper()
	var dump string
	must(t, ownerPool.QueryRow(context.Background(),
		`SELECT COALESCE(string_agg(row_to_json(dc)::text, E'\n'), '') FROM device_credentials dc`).Scan(&dump))
	return dump
}

// requireNoForbiddenFields fails when an API payload contains secret material
// or envelope columns.
func requireNoForbiddenFields(t *testing.T, body string, secretsToCheck ...string) {
	t.Helper()
	for _, field := range []string{"data_enc", "kms_key_id", "key_version", "encryption_context"} {
		if strings.Contains(body, field) {
			t.Fatalf("response leaks envelope column %q: %s", field, body)
		}
	}
	for _, secret := range secretsToCheck {
		if secret == "" {
			continue
		}
		if strings.Contains(body, secret) {
			t.Fatalf("response leaks a secret value: %s", body)
		}
	}
}

// TestCredentialsWriteOnlyLifecycle covers create -> list -> detail ->
// rotation with metadata-only responses, at-rest verification, and the
// guarantee that no secret-read endpoint exists.
func TestCredentialsWriteOnlyLifecycle(t *testing.T) {
	env := newCredentialEnv(t, "cred-wo-"+newUUID()[:8])
	secret1 := "SENTINEL-SECRET-1-" + newUUID()
	secret2 := "SENTINEL-SECRET-2-" + newUUID()

	res := env.do(t, http.MethodPost, "/v1/credentials", `{"name":"core-snmp","kind":"snmp_v2c","secret":"`+secret1+`","metadata":{"username":"ops"}}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("create: status %d body %v", res.Status, res.Body)
	}
	id, _ := res.Body["id"].(string)
	requireNoForbiddenFields(t, toJSON(t, res.Body), secret1)
	if res.Body["name"] != "core-snmp" || res.Body["kind"] != "snmp_v2c" {
		t.Fatalf("metadata fields wrong: %v", res.Body)
	}
	if res.Body["rotated_at"] != nil {
		t.Fatalf("fresh credential must have null rotated_at: %v", res.Body["rotated_at"])
	}
	if res.Body["secret"] != nil {
		t.Fatal("response must not have a secret field")
	}
	meta, _ := res.Body["metadata"].(map[string]any)
	if meta["username"] != "ops" {
		t.Fatalf("metadata not passed through: %v", res.Body["metadata"])
	}

	// List and detail are metadata-only and include the binding summary.
	res = env.do(t, http.MethodGet, "/v1/credentials", "")
	if res.Status != http.StatusOK {
		t.Fatalf("list: status %d body %v", res.Status, res.Body)
	}
	requireNoForbiddenFields(t, toJSON(t, res.Body), secret1)
	if items := dataList(t, res.Body); len(items) != 1 || items[0]["id"] != id {
		t.Fatalf("list payload = %v", res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/credentials/"+id, "")
	if res.Status != http.StatusOK {
		t.Fatalf("detail: status %d body %v", res.Status, res.Body)
	}
	requireNoForbiddenFields(t, toJSON(t, res.Body), secret1)
	detailPayload := toJSON(t, res.Body)

	// No secret-read surface exists: unknown sub-path is 404, ?reveal=true is
	// ignored (same metadata), and neither carries secret material.
	res = env.do(t, http.MethodGet, "/v1/credentials/"+id+"/secret", "")
	if res.Status != http.StatusNotFound {
		t.Fatalf("secret sub-path: status %d, want 404", res.Status)
	}
	if strings.Contains(toJSON(t, res.Body), secret1) {
		t.Fatal("404 body leaks the secret")
	}
	res = env.do(t, http.MethodGet, "/v1/credentials/"+id+"?reveal=true", "")
	if res.Status != http.StatusOK || toJSON(t, res.Body) != detailPayload {
		t.Fatalf("?reveal=true changed the metadata response: %d %v", res.Status, res.Body)
	}

	// At rest: ciphertext envelope, no plaintext anywhere in the row/table.
	stored, dataEncBefore := credentialEnvelopeRow(t, id)
	if len(dataEncBefore) == 0 || bytes.Contains(dataEncBefore, []byte(secret1)) {
		t.Fatal("data_enc must be a non-empty ciphertext envelope")
	}
	if got, err := env.vault.Open(stored); err != nil || string(got) != secret1 {
		t.Fatalf("stored envelope does not open to the submitted secret: %v", err)
	}
	if dump := credentialDump(t); strings.Contains(dump, secret1) {
		t.Fatal("plaintext appears in a device_credentials dump")
	}

	// Rotation: metadata-only response, fresh ciphertext, rotated_at stamped,
	// and the new envelope opens to secret2 only.
	res = env.do(t, http.MethodPost, "/v1/credentials/"+id+"/rotate", `{"secret":"`+secret2+`"}`)
	if res.Status != http.StatusOK {
		t.Fatalf("rotate: status %d body %v", res.Status, res.Body)
	}
	requireNoForbiddenFields(t, toJSON(t, res.Body), secret2, secret1)
	if res.Body["rotated_at"] == nil {
		t.Fatal("rotate must stamp rotated_at")
	}
	_, dataEncAfter := credentialEnvelopeRow(t, id)
	if bytes.Equal(dataEncBefore, dataEncAfter) {
		t.Fatal("rotation must replace the ciphertext envelope")
	}
	rotated, _ := credentialEnvelopeRow(t, id)
	if got, err := env.vault.Open(rotated); err != nil || string(got) != secret2 {
		t.Fatalf("rotated envelope does not open to the new secret: %v", err)
	}
	if rotatedAt := credentialRotatedAt(t, id); rotatedAt == nil {
		t.Fatal("rotated_at not persisted")
	}
	if dump := credentialDump(t); strings.Contains(dump, secret1) || strings.Contains(dump, secret2) {
		t.Fatal("plaintext appears in a device_credentials dump after rotation")
	}

	// Validation: required fields produce field errors naming no secret.
	res = env.do(t, http.MethodPost, "/v1/credentials", `{"name":"","kind":"","secret":""}`)
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	fields, _ := res.Body["errors"].([]any)
	if len(fields) < 3 {
		t.Fatalf("expected name/kind/secret field errors: %v", res.Body)
	}

	// Name uniqueness is a deterministic 409.
	res = env.do(t, http.MethodPost, "/v1/credentials", `{"name":"core-snmp","kind":"snmp_v2c","secret":"`+secret2+`"}`)
	requireProblem(t, res, http.StatusConflict, "credential.name_conflict")

	// Pagination: one row per page with a cursor, invalid cursor rejected.
	env.create(t, "core-snmp-2", "snmp_v3", "SENTINEL-SECRET-3-"+newUUID(), nil)
	res = env.do(t, http.MethodGet, "/v1/credentials?limit=1", "")
	if res.Status != http.StatusOK || res.Body["has_more"] != true {
		t.Fatalf("page 1: %d %v", res.Status, res.Body)
	}
	cursor, _ := res.Body["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("page 1 missing next_cursor")
	}
	res = env.do(t, http.MethodGet, "/v1/credentials?limit=1&cursor="+cursor, "")
	if res.Status != http.StatusOK || res.Body["has_more"] != false {
		t.Fatalf("page 2: %d %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/credentials?cursor=not-a-uuid", "")
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
}

// TestCredentialsBindUnbind covers all four scope types, duplicate conflicts,
// invalid/foreign targets, and unbind semantics.
func TestCredentialsBindUnbind(t *testing.T) {
	env := newCredentialEnv(t, "cred-bind-"+newUUID()[:8])
	credID := env.create(t, "bind-cred", "snmp_v2c", "SENTINEL-BIND-"+newUUID(), nil)
	deviceID := createDeviceRowCred(t, env.orgID, env.siteID, "bind-dev-"+newUUID()[:8])
	groupID := createGroupRowCred(t, env.orgID, "bind-group-"+newUUID()[:8])

	// Every scope type binds.
	env.bind(t, credID, "org", env.orgID, 0)
	env.bind(t, credID, "site", env.siteID, 5)
	env.bind(t, credID, "device_group", groupID, 7)
	env.bind(t, credID, "device", deviceID, 9)

	res := env.do(t, http.MethodGet, "/v1/credentials/"+credID, "")
	bindings, _ := res.Body["bindings"].([]any)
	if len(bindings) != 4 {
		t.Fatalf("bindings = %v", res.Body["bindings"])
	}
	byScope := map[string]map[string]any{}
	for _, raw := range bindings {
		b, _ := raw.(map[string]any)
		st, _ := b["scope_type"].(string)
		byScope[st] = b
	}
	for _, scope := range []string{"org", "site", "device_group", "device"} {
		if byScope[scope] == nil {
			t.Fatalf("missing %s binding: %v", scope, bindings)
		}
	}
	if byScope["site"]["priority"] != float64(5) || byScope["device"]["priority"] != float64(9) {
		t.Fatalf("priorities not persisted: %v", byScope)
	}

	// Duplicate binding -> deterministic 409.
	res = env.do(t, http.MethodPost, "/v1/credentials/"+credID+"/bind",
		`{"scope_type":"site","scope_id":"`+env.siteID+`","priority":1}`)
	requireProblem(t, res, http.StatusConflict, "credential.binding_conflict")

	// Invalid scope types / ids are validation errors.
	for _, body := range []string{
		`{"scope_type":"building","scope_id":"` + env.siteID + `"}`,
		`{"scope_type":"site","scope_id":"not-a-uuid"}`,
		`{"scope_id":"` + env.siteID + `"}`,
	} {
		res = env.do(t, http.MethodPost, "/v1/credentials/"+credID+"/bind", body)
		requireProblem(t, res, http.StatusBadRequest, "validation.failed")
	}

	// Foreign/unknown targets are uniformly 404 (no existence oracle).
	other := newCredentialEnv(t, "cred-bind-other-"+newUUID()[:8])
	foreignSite := createSite(t, other.orgID, "FOREIGN-"+newUUID()[:8])
	foreignGroup := createGroupRowCred(t, other.orgID, "foreign-group-"+newUUID()[:8])
	foreignDevice := createDeviceRowCred(t, other.orgID, other.siteID, "foreign-dev-"+newUUID()[:8])
	missing := newUUID()
	for _, tc := range []struct{ scopeType, scopeID string }{
		{"site", foreignSite}, {"site", missing},
		{"device_group", foreignGroup}, {"device_group", missing},
		{"device", foreignDevice}, {"device", missing},
	} {
		raw, err := json.Marshal(map[string]any{"scope_type": tc.scopeType, "scope_id": tc.scopeID})
		must(t, err)
		res = env.do(t, http.MethodPost, "/v1/credentials/"+credID+"/bind", string(raw))
		requireProblem(t, res, http.StatusNotFound, "credential.target_not_found")
	}

	// Foreign credential ids are 404 on every mutation/read.
	for _, tc := range []struct{ name, method, path, body string }{
		{"detail", http.MethodGet, "/v1/credentials/" + otherCredID(t, other), ""},
		{"rotate", http.MethodPost, "/v1/credentials/" + otherCredID(t, other) + "/rotate", `{"secret":"x"}`},
		{"bind", http.MethodPost, "/v1/credentials/" + otherCredID(t, other) + "/bind", `{"scope_type":"org","scope_id":"` + env.orgID + `"}`},
		{"unbind", http.MethodPost, "/v1/credentials/" + otherCredID(t, other) + "/unbind", `{"scope_type":"org","scope_id":"` + env.orgID + `"}`},
	} {
		t.Run("foreign_credential_"+tc.name, func(t *testing.T) {
			res := env.do(t, tc.method, tc.path, tc.body)
			requireProblem(t, res, http.StatusNotFound, "credential.not_found")
		})
	}

	// Unbind is by (scope_type, scope_id) and does not resolve the target.
	res = env.do(t, http.MethodPost, "/v1/credentials/"+credID+"/unbind",
		`{"scope_type":"site","scope_id":"`+foreignSite+`"}`)
	requireProblem(t, res, http.StatusNotFound, "credential.binding_not_found")
	res = env.do(t, http.MethodPost, "/v1/credentials/"+credID+"/unbind",
		`{"scope_type":"site","scope_id":"`+env.siteID+`"}`)
	if res.Status != http.StatusNoContent {
		t.Fatalf("unbind: status %d body %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodGet, "/v1/credentials/"+credID, "")
	bindings, _ = res.Body["bindings"].([]any)
	if len(bindings) != 3 {
		t.Fatalf("bindings after unbind = %v", res.Body["bindings"])
	}
	// Unbinding the same scope again is a deterministic 404.
	res = env.do(t, http.MethodPost, "/v1/credentials/"+credID+"/unbind",
		`{"scope_type":"site","scope_id":"`+env.siteID+`"}`)
	requireProblem(t, res, http.StatusNotFound, "credential.binding_not_found")
	// Unbind an unknown scope type is 400.
	res = env.do(t, http.MethodPost, "/v1/credentials/"+credID+"/unbind",
		`{"scope_type":"zone","scope_id":"`+env.siteID+`"}`)
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
}

// otherCredID lazily creates one credential in another environment.
func otherCredID(t *testing.T, env *credentialEnv) string {
	t.Helper()
	if env.firstCredID != "" {
		return env.firstCredID
	}
	env.firstCredID = env.create(t, "other-cred-"+newUUID()[:8], "snmp_v3", "SENTINEL-OTHER-"+newUUID(), nil)
	return env.firstCredID
}

// TestCredentialsEnumerationParity: foreign and missing credentials/targets
// produce byte-identical problem bodies (modulo request_id), so responses are
// not an existence oracle.
func TestCredentialsEnumerationParity(t *testing.T) {
	env := newCredentialEnv(t, "cred-enum-"+newUUID()[:8])
	other := newCredentialEnv(t, "cred-enum-other-"+newUUID()[:8])
	foreignCred := otherCredID(t, other)
	missingCred := newUUID()

	normalize := func(res apiResponse) string {
		body := map[string]any{}
		for k, v := range res.Body {
			if k == "request_id" {
				continue
			}
			body[k] = v
		}
		return toJSON(t, body)
	}

	// Foreign vs missing credential (detail and rotate).
	for _, tc := range []struct{ name, method, path, body string }{
		{"detail", http.MethodGet, "/v1/credentials/", ""},
		{"rotate", http.MethodPost, "/v1/credentials/%s/rotate", `{"secret":"x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var foreignRes, missingRes apiResponse
			if tc.method == http.MethodGet {
				foreignRes = env.do(t, tc.method, tc.path+foreignCred, tc.body)
				missingRes = env.do(t, tc.method, tc.path+missingCred, tc.body)
			} else {
				foreignRes = env.do(t, tc.method, strings.Replace(tc.path, "%s", foreignCred, 1), tc.body)
				missingRes = env.do(t, tc.method, strings.Replace(tc.path, "%s", missingCred, 1), tc.body)
			}
			requireProblem(t, foreignRes, http.StatusNotFound, "credential.not_found")
			requireProblem(t, missingRes, http.StatusNotFound, "credential.not_found")
			if normalize(foreignRes) != normalize(missingRes) {
				t.Fatalf("foreign and missing bodies differ:\n%s\n%s", normalize(foreignRes), normalize(missingRes))
			}
			if ct := foreignRes.Header.Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
				t.Fatalf("content type = %q", ct)
			}
		})
	}

	// Foreign vs missing bind target (site type).
	credID := env.create(t, "enum-cred", "snmp_v2c", "SENTINEL-ENUM-"+newUUID(), nil)
	foreignSite := createSite(t, other.orgID, "ENUM-FOREIGN-"+newUUID()[:8])
	missingSite := newUUID()
	foreignRes := env.do(t, http.MethodPost, "/v1/credentials/"+credID+"/bind",
		`{"scope_type":"site","scope_id":"`+foreignSite+`"}`)
	missingRes := env.do(t, http.MethodPost, "/v1/credentials/"+credID+"/bind",
		`{"scope_type":"site","scope_id":"`+missingSite+`"}`)
	requireProblem(t, foreignRes, http.StatusNotFound, "credential.target_not_found")
	requireProblem(t, missingRes, http.StatusNotFound, "credential.target_not_found")
	if normalize(foreignRes) != normalize(missingRes) {
		t.Fatalf("foreign and missing target bodies differ:\n%s\n%s", normalize(foreignRes), normalize(missingRes))
	}
}

// TestCredentialsResolver covers the M9 hook: unbound rejection, every scope
// level, priority, deterministic tie-break, group-tier extension, cross-tenant
// rejection, and plaintext materialization.
func TestCredentialsResolver(t *testing.T) {
	env := newCredentialEnv(t, "cred-res-"+newUUID()[:8])
	site2 := createSite(t, env.orgID, "R2-"+env.slug)
	dev1 := createDeviceRowCred(t, env.orgID, env.siteID, "res-dev1-"+newUUID()[:8])
	dev2 := createDeviceRowCred(t, env.orgID, site2, "res-dev2-"+newUUID()[:8])
	group1 := createGroupRowCred(t, env.orgID, "res-group-"+newUUID()[:8])

	orgCred := env.create(t, "res-org", "snmp_v2c", "SENTINEL-RES-ORG-"+newUUID(), nil)
	siteCred := env.create(t, "res-site", "snmp_v2c", "SENTINEL-RES-SITE-"+newUUID(), nil)
	deviceCred := env.create(t, "res-device", "snmp_v3", "SENTINEL-RES-DEVICE-"+newUUID(), nil)
	groupCred := env.create(t, "res-group-cred", "snmp_v2c", "SENTINEL-RES-GROUP-"+newUUID(), nil)

	resolver := credentials.NewResolver(appPool, env.vault)
	ctx := context.Background()
	orgID := mustUUID(t, env.orgID)

	// Unbound credential cannot be selected.
	if _, err := resolver.ResolveForDevice(ctx, orgID, mustUUID(t, dev1)); !errors.Is(err, credentials.ErrNoCredential) {
		t.Fatalf("unbound device: want ErrNoCredential, got %v", err)
	}

	// Org level resolves (and covers every device).
	env.bind(t, orgCred, "org", env.orgID, 0)
	eff, err := resolver.ResolveForDevice(ctx, orgID, mustUUID(t, dev1))
	must(t, err)
	if eff.CredentialID.String() != orgCred || eff.ScopeType != "org" {
		t.Fatalf("org resolution = %+v", eff)
	}

	// Site level beats org; devices on other sites fall back.
	env.bind(t, siteCred, "site", env.siteID, 0)
	eff, err = resolver.ResolveForDevice(ctx, orgID, mustUUID(t, dev1))
	must(t, err)
	if eff.CredentialID.String() != siteCred || eff.ScopeType != "site" {
		t.Fatalf("site resolution = %+v", eff)
	}
	eff, err = resolver.ResolveForDevice(ctx, orgID, mustUUID(t, dev2))
	must(t, err)
	if eff.CredentialID.String() != orgCred || eff.ScopeType != "org" {
		t.Fatalf("site2 fallback = %+v", eff)
	}

	// Device level beats site regardless of priority.
	env.bind(t, deviceCred, "device", dev1, -100)
	eff, err = resolver.ResolveForDevice(ctx, orgID, mustUUID(t, dev1))
	must(t, err)
	if eff.CredentialID.String() != deviceCred || eff.ScopeType != "device" {
		t.Fatalf("device resolution = %+v", eff)
	}

	// Same-level priority wins; equal priority breaks deterministically to the
	// oldest (lowest) credential id.
	prioritySiteCred := env.create(t, "res-priority", "snmp_v2c", "SENTINEL-RES-PRIO-"+newUUID(), nil)
	env.bind(t, prioritySiteCred, "site", env.siteID, 1)
	eff, err = resolver.ResolveForDevice(ctx, orgID, mustUUID(t, dev1))
	must(t, err)
	if eff.CredentialID.String() != deviceCred {
		t.Fatalf("device tier must still win: %+v", eff)
	}
	// Remove the device binding so the site tier decides.
	res := env.do(t, http.MethodPost, "/v1/credentials/"+deviceCred+"/unbind",
		`{"scope_type":"device","scope_id":"`+dev1+`"}`)
	if res.Status != http.StatusNoContent {
		t.Fatalf("unbind device: %d %v", res.Status, res.Body)
	}
	eff, err = resolver.ResolveForDevice(ctx, orgID, mustUUID(t, dev1))
	must(t, err)
	if eff.CredentialID.String() != prioritySiteCred || eff.Priority != 1 {
		t.Fatalf("priority resolution = %+v", eff)
	}
	// Two same-priority site bindings: the older credential (smaller UUIDv7)
	// wins, deterministically under repetition.
	tieCred := env.create(t, "res-tie", "snmp_v2c", "SENTINEL-RES-TIE-"+newUUID(), nil)
	env.bind(t, tieCred, "site", env.siteID, 1)
	older, newer := prioritySiteCred, tieCred
	if older > newer {
		older, newer = newer, older
	}
	for i := 0; i < 5; i++ {
		eff, err = resolver.ResolveForDevice(ctx, orgID, mustUUID(t, dev1))
		must(t, err)
		if eff.CredentialID.String() != older {
			t.Fatalf("tie-break picked %s, want the older %s (vs %s)", eff.CredentialID, older, newer)
		}
	}

	// Group-tier extension: without membership it is unreachable; with the M9
	// membership hook injected, the group binding resolves.
	env.bind(t, groupCred, "device_group", group1, 1000)
	eff, err = resolver.ResolveForDevice(ctx, orgID, mustUUID(t, dev1))
	must(t, err)
	if eff.CredentialID.String() != prioritySiteCred {
		t.Fatalf("device_group must stay unreachable without membership resolution: %+v", eff)
	}
	groupResolver := credentials.NewResolver(appPool, env.vault, credentials.WithGroupMembership(
		func(_ context.Context, _ pgx.Tx, deviceID uuid.UUID) ([]uuid.UUID, error) {
			if deviceID.String() == dev1 {
				return []uuid.UUID{mustUUID(t, group1)}, nil
			}
			return nil, nil
		}))
	eff, err = groupResolver.ResolveForDevice(ctx, orgID, mustUUID(t, dev1))
	must(t, err)
	if eff.CredentialID.String() != groupCred || eff.ScopeType != "device_group" {
		t.Fatalf("group resolution with membership hook = %+v", eff)
	}

	// Cross-tenant rejection: a second tenant's device is invisible in this
	// tenant (and vice versa).
	other := newCredentialEnv(t, "cred-res-other-"+newUUID()[:8])
	devOther := createDeviceRowCred(t, other.orgID, other.siteID, "res-other-dev-"+newUUID()[:8])
	if _, err := resolver.ResolveForDevice(ctx, orgID, mustUUID(t, devOther)); !errors.Is(err, credentials.ErrDeviceNotFound) {
		t.Fatalf("cross-tenant device: want ErrDeviceNotFound, got %v", err)
	}
	if _, err := credentials.NewResolver(appPool, other.vault).ResolveForDevice(ctx, mustUUID(t, other.orgID), mustUUID(t, dev1)); !errors.Is(err, credentials.ErrDeviceNotFound) {
		t.Fatalf("reverse cross-tenant device: want ErrDeviceNotFound, got %v", err)
	}

	// Materialize decrypts the effective credential's plaintext (internal use
	// only). The priority site credential is the effective one for dev1.
	plaintext, eff, err := resolver.Materialize(ctx, orgID, mustUUID(t, dev1))
	must(t, err)
	if eff.CredentialID.String() != prioritySiteCred {
		t.Fatalf("materialize picked %+v", eff)
	}
	if string(plaintext) == "" || !strings.HasPrefix(string(plaintext), "SENTINEL-RES-") {
		t.Fatalf("materialized plaintext is wrong (len %d)", len(plaintext))
	}
	// A second resolution+materialization is stable; dev2 resolves through the
	// org binding and materializes too.
	plaintext2, _, err := resolver.Materialize(ctx, orgID, mustUUID(t, dev1))
	must(t, err)
	if !bytes.Equal(plaintext, plaintext2) {
		t.Fatal("materialization is not deterministic")
	}
	orgPlain, eff2, err := resolver.Materialize(ctx, orgID, mustUUID(t, dev2))
	must(t, err)
	if eff2.CredentialID.String() != orgCred {
		t.Fatalf("dev2 materialize picked %+v", eff2)
	}
	if !strings.HasPrefix(string(orgPlain), "SENTINEL-RES-ORG-") {
		t.Fatalf("dev2 materialized the wrong secret (len %d)", len(orgPlain))
	}
}

// TestCredentialsRotationEnvelopeVersion proves rotation re-seals under the
// vault's current KEK version: with a key ring advancing to version 2, the
// stored key_version follows, the old ciphertext is unreplaced, and the old
// vault cannot read the new envelope.
func TestCredentialsRotationEnvelopeVersion(t *testing.T) {
	ctx := context.Background()
	env := newCredentialEnv(t, "cred-rotver-"+newUUID()[:8])
	keyPath := env.keyPath

	// Service bound to the version-1 key file.
	kek1, err := secrets.LoadOrCreateLocalKMS(secrets.LocalConfig{Path: keyPath, KeyID: "it-credentials"})
	must(t, err)
	svc1 := credentials.New(appPool, secrets.New(kek1), nil)
	orgID := mustUUID(t, env.orgID)
	created, err := svc1.Create(ctx, orgID, credentials.CreateInput{
		Name: "rotver", Kind: "snmp_v2c", Secret: []byte("SENTINEL-ROTVER-1-" + newUUID()),
	}, credentials.Actor{UserID: mustUUID(t, env.userID)})
	must(t, err)
	oldStored, before := credentialEnvelopeRow(t, created.ID)
	if oldStored.KeyVersion != 1 {
		t.Fatalf("fresh envelope key_version = %d, want 1", oldStored.KeyVersion)
	}

	// Advance the key ring: keep version 1 material, add version 2 as current.
	raw, err := os.ReadFile(keyPath) //nolint:gosec // test fixture path
	must(t, err)
	var ring struct {
		Format         int               `json:"format"`
		KeyID          string            `json:"key_id"`
		CurrentVersion int               `json:"current_version"`
		Keys           map[string][]byte `json:"keys"`
	}
	must(t, json.Unmarshal(raw, &ring))
	newKey := make([]byte, 32)
	_, err = rand.Read(newKey)
	must(t, err)
	ring.Keys["2"] = newKey
	ring.CurrentVersion = 2
	encoded, err := json.MarshalIndent(ring, "", "  ")
	must(t, err)
	must(t, os.WriteFile(keyPath, encoded, 0o600))
	kek2, err := secrets.LoadOrCreateLocalKMS(secrets.LocalConfig{Path: keyPath, KeyID: "it-credentials"})
	must(t, err)
	if kek2.CurrentVersion() != 2 {
		t.Fatalf("key ring current version = %d, want 2", kek2.CurrentVersion())
	}

	svc2 := credentials.New(appPool, secrets.New(kek2), nil)
	newSecret := "SENTINEL-ROTVER-2-" + newUUID()
	if _, err := svc2.Rotate(ctx, orgID, mustUUID(t, created.ID), []byte(newSecret), credentials.Actor{UserID: mustUUID(t, env.userID)}); err != nil {
		t.Fatalf("rotate under version 2: %v", err)
	}
	afterStored, after := credentialEnvelopeRow(t, created.ID)
	if afterStored.KeyVersion != 2 {
		t.Fatalf("rotated envelope key_version = %d, want 2", afterStored.KeyVersion)
	}
	if bytes.Equal(before, after) {
		t.Fatal("rotation did not change the ciphertext")
	}
	if got, err := secrets.New(kek2).Open(afterStored); err != nil || string(got) != newSecret {
		t.Fatalf("version-2 vault opens rotated envelope: %v", err)
	}
	// The old vault (version 1 only) cannot read the re-wrapped envelope.
	if _, err := secrets.New(kek1).Open(afterStored); !errors.Is(err, secrets.ErrUnknownKeyVersion) {
		t.Fatalf("version-1 vault opening a re-wrapped envelope: want ErrUnknownKeyVersion, got %v", err)
	}
}

// TestCredentialsAuditAndLeakScan proves audit coverage without secret
// material, that denied attempts create no success audit, and that neither
// responses, audit payloads, nor captured server logs contain the sentinels.
func TestCredentialsAuditAndLeakScan(t *testing.T) {
	env := newCredentialEnv(t, "cred-audit-"+newUUID()[:8])
	secret1 := "SENTINEL-AUDIT-1-" + newUUID()
	secret2 := "SENTINEL-AUDIT-2-" + newUUID()
	deviceID := createDeviceRowCred(t, env.orgID, env.siteID, "audit-dev-"+newUUID()[:8])

	var bodies []string
	record := func(res apiResponse) {
		bodies = append(bodies, toJSON(t, res.Body))
	}

	res := env.do(t, http.MethodPost, "/v1/credentials", `{"name":"audit-cred","kind":"snmp_v2c","secret":"`+secret1+`"}`)
	record(res)
	if res.Status != http.StatusCreated {
		t.Fatalf("create: %d %v", res.Status, res.Body)
	}
	id, _ := res.Body["id"].(string)
	res = env.do(t, http.MethodPost, "/v1/credentials/"+id+"/rotate", `{"secret":"`+secret2+`"}`)
	record(res)
	if res.Status != http.StatusOK {
		t.Fatalf("rotate: %d %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodPost, "/v1/credentials/"+id+"/bind",
		`{"scope_type":"device","scope_id":"`+deviceID+`","priority":3}`)
	record(res)
	if res.Status != http.StatusCreated {
		t.Fatalf("bind: %d %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodPost, "/v1/credentials/"+id+"/unbind",
		`{"scope_type":"device","scope_id":"`+deviceID+`"}`)
	record(res)
	if res.Status != http.StatusNoContent {
		t.Fatalf("unbind: %d %v", res.Status, res.Body)
	}
	// Duplicate create (conflict) and foreign target (404) must not audit.
	res = env.do(t, http.MethodPost, "/v1/credentials", `{"name":"audit-cred","kind":"snmp_v2c","secret":"`+secret2+`"}`)
	record(res)
	if res.Status != http.StatusConflict {
		t.Fatalf("duplicate create: %d %v", res.Status, res.Body)
	}
	res = env.do(t, http.MethodPost, "/v1/credentials/"+id+"/bind",
		`{"scope_type":"site","scope_id":"`+newUUID()+`"}`)
	record(res)
	if res.Status != http.StatusNotFound {
		t.Fatalf("foreign target: %d %v", res.Status, res.Body)
	}

	// Audit events: one per successful mutation, actor/resource correlated,
	// never carrying secret material (sentinel scan below).
	for _, action := range []string{
		credentials.ActionCredentialCreate, credentials.ActionCredentialRotate,
		credentials.ActionCredentialBind, credentials.ActionCredentialUnbind,
	} {
		events := env.audit.find(action)
		if len(events) != 1 {
			t.Fatalf("audit events for %s = %d, want 1", action, len(events))
		}
		ev := events[0]
		if ev.ActorID.String() != env.userID || ev.OrgID.String() != env.orgID {
			t.Fatalf("audit %s actor/org mismatch: %+v", action, ev)
		}
		if ev.ResourceType != "credential" || ev.ResourceID.String() != id {
			t.Fatalf("audit %s resource mismatch: %+v", action, ev)
		}
	}
	if n := env.audit.count(); n != 4 {
		t.Fatalf("total success audit events = %d, want 4 (denied ops must not audit)", n)
	}
	auditJSON, err := json.Marshal(env.audit.all())
	must(t, err)
	if strings.Contains(string(auditJSON), secret1) || strings.Contains(string(auditJSON), secret2) {
		t.Fatal("audit payload carries secret material")
	}

	// Response bodies carry no secret material or envelope columns.
	for _, body := range bodies {
		requireNoForbiddenFields(t, body, secret1, secret2)
	}

	// Database dump and captured server logs carry no plaintext.
	dump := credentialDump(t)
	for _, secret := range []string{secret1, secret2} {
		if strings.Contains(dump, secret) {
			t.Fatal("plaintext appears in a device_credentials dump")
		}
		if strings.Contains(env.logs.String(), secret) {
			t.Fatal("plaintext appears in captured server logs")
		}
	}
}

// TestCredentialsSchemaNoPlaintextColumn proves the 000009 credential tables
// carry only envelope columns: no secret/plaintext/cleartext column (or any
// column whose name suggests raw credential material) exists on either table.
func TestCredentialsSchemaNoPlaintextColumn(t *testing.T) {
	ctx := context.Background()
	want := map[string]bool{
		"id": true, "org_id": true, "name": true, "kind": true, "data_enc": true,
		"kms_key_id": true, "key_version": true, "encryption_context": true,
		"metadata": true, "rotated_at": true, "created_at": true, "updated_at": true,
	}
	rows, err := ownerPool.Query(ctx, `
		SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name IN ('device_credentials', 'credential_bindings')
		ORDER BY table_name, column_name`)
	must(t, err)
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var table, column string
		must(t, rows.Scan(&table, &column))
		seen[table+"."+column] = true
		if table == "device_credentials" && !want[column] {
			t.Fatalf("unexpected device_credentials column %q (no plaintext column may exist)", column)
		}
		for _, forbidden := range []string{"secret", "plaintext", "cleartext", "password", "passphrase", "community"} {
			if strings.Contains(column, forbidden) {
				t.Fatalf("column %s.%s looks like raw credential material", table, column)
			}
		}
	}
	must(t, rows.Err())
	for column := range want {
		if !seen["device_credentials."+column] {
			t.Fatalf("device_credentials column %q missing", column)
		}
	}
	if !seen["credential_bindings.id"] || !seen["credential_bindings.scope_type"] || !seen["credential_bindings.priority"] {
		t.Fatal("credential_bindings shape changed")
	}
}

// ---------------------------------------------------------------------------
// Security suite additions (S-22..S-25).
// ---------------------------------------------------------------------------

// seedUserWithRoleCred inserts a login user with the given role.
func seedUserWithRoleCred(t *testing.T, env *credentialEnv, role string) (string, string) {
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

// loginAsCred logs in an existing user on a fresh client and returns the
// client plus its CSRF token.
func loginAsCred(t *testing.T, env *credentialEnv, email string) (*http.Client, string) {
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

// TestCredentialsCapabilityEnforcement (security suite S-22): unauthenticated
// requests are 401; a viewer holds none of the credential capabilities
// (including metadata reads) and receives deterministic 403 problem+json on
// every credential endpoint.
func TestCredentialsCapabilityEnforcement(t *testing.T) {
	env := newCredentialEnv(t, "cred-cap-"+newUUID()[:8])
	credID := env.create(t, "cap-cred", "snmp_v2c", "SENTINEL-CAP-"+newUUID(), nil)

	endpoints := []struct{ name, method, path, body string }{
		{"list", http.MethodGet, "/v1/credentials", ""},
		{"create", http.MethodPost, "/v1/credentials", `{"name":"cap-2","kind":"snmp_v2c","secret":"x"}`},
		{"detail", http.MethodGet, "/v1/credentials/" + credID, ""},
		{"rotate", http.MethodPost, "/v1/credentials/" + credID + "/rotate", `{"secret":"x"}`},
		{"bind", http.MethodPost, "/v1/credentials/" + credID + "/bind", `{"scope_type":"org","scope_id":"` + env.orgID + `"}`},
		{"unbind", http.MethodPost, "/v1/credentials/" + credID + "/unbind", `{"scope_type":"org","scope_id":"` + env.orgID + `"}`},
	}

	// Unauthenticated: 401 before CSRF/capability checks (fail closed).
	anon := &http.Client{Timeout: 10 * time.Second}
	for _, tc := range endpoints {
		t.Run("anon_"+tc.name, func(t *testing.T) {
			res := doRequest(t, anon, tc.method, env.srv.URL+tc.path, tc.body, nil)
			requireProblem(t, res, http.StatusUnauthorized, "auth.unauthenticated")
		})
	}

	// Viewer: no credential capability at all.
	_, viewerEmail := seedUserWithRoleCred(t, env, "viewer")
	viewer, viewerCSRF := loginAsCred(t, env, viewerEmail)
	for _, tc := range endpoints {
		t.Run("viewer_"+tc.name, func(t *testing.T) {
			res := doRequest(t, viewer, tc.method, env.srv.URL+tc.path, tc.body, map[string]string{"X-CSRF-Token": viewerCSRF})
			requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
		})
	}
	// The viewer's denied attempts left no state behind.
	res := env.do(t, http.MethodGet, "/v1/credentials", "")
	if res.Status != http.StatusOK || len(dataList(t, res.Body)) != 1 {
		t.Fatalf("credential set changed by denied viewer attempts: %v", res.Body)
	}
}

// TestCredentialsCSRFEnforcement (security suite S-23): capabilities are in
// ADDITION to CSRF; every credential mutation without the double-submit header
// is rejected before any state change.
func TestCredentialsCSRFEnforcement(t *testing.T) {
	env := newCredentialEnv(t, "cred-csrf-"+newUUID()[:8])
	credID := env.create(t, "csrf-cred", "snmp_v2c", "SENTINEL-CSRF-"+newUUID(), nil)
	before := credentialCount(t, env.orgID)

	for _, tc := range []struct{ name, path, body string }{
		{"create", "/v1/credentials", `{"name":"csrf-2","kind":"snmp_v2c","secret":"x"}`},
		{"rotate", "/v1/credentials/" + credID + "/rotate", `{"secret":"x"}`},
		{"bind", "/v1/credentials/" + credID + "/bind", `{"scope_type":"org","scope_id":"` + env.orgID + `"}`},
		{"unbind", "/v1/credentials/" + credID + "/unbind", `{"scope_type":"org","scope_id":"` + env.orgID + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := doRequest(t, env.client, http.MethodPost, env.srv.URL+tc.path, tc.body, nil)
			requireProblem(t, res, http.StatusForbidden, "auth.csrf")
		})
	}
	if after := credentialCount(t, env.orgID); after != before {
		t.Fatalf("credential rows changed by CSRF-rejected requests: %d -> %d", before, after)
	}
	if n := env.audit.count(); n != 1 { // only the successful setup create
		t.Fatalf("audit events after CSRF rejects = %d, want 1", n)
	}
	// With the header the same mutation succeeds (sanity contrast).
	res := env.do(t, http.MethodPost, "/v1/credentials/"+credID+"/bind",
		`{"scope_type":"org","scope_id":"`+env.orgID+`"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("bind with CSRF: %d %v", res.Status, res.Body)
	}
}

// credentialCount counts device_credentials rows visible to the org.
func credentialCount(t *testing.T, orgID string) int {
	t.Helper()
	var n int
	err := database.WithTenant(context.Background(), appPool, mustUUID(t, orgID), func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM device_credentials`).Scan(&n)
	})
	must(t, err)
	return n
}

// TestCredentialsCrossTenantS24 (security suite S-24): cross-tenant
// invisibility of credentials and bindings, including direct DB/RLS probes, and
// enumeration-resistance parity.
func TestCredentialsCrossTenantS24(t *testing.T) {
	ctx := context.Background()
	a := newCredentialEnv(t, "cred-x-a-"+newUUID()[:8])
	b := newCredentialEnv(t, "cred-x-b-"+newUUID()[:8])

	credA := a.create(t, "x-cred-a", "snmp_v2c", "SENTINEL-X-A-"+newUUID(), nil)
	deviceA := createDeviceRowCred(t, a.orgID, a.siteID, "x-dev-a-"+newUUID()[:8])
	a.bind(t, credA, "device", deviceA, 4)

	// B's lists never contain A's rows.
	res := b.do(t, http.MethodGet, "/v1/credentials?limit=100", "")
	if res.Status != http.StatusOK {
		t.Fatalf("B list: %d %v", res.Status, res.Body)
	}
	if payload := toJSON(t, res.Body); strings.Contains(payload, credA) || strings.Contains(payload, "x-cred-a") {
		t.Fatalf("B sees A's credential: %s", payload)
	}

	// Foreign ids on every endpoint are 404 with A's canonical not-found code.
	for _, tc := range []struct{ name, method, path, body string }{
		{"detail", http.MethodGet, "/v1/credentials/" + credA, ""},
		{"rotate", http.MethodPost, "/v1/credentials/" + credA + "/rotate", `{"secret":"x"}`},
		{"bind", http.MethodPost, "/v1/credentials/" + credA + "/bind", `{"scope_type":"org","scope_id":"` + b.orgID + `"}`},
		{"unbind", http.MethodPost, "/v1/credentials/" + credA + "/unbind", `{"scope_type":"device","scope_id":"` + deviceA + `"}`},
	} {
		t.Run("b_on_a_"+tc.name, func(t *testing.T) {
			res := b.do(t, tc.method, tc.path, tc.body)
			requireProblem(t, res, http.StatusNotFound, "credential.not_found")
		})
	}
	// Enumeration parity: A's foreign id and a random id are indistinguishable.
	foreign := b.do(t, http.MethodGet, "/v1/credentials/"+credA, "")
	missing := b.do(t, http.MethodGet, "/v1/credentials/"+newUUID(), "")
	delete(foreign.Body, "request_id")
	delete(missing.Body, "request_id")
	if toJSON(t, foreign.Body) != toJSON(t, missing.Body) {
		t.Fatalf("foreign vs missing credential bodies differ:\n%v\n%v", foreign.Body, missing.Body)
	}

	// Direct DB probes: under B's tenant context the A rows are invisible (and
	// unscoped reads return nothing under default-deny RLS).
	var credRows, bindingRows, unscoped int
	must(t, database.WithTenant(ctx, appPool, mustUUID(t, b.orgID), func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM device_credentials`).Scan(&credRows); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM credential_bindings`).Scan(&bindingRows); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM device_credentials WHERE org_id = $1`, a.orgID).Scan(&unscoped)
	}))
	if credRows != 0 || bindingRows != 0 || unscoped != 0 {
		t.Fatalf("B's context sees A's credential rows: credentials=%d bindings=%d filtered=%d", credRows, bindingRows, unscoped)
	}
	var ownerRows int
	must(t, ownerPool.QueryRow(ctx, `SELECT count(*) FROM device_credentials WHERE id = $1`, credA).Scan(&ownerRows))
	if ownerRows != 1 {
		t.Fatal("A's credential row missing for the owner probe")
	}

	// Foreign-org INSERTs fail RLS WITH CHECK (device_credentials and
	// credential_bindings).
	err := database.WithTenant(ctx, appPool, mustUUID(t, a.orgID), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO device_credentials (id, org_id, name, kind, data_enc, kms_key_id, key_version)
			 VALUES ($1, $2, 'x-intruder', 'snmp_v2c', $3, 'dev-master-key', 1)`,
			newUUID(), b.orgID, []byte("intruder-envelope"))
		return err
	})
	if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
		t.Fatalf("foreign credential insert: want SQLSTATE %s, got %q (%v)", sqlstateInsufficientPrivilege, got, err)
	}
	err = database.WithTenant(ctx, appPool, mustUUID(t, a.orgID), func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO credential_bindings (id, org_id, credential_id, scope_type, scope_id)
			 VALUES ($1, $2, $3, 'device', $4)`,
			newUUID(), b.orgID, credA, deviceA)
		return err
	})
	if got := pgErrCode(err); got != sqlstateInsufficientPrivilege {
		t.Fatalf("cross-tenant binding insert: want SQLSTATE %s, got %q (%v)", sqlstateInsufficientPrivilege, got, err)
	}

	// B's foreign probes left A's data untouched.
	res = a.do(t, http.MethodGet, "/v1/credentials/"+credA, "")
	if res.Status != http.StatusOK || res.Body["name"] != "x-cred-a" {
		t.Fatalf("A's credential changed by B: %d %v", res.Status, res.Body)
	}
	if len(res.Body["bindings"].([]any)) != 1 {
		t.Fatalf("A's bindings changed by B: %v", res.Body["bindings"])
	}
}

// TestCredentialsScopeRestriction (security suite S-25): a scope-restricted
// admin cannot use the org-level credential surface; the denial is
// deterministic 403 problem+json and leaves no state behind.
func TestCredentialsScopeRestriction(t *testing.T) {
	env := newCredentialEnv(t, "cred-scope-"+newUUID()[:8])
	// Seed one credential so the surface is non-empty.
	env.create(t, "scope-cred", "snmp_v2c", "SENTINEL-SCOPE-"+newUUID(), nil)

	adminID, adminEmail := seedUserWithRoleCred(t, env, "admin")
	bindScope(t, env.orgID, adminID, "site", env.siteID)
	admin, adminCSRF := loginAsCred(t, env, adminEmail)
	headers := map[string]string{"X-CSRF-Token": adminCSRF}

	// Reads and writes are both org-level credential operations: denied.
	for _, tc := range []struct{ name, method, path, body string }{
		{"list", http.MethodGet, "/v1/credentials", ""},
		{"create", http.MethodPost, "/v1/credentials", `{"name":"scope-2","kind":"snmp_v2c","secret":"x"}`},
	} {
		t.Run("site_bound_"+tc.name, func(t *testing.T) {
			res := doRequest(t, admin, tc.method, env.srv.URL+tc.path, tc.body, headers)
			requireProblem(t, res, http.StatusForbidden, "auth.forbidden")
		})
	}
	if n := credentialCount(t, env.orgID); n != 1 {
		t.Fatalf("denied scope-restricted create left rows behind: %d", n)
	}

	// An unrestricted admin succeeds on the same surface (contrast).
	res := env.do(t, http.MethodGet, "/v1/credentials", "")
	if res.Status != http.StatusOK {
		t.Fatalf("unrestricted admin list: %d %v", res.Status, res.Body)
	}
}

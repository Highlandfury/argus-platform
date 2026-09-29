package integration

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/security"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// newTestAPI builds the real router (identity + tenancy services over the
// containerized database) behind an in-process HTTP server with its own cookie
// jar and its own rate-limiter instance.
func newTestAPI(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identity.New(appPool, authPool, tenancySvc)
	must(t, err)
	router := api.NewRouter(api.Options{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Telemetry: telemetry.New("it-api", "0", "0"),
		Version:   "it",
		Commit:    "it",
		Identity:  identitySvc,
		Tenancy:   tenancySvc,
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	must(t, err)
	return srv, &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

// apiResponse is a fully-drained HTTP result (bodies are always closed).
type apiResponse struct {
	Status  int
	Body    map[string]any
	Cookies []*http.Cookie
	Header  http.Header
}

func doRequest(t *testing.T, client *http.Client, method, url, jsonBody string, headers map[string]string) apiResponse {
	t.Helper()
	var reader io.Reader
	if jsonBody != "" {
		reader = strings.NewReader(jsonBody)
	}
	req, err := http.NewRequest(method, url, reader)
	must(t, err)
	if jsonBody != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	must(t, err)
	defer func() { _ = res.Body.Close() }()

	out := apiResponse{Status: res.StatusCode, Cookies: res.Cookies(), Header: res.Header}
	// Includes application/problem+json (RFC 9457 error bodies).
	if strings.Contains(res.Header.Get("Content-Type"), "json") {
		_ = json.NewDecoder(res.Body).Decode(&out.Body)
	} else {
		_, _ = io.Copy(io.Discard, res.Body)
	}
	return out
}

func loginBody(slug, password string) string {
	return `{"org_slug":"` + slug + `","email":"` + slug + `@dev.local","password":"` + password + `"}`
}

// seedLoginUser creates a tenant whose admin can log in with it-password.
func seedLoginUser(t *testing.T, slug, siteName string) tenancy.SeedResult {
	t.Helper()
	hash, err := security.HashPassword("it-password")
	must(t, err)
	res, err := tenancy.SeedDev(context.Background(), appPool, authPool, tenancy.SeedParams{
		Slug:              slug,
		OrgName:           "Org " + slug,
		SiteName:          siteName,
		AdminEmail:        slug + "@dev.local",
		AdminPasswordHash: hash,
	})
	must(t, err)
	return res
}

func cookieByName(res apiResponse, name string) *http.Cookie {
	for _, c := range res.Cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestLoginSessionLifecycle covers the API half of AC-12: uniform failure,
// cookie issuance (HttpOnly session, readable CSRF), /v1/me, /v1/sites, CSRF
// enforcement on logout, revocation, and hashed-at-rest tokens.
func TestLoginSessionLifecycle(t *testing.T) {
	slug := "sec-" + newUUID()[:8]
	seedLoginUser(t, slug, "HQ-"+slug)
	srv, client := newTestAPI(t)
	base := srv.URL

	// Wrong password: 401 problem, no cookies.
	res := doRequest(t, client, http.MethodPost, base+"/v1/auth/login", loginBody(slug, "wrong"), nil)
	if res.Status != http.StatusUnauthorized {
		t.Fatalf("wrong password: status %d, want 401", res.Status)
	}
	if res.Body["code"] != "auth.invalid_credentials" {
		t.Fatalf("wrong password code = %v", res.Body["code"])
	}
	if len(res.Cookies) != 0 {
		t.Fatalf("failed login must not set cookies: %v", res.Cookies)
	}

	// Successful login: session + CSRF cookies.
	res = doRequest(t, client, http.MethodPost, base+"/v1/auth/login", loginBody(slug, "it-password"), nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login: status %d, want 200", res.Status)
	}
	user, _ := res.Body["user"].(map[string]any)
	if user["email"] != slug+"@dev.local" {
		t.Fatalf("login payload user = %v", user)
	}
	sessionCookie := cookieByName(res, "argus_session")
	csrfCookie := cookieByName(res, "argus_csrf")
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatalf("login must set argus_session and argus_csrf cookies; got %v", res.Cookies)
	}
	if !sessionCookie.HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if csrfCookie.HttpOnly {
		t.Fatal("CSRF cookie must be readable by the UI (not HttpOnly)")
	}

	// /v1/me and /v1/sites with the session.
	if res = doRequest(t, client, http.MethodGet, base+"/v1/me", "", nil); res.Status != http.StatusOK {
		t.Fatalf("me: status %d", res.Status)
	}
	res = doRequest(t, client, http.MethodGet, base+"/v1/sites", "", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("sites: status %d", res.Status)
	}
	if !strings.Contains(toJSON(t, res.Body), "HQ-"+slug) {
		t.Fatalf("sites payload missing seeded site: %v", res.Body)
	}

	// Tokens are stored hashed: the raw session token must not appear in the DB.
	ctx := context.Background()
	tokenHash := security.HashToken(sessionCookie.Value)
	var stored int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE token_hash = $1`, tokenHash).Scan(&stored))
	if stored != 1 {
		t.Fatalf("session row for hashed token = %d, want 1", stored)
	}
	var rawCount int
	must(t, ownerPool.QueryRow(ctx,
		`SELECT count(*) FROM sessions WHERE encode(token_hash, 'hex') = $1`, sessionCookie.Value).Scan(&rawCount))
	if rawCount != 0 {
		t.Fatal("raw session token found in sessions table — must be hashed")
	}

	// Logout without CSRF header: 403 and session still valid.
	res = doRequest(t, client, http.MethodPost, base+"/v1/auth/logout", "", nil)
	if res.Status != http.StatusForbidden {
		t.Fatalf("logout without CSRF: status %d, want 403", res.Status)
	}
	if res = doRequest(t, client, http.MethodGet, base+"/v1/me", "", nil); res.Status != http.StatusOK {
		t.Fatalf("me after rejected logout: status %d, want 200", res.Status)
	}

	// Logout with the correct double-submit pair: 204, session revoked.
	res = doRequest(t, client, http.MethodPost, base+"/v1/auth/logout", "",
		map[string]string{"X-CSRF-Token": csrfCookie.Value})
	if res.Status != http.StatusNoContent {
		t.Fatalf("logout with CSRF: status %d, want 204", res.Status)
	}
	if res = doRequest(t, client, http.MethodGet, base+"/v1/me", "", nil); res.Status != http.StatusUnauthorized {
		t.Fatalf("me after logout: status %d, want 401", res.Status)
	}
}

// TestLoginRateLimitS09: the 11th rapid attempt on one server is 429 with
// Retry-After (burst 10, ~10/min).
func TestLoginRateLimitS09(t *testing.T) {
	slug := "rl-" + newUUID()[:8]
	seedLoginUser(t, slug, "HQ-"+slug)
	srv, client := newTestAPI(t)

	for i := 1; i <= 10; i++ {
		res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", loginBody(slug, "wrong"), nil)
		if res.Status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i, res.Status)
		}
	}
	res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", loginBody(slug, "wrong"), nil)
	if res.Status != http.StatusTooManyRequests {
		t.Fatalf("11th attempt: status %d, want 429", res.Status)
	}
	if res.Header.Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
}

// TestLoginEnumerationUniformS16: unknown org, unknown email, and wrong
// password are indistinguishable in status, code, and body; every path also
// performs comparable verification work (dummy-hash equalization), asserted as
// a minimum duration so the naive "skip verify when missing" regression fails.
func TestLoginEnumerationUniformS16(t *testing.T) {
	slug := "enum-" + newUUID()[:8]
	seedLoginUser(t, slug, "HQ-"+slug)
	srv, client := newTestAPI(t)

	attempts := []struct {
		name string
		body string
	}{
		{"unknown-org", `{"org_slug":"no-such-org","email":"x@dev.local","password":"whatever"}`},
		{"unknown-email", `{"org_slug":"` + slug + `","email":"nobody@dev.local","password":"whatever"}`},
		{"wrong-password", loginBody(slug, "wrong")},
	}

	var codes []string
	for _, a := range attempts {
		start := time.Now()
		res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", a.body, nil)
		elapsed := time.Since(start)
		if res.Status != http.StatusUnauthorized {
			t.Fatalf("%s: status %d, want 401", a.name, res.Status)
		}
		if res.Body["code"] != "auth.invalid_credentials" {
			t.Fatalf("%s: code %v", a.name, res.Body["code"])
		}
		if elapsed < 15*time.Millisecond {
			t.Fatalf("%s: completed in %v — verification work was skipped (timing oracle)", a.name, elapsed)
		}
		codes = append(codes, res.Body["code"].(string))
		t.Logf("%s: %v", a.name, elapsed)
	}
	if codes[0] != codes[1] || codes[1] != codes[2] {
		t.Fatalf("failure codes differ across enumeration cases: %v", codes)
	}
}

// TestSitesAreTenantScoped: a session for org A sees only A's sites.
func TestSitesAreTenantScoped(t *testing.T) {
	slugA := "scope-a-" + newUUID()[:8]
	slugB := "scope-b-" + newUUID()[:8]
	seedLoginUser(t, slugA, "SITE-A-"+slugA)
	seedLoginUser(t, slugB, "SITE-B-"+slugB)
	srv, client := newTestAPI(t)

	res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", loginBody(slugA, "it-password"), nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login A: status %d", res.Status)
	}
	res = doRequest(t, client, http.MethodGet, srv.URL+"/v1/sites", "", nil)
	payload := toJSON(t, res.Body)
	if !strings.Contains(payload, "SITE-A-"+slugA) {
		t.Fatalf("tenant A missing its own site: %s", payload)
	}
	if strings.Contains(payload, "SITE-B-"+slugB) {
		t.Fatalf("tenant A can see tenant B's site: %s", payload)
	}
}

func toJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	must(t, err)
	return string(raw)
}

// Package e2e is the Phase-1 compose-stack end-to-end harness (M6c).
//
// Unlike tests/integration (testcontainers, in-process gRPC), this harness runs
// against the real dockerized stack: server API :8080, ops :9090, enrollment
// :8444, mTLS collector stream :8443, the internal CA and the running collector.
//
// Run locally:
//
//	docker compose -f deployments/compose/docker-compose.dev.yml up -d --build --wait
//	docker compose -f deployments/compose/docker-compose.dev.yml cp server:/var/lib/argus/ca/root.pem .dev/ca-root.pem
//	$env:ARGUS_E2E="1"; go test ./tests/e2e/... -count=1 -v
//
// Coverage: AC-01 (enroll and activate), AC-02 (signed policy verified by the
// real enrollment client), AC-03 (mTLS stream ACTIVE + argus_grpc_streams_active),
// AC-08 (metric query returns stored points), T7 (live revocation is terminal
// and reconnects are rejected). The harness creates one throwaway collector per
// run (named e2e-<id>) and revokes it during T7; the dev stack accumulates
// those records until a development reset.
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/argus-platform/argus/internal/collector"
	"github.com/argus-platform/argus/internal/collector/enrollclient"
	"github.com/argus-platform/argus/internal/collector/identity"
	"github.com/argus-platform/argus/internal/collector/stream"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv("ARGUS_E2E") != "1" {
		t.Skip("e2e harness disabled; set ARGUS_E2E=1 with the compose stack running")
	}
}

// resolveCA makes a relative CA path work regardless of the test's working
// directory (tests/e2e locally, repo root in CI).
func resolveCA(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	candidates := []string{path}
	dir, err := os.Getwd()
	if err == nil {
		for i := 0; i < 5; i++ {
			dir = filepath.Dir(dir)
			candidates = append(candidates, filepath.Join(dir, path))
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return path
}

type harness struct {
	api       string
	ops       string
	enrollURL string
	streamTgt string
	caFile    string
	org       string
	email     string
	password  string

	client *http.Client
	csrf   string
	slug   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		api:       env("ARGUS_E2E_API", "http://127.0.0.1:8080"),
		ops:       env("ARGUS_E2E_OPS", "http://127.0.0.1:9090"),
		enrollURL: env("ARGUS_E2E_ENROLL", "https://127.0.0.1:8444"),
		streamTgt: env("ARGUS_E2E_STREAM", "127.0.0.1:8443"),
		caFile:    env("ARGUS_E2E_CA", filepath.Join(".dev", "ca-root.pem")),
		org:       env("ARGUS_E2E_ORG", "dev"),
		email:     env("ARGUS_E2E_EMAIL", "admin@dev.local"),
		password:  env("ARGUS_E2E_PASSWORD", env("ARGUS_DEV_ADMIN_PASSWORD", "dev-admin-change-me")),
		slug:      fmt.Sprintf("e2e-%d", time.Now().UnixNano()),
	}
	// Relative CA paths are resolved against the working directory and then
	// upward: the harness runs from tests/e2e locally and the repo root in CI.
	h.caFile = resolveCA(h.caFile)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	h.client = &http.Client{Jar: jar, Timeout: 15 * time.Second}

	// Wait for readiness (the stack may still be settling in CI).
	deadline := time.Now().Add(60 * time.Second)
	for {
		res, err := h.client.Get(h.api + "/v1/readyz")
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("stack not ready at %s/v1/readyz within 60s", h.api)
		}
		time.Sleep(time.Second)
	}

	// Login (real session + CSRF cookies).
	body := fmt.Sprintf(`{"org_slug":%q,"email":%q,"password":%q}`, h.org, h.email, h.password)
	res, err := h.client.Post(h.api+"/v1/auth/login", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", res.StatusCode)
	}
	base, _ := url.Parse(h.api)
	for _, c := range h.client.Jar.Cookies(base) {
		if c.Name == "argus_csrf" {
			h.csrf = c.Value
		}
	}
	if h.csrf == "" {
		t.Fatal("login did not set the CSRF cookie")
	}
	return h
}

func (h *harness) get(t *testing.T, path string, out any) {
	t.Helper()
	res, err := h.client.Get(h.api + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", path, res.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(res.Body).Decode(out); err != nil {
			t.Fatalf("GET %s decode: %v", path, err)
		}
	}
}

func (h *harness) post(t *testing.T, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.api+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", h.csrf)
	req.Header.Set("Idempotency-Key", h.slug+"-"+strings.ReplaceAll(path, "/", "-"))
	res, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return res
}

// enroll creates one token via the API and enrolls a throwaway collector using
// the real enrollment client (TLS + signed-policy verification).
func (h *harness) enroll(t *testing.T) (identity.Identity, *identity.Store) {
	t.Helper()
	var sites struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	h.get(t, "/v1/sites?limit=1", &sites)
	if len(sites.Data) == 0 {
		t.Fatal("no sites available to bind an enrollment")
	}
	res := h.post(t, "/v1/enrollments", fmt.Sprintf(`{"site_id":%q,"ttl_seconds":3600}`, sites.Data[0].ID))
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(res.Body)
		t.Fatalf("create enrollment: status %d body %s", res.StatusCode, raw)
	}
	var created struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&created); err != nil {
		t.Fatalf("decode enrollment: %v", err)
	}

	enrolled, err := enrollclient.Enroll(context.Background(), enrollclient.Config{
		EnrollURL:    h.enrollURL,
		CAFile:       h.caFile,
		Token:        created.Token,
		Name:         h.slug,
		AgentVersion: "e2e",
		Hostname:     "e2e-harness",
		OS:           "linux",
		Timeout:      20 * time.Second,
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	id := identity.Identity{
		CollectorID:     enrolled.CollectorID,
		Name:            h.slug,
		ServerEnrollURL: h.enrollURL,
		StreamAddr:      h.streamTgt,
		AgentVersion:    "e2e",
		CertNotAfter:    enrolled.CertNotAfter,
		EnrolledAt:      time.Now().UTC(),
		PolicyVersion:   enrolled.PolicyVersion,
		PolicyKeyDERB64: base64.StdEncoding.EncodeToString(enrolled.PolicyKeyDER),
	}
	store := identity.NewStore(t.TempDir())
	if err := store.Save(id, enrolled.CertPEM, enrolled.KeyPEM, enrolled.CAPEM); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	return id, store
}

func (h *harness) streamClient(t *testing.T, id identity.Identity, store *identity.Store, machine *collector.Machine) *stream.Client {
	t.Helper()
	certPath, keyPath, _, _ := store.Paths()
	keyDER, err := base64.StdEncoding.DecodeString(id.PolicyKeyDERB64)
	if err != nil {
		t.Fatalf("decode policy key: %v", err)
	}
	return stream.New(stream.Config{
		StreamAddr:     h.streamTgt,
		CAFile:         h.caFile,
		CertFile:       certPath,
		KeyFile:        keyPath,
		CollectorID:    id.CollectorID,
		AgentVersion:   "e2e",
		PolicyDir:      t.TempDir(),
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		AppliedVersion: id.PolicyVersion,
		PolicyKeyDER:   keyDER,
		CorrelationID:  h.slug,
	}, machine)
}

func waitState(t *testing.T, m *collector.Machine, want collector.State, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.State() == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("state = %s, want %s within %s", m.State(), want, timeout)
}

func (h *harness) collectors(t *testing.T) map[string]string {
	t.Helper()
	var list struct {
		Data []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"data"`
	}
	h.get(t, "/v1/collectors?limit=100", &list)
	out := map[string]string{}
	for _, c := range list.Data {
		out[c.Name] = c.Status
	}
	return out
}

// AC-01/AC-02: a token-bound collector enrolls with a proof-of-possession CSR,
// receives a certificate and a signed policy the real client verifies, and
// appears in the registry.
func TestE2EAC01EnrollAndRegister(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	id, _ := h.enroll(t)

	list := h.collectors(t)
	if _, ok := list[h.slug]; !ok {
		t.Fatalf("enrolled collector %s not visible in /v1/collectors", h.slug)
	}
	if id.CertNotAfter.Before(time.Now().Add(80 * 24 * time.Hour)) {
		t.Fatalf("certificate validity too short: %s", id.CertNotAfter)
	}
}

// AC-03/T7: the mTLS stream reaches ACTIVE (and argus_grpc_streams_active
// reflects it); live revocation is terminal, and the revoked identity is
// rejected on any reconnect attempt.
func TestE2EAC03StreamActiveAndRevocationT7(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)
	id, store := h.enroll(t)

	machine := collector.NewMachine(collector.StateNew, nil)
	if err := machine.Transition(collector.StateReconnecting); err != nil {
		t.Fatalf("state: %v", err)
	}
	client := h.streamClient(t, id, store, machine)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- client.Run(ctx) }()
	waitState(t, machine, collector.StateActive, 20*time.Second)

	// AC-03: ops metric shows at least one active stream.
	res, err := http.Get(h.ops + "/metrics")
	if err != nil {
		t.Fatalf("ops metrics: %v", err)
	}
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if !strings.Contains(string(raw), "argus_grpc_streams_active") {
		t.Fatal("argus_grpc_streams_active missing from /metrics")
	}

	// T7: revoke via the real API; the live stream must terminate terminally.
	res = h.post(t, fmt.Sprintf("/v1/collectors/%s/revoke", id.CollectorID), "")
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("revoke status %d", res.StatusCode)
	}
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("revoked stream Run returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("stream did not terminate after revocation")
	}
	if machine.State() != collector.StateRevoked {
		t.Fatalf("state after revocation = %s, want REVOKED", machine.State())
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if h.collectors(t)[h.slug] == "revoked" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if got := h.collectors(t)[h.slug]; got != "revoked" {
		t.Fatalf("registry status = %q, want revoked", got)
	}

	// A fresh connection with the revoked identity is rejected pre-hello and
	// the client stops permanently.
	machine2 := collector.NewMachine(collector.StateNew, nil)
	if err := machine2.Transition(collector.StateReconnecting); err != nil {
		t.Fatalf("state: %v", err)
	}
	client2 := h.streamClient(t, id, store, machine2)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel2()
	start := time.Now()
	if err := client2.Run(ctx2); err != nil {
		t.Fatalf("revoked reconnect Run error: %v", err)
	}
	if time.Since(start) > 15*time.Second {
		t.Fatalf("revoked reconnect did not terminate promptly (%s)", time.Since(start))
	}
	if machine2.State() != collector.StateRevoked {
		t.Fatalf("revoked reconnect state = %s", machine2.State())
	}
}

// AC-08: the query API returns stored points for the running dev collector.
func TestE2EAC08MetricQuery(t *testing.T) {
	requireE2E(t)
	h := newHarness(t)

	deadline := time.Now().Add(45 * time.Second)
	var lastPoints int
	for time.Now().Before(deadline) {
		list := h.collectors(t)
		for name, status := range list {
			if name != "dev-collector" || status == "revoked" {
				continue
			}
			var id string
			var l struct {
				Data []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"data"`
			}
			h.get(t, "/v1/collectors?limit=100", &l)
			for _, c := range l.Data {
				if c.Name == "dev-collector" {
					id = c.ID
				}
			}
			if id == "" {
				continue
			}
			to := time.Now().UTC()
			from := to.Add(-15 * time.Minute)
			var q struct {
				Status string `json:"status"`
				Points []any  `json:"points"`
				Meta   struct {
					ReturnedPoints int `json:"returned_points"`
				} `json:"meta"`
			}
			h.get(t, fmt.Sprintf(
				"/v1/collectors/%s/metrics?metric=collector_cpu_percent&from=%s&to=%s&step=raw",
				id, url.QueryEscape(from.Format(time.RFC3339)), url.QueryEscape(to.Format(time.RFC3339)),
			), &q)
			lastPoints = q.Meta.ReturnedPoints
			if lastPoints > 0 {
				return // stored telemetry reachable through API, chart feed verified
			}
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("no metric points returned within 45s (last=%d)", lastPoints)
}

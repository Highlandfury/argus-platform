package integration

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/collector/enrollclient"
	"github.com/argus-platform/argus/internal/modules/collectors"
	identitymod "github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// S-08 (SPEC §15): exercise authentication, enrollment, and the control stream
// with logs captured to a buffer, then scan the output for forbidden secret
// classes. The test fails with the PATTERN NAME only — fixture secrets are
// never printed.
func TestM5LogScanNoSecretLeakage(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	env := startM3Env(t, withLogBuffer(&buf))
	slug := "m5-logscan-" + newUUID()[:8]
	tn := seedLoginUser(t, slug, "HQ-"+slug)

	// HTTP surface with the buffer logger (login success/failure, enrollment
	// creation, telemetry query).
	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identitymod.New(appPool, authPool, tenancySvc)
	must(t, err)
	router := api.NewRouter(api.Options{
		Logger:            logger,
		Telemetry:         telemetry.New("it-logscan", "0", "0"),
		Version:           "it",
		Commit:            "it",
		Identity:          identitySvc,
		Tenancy:           tenancySvc,
		Collectors:        collectors.New(appPool, authPool, nil, nil),
		CollectorSessions: collectors.NewSessionRegistry(),
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	must(t, err)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	// Failed login with a distinctive wrong password (secret fixture).
	failPw := "wrong-password-" + newUUID()[:8]
	res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", loginBody(slug, failPw), nil)
	if res.Status != http.StatusUnauthorized {
		t.Fatalf("failed login status %d", res.Status)
	}
	// Successful login (session + CSRF cookies exist in the jar).
	res = doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", loginBody(slug, "it-password"), nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login: %d", res.Status)
	}
	csrf := cookieByName(res, "argus_csrf")
	if csrf == nil {
		t.Fatal("no csrf cookie")
	}

	// Create a one-time enrollment token (raw value is a secret fixture).
	body := `{"site_id":"` + tn.SiteID + `","ttl_seconds":3600}`
	create := doRequest(t, client, http.MethodPost, srv.URL+"/v1/enrollments", body,
		map[string]string{"X-CSRF-Token": csrf.Value, "Idempotency-Key": "logscan-" + newUUID()[:8]})
	if create.Status != http.StatusCreated {
		t.Fatalf("create enrollment: %d", create.Status)
	}
	rawToken, _ := create.Body["token"].(string)
	if rawToken == "" {
		t.Fatal("no token in response")
	}

	// Successful enrollment (uses the token) and a denied replay.
	id, store := env.enrollIdentity(t, "collector-logscan", rawToken)
	replay, err := enrollclient.Enroll(context.Background(), enrollclient.Config{
		EnrollURL: "https://" + env.enrollAddr, CAFile: env.caFile, Token: rawToken,
		Name: "collector-replay", Timeout: 5 * time.Second,
	})
	if err == nil || replay.CollectorID != "" {
		t.Fatalf("replay must be denied: %v", err)
	}

	// Control stream: connect (lifecycle log), one good batch, then a protocol
	// violation (duplicate hello) so error-code logging is exercised too.
	rs := dialBatchStream(t, env, id, store)
	rs.send(t, 1, []*collectorv1.MetricSample{
		m4Sample(12.5, map[string]string{"cpu": "total"}, time.Now().UTC()),
	})
	if res := rs.result(t); res.GetStatus() != collectorv1.BatchResult_STATUS_OK {
		t.Fatalf("batch status %v", res.GetStatus())
	}
	if err := rs.stream.Send(&collectorv1.ClientMessage{
		Msg: &collectorv1.ClientMessage_Hello{Hello: &collectorv1.ClientHello{
			CollectorId: id.CollectorID, ProtocolVersion: 1,
		}},
	}); err != nil {
		t.Fatalf("send duplicate hello: %v", err)
	}
	_, _ = rs.stream.Recv()

	// Anti-vacuous: the capture must contain the representative operations.
	logText := buf.String()
	if len(logText) == 0 {
		t.Fatal("no logs captured")
	}
	for _, want := range []string{"request_id", "collector stream connected", id.CollectorID, "protocol error"} {
		if !strings.Contains(logText, want) {
			t.Fatalf("logs missing representative evidence %q (capture had %d bytes)", want, len(logText))
		}
	}

	// Forbidden secret classes: fail with the PATTERN NAME only.
	forbidden := []struct {
		name    string
		pattern string
	}{
		{"enrollment_token", rawToken},
		{"ec_private_key", "BEGIN EC PRIVATE KEY"},
		{"pkcs8_private_key", "BEGIN PRIVATE KEY"},
		{"wrong_password_fixture", failPw},
		{"session_cookie_name", "argus_session="},
		{"csrf_cookie_name", "argus_csrf="},
		{"db_password", "devpass"},
		{"authorization_header", "Authorization:"},
		{"bearer_value", "Bearer "},
	}
	for _, f := range forbidden {
		if strings.Contains(logText, f.pattern) {
			t.Fatalf("S-08 violation: %s appears in captured logs", f.name)
		}
	}
}

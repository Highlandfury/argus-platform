package integration

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// M5 operational failure test: readiness answers a different question than
// liveness. With the database unreachable, the operator must see
// healthz 200 (process alive) and readyz 503 (not operational), with the
// failing dependency named in the response.
func TestM5OperationalReadinessFailure(t *testing.T) {
	ctx := context.Background()
	badPool, err := pgxpool.New(ctx, "postgres://nobody:nopass@127.0.0.1:1/argus?sslmode=disable&connect_timeout=1")
	must(t, err)
	t.Cleanup(badPool.Close)

	router := api.NewOpsRouter(api.Options{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Telemetry: telemetry.New("it-ops", "0", "0"),
		Version:   "it",
		Commit:    "it",
		Readiness: []api.Check{{
			Name: "database",
			Fn: func(ctx context.Context) error {
				return database.CheckSchema(ctx, badPool)
			},
		}},
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	res, err := http.Get(srv.URL + "/healthz")
	must(t, err)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("healthz with dead DB = %d, want 200 (process liveness)", res.StatusCode)
	}

	res, err = http.Get(srv.URL + "/readyz")
	must(t, err)
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz with dead DB = %d, want 503", res.StatusCode)
	}
	if !strings.Contains(string(body), "database") {
		t.Fatalf("readyz must name the failing dependency: %s", body)
	}
}

// M5 operational failure test: a collector whose heartbeat is older than
// 3x the policy interval is reported STALE through the API — the operator
// never sees an idle collector as healthy merely because rows exist.
func TestM5OperationalStaleCollectorView(t *testing.T) {
	ctx := context.Background()
	_, id, _, _ := m4Env(t, "m5-ops-stale-"+newUUID()[:8])

	_, err := ownerPool.Exec(ctx,
		`UPDATE collectors SET status='active', last_heartbeat_at = now() - interval '5 minutes' WHERE id=$1`,
		id.CollectorID)
	must(t, err)

	srv, client := newTestAPIWithMetrics(t)
	// The tenant admin login seeded by m4Env: slug == collector name minus the
	// "collector-" prefix.
	name := ""
	must(t, ownerPool.QueryRow(ctx, `SELECT name FROM collectors WHERE id=$1`, id.CollectorID).Scan(&name))
	tenantSlug := strings.TrimPrefix(name, "collector-")
	res := doRequest(t, client, http.MethodPost, srv.URL+"/v1/auth/login", loginBody(tenantSlug, "it-password"), nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login: %d %v", res.Status, res.Body)
	}

	find := func() string {
		list := doRequest(t, client, http.MethodGet, srv.URL+"/v1/collectors?limit=100", "", nil)
		if list.Status != http.StatusOK {
			t.Fatalf("list: %d", list.Status)
		}
		data, _ := list.Body["data"].([]any)
		for _, item := range data {
			m, _ := item.(map[string]any)
			if m["id"] == id.CollectorID {
				s, _ := m["status"].(string)
				return s
			}
		}
		t.Fatalf("collector %s not in list", id.CollectorID)
		return ""
	}
	if got := find(); got != "stale" {
		t.Fatalf("aged collector status = %q, want stale", got)
	}

	_, err = ownerPool.Exec(ctx, `UPDATE collectors SET last_heartbeat_at = now() WHERE id=$1`, id.CollectorID)
	must(t, err)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if find() == "active" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("fresh-heartbeat collector did not return to active")
}

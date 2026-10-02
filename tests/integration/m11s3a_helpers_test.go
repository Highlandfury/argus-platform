package integration

// Shared fixture for the M11-S3a suppression + SSE suites: the full M11-S2
// stack (alerts service/evaluator, notify engine, scripted transports) plus
// the M11-S3a StreamHub wired into both sinks and the API router.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/modules/alerts"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/notify"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// m11s3aEnv is one logged-in tenant with alerts + notify + the SSE hub.
type m11s3aEnv struct {
	*m11s2Env
	hub *alerts.StreamHub
}

func newM11S3aEnv(t *testing.T, slug string) *m11s3aEnv {
	t.Helper()
	seed := seedLoginUser(t, slug, "HQ-"+slug)

	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	clock := &m11Clock{now: time.Now().UTC().Truncate(time.Second)}
	svc := alerts.New(appPool, authz.New(appPool))
	svc.Now = clock.Now
	eval := alerts.NewEvaluator(appPool, alerts.EvaluatorOptions{Now: clock.Now, Logger: logger})
	vault := testNotifyVault(t)
	notifySvc := notify.New(appPool, vault)
	notifySvc.SetAuthorizer(authz.New(appPool))
	notifySvc.Now = clock.Now
	engine := notify.NewEngine(appPool, vault, notify.EngineOptions{
		Now: clock.Now, Logger: logger, BaseURL: "https://argus.example", Auth: authPool,
	})
	recorder := &recordingSink{engine: engine}
	hub := alerts.NewStreamHub(alerts.StreamOptions{Now: clock.Now, Logger: logger})
	svc.SetSink(recorder)
	svc.AddSink(hub)
	eval.SetSink(recorder)
	eval.AddSink(hub)

	tenancySvc := tenancy.New(appPool, authPool)
	identitySvc, err := identity.New(appPool, authPool, tenancySvc)
	must(t, err)
	router := api.NewRouter(api.Options{
		Logger:       logger,
		Telemetry:    telemetry.New("it-m11s3a", "0", "0"),
		Version:      "it",
		Commit:       "it",
		Identity:     identitySvc,
		Tenancy:      tenancySvc,
		Alerts:       svc,
		AlertsStream: hub,
		Notify:       notifySvc,
		NotifyEngine: engine,
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
	base := &m11Env{
		srv: srv, client: client, slug: slug,
		orgID: seed.OrgID, siteID: seed.SiteID, userID: seed.UserID, csrf: csrf.Value,
		svc: svc, eval: eval, clock: clock,
	}
	return &m11s3aEnv{
		m11s2Env: &m11s2Env{
			m11Env: base, notifySvc: notifySvc, engine: engine, vault: vault,
			recorder: recorder, logs: logs,
		},
		hub: hub,
	}
}

// createWindow creates a maintenance window through the API and returns its id.
func (e *m11s3aEnv) createWindow(t *testing.T, name, scope string, startsAt, endsAt time.Time) string {
	t.Helper()
	body := map[string]any{
		"name":      name,
		"scope":     m11Raw(t, scope),
		"starts_at": startsAt.UTC().Format(time.RFC3339),
		"ends_at":   endsAt.UTC().Format(time.RFC3339),
	}
	res := e.do(t, http.MethodPost, "/v1/maintenance-windows", m11JSON(t, body))
	if res.Status != http.StatusCreated {
		t.Fatalf("create window: %d %v", res.Status, res.Body)
	}
	id, _ := res.Body["id"].(string)
	if id == "" {
		t.Fatalf("created window without id: %v", res.Body)
	}
	return id
}

// createSilence creates a silence through the API and returns its id.
func (e *m11s3aEnv) createSilence(t *testing.T, match string, reason string, duration time.Duration) string {
	t.Helper()
	body := map[string]any{
		"match":            m11Raw(t, match),
		"reason":           reason,
		"duration_seconds": int(duration.Seconds()),
	}
	res := e.do(t, http.MethodPost, "/v1/silences", m11JSON(t, body))
	if res.Status != http.StatusCreated {
		t.Fatalf("create silence: %d %v", res.Status, res.Body)
	}
	id, _ := res.Body["id"].(string)
	if id == "" {
		t.Fatalf("created silence without id: %v", res.Body)
	}
	return id
}

func m11Raw(t *testing.T, raw string) any {
	t.Helper()
	var out any
	must(t, json.Unmarshal([]byte(raw), &out))
	return out
}

// alertRowState loads one alert row (owner role; assertions only).
func m11s3aAlert(t *testing.T, orgID, alertID uuid.UUID) map[string]any {
	t.Helper()
	var (
		state, reason string
		fp            string
		ref           *uuid.UUID
		value         []byte
	)
	err := ownerPool.QueryRow(context.Background(), `
		SELECT state, suppression_reason, suppression_ref, fingerprint, value
		FROM alerts WHERE id = $1 AND org_id = $2`, alertID, orgID).Scan(&state, &reason, &ref, &fp, &value)
	must(t, err)
	row := map[string]any{"state": state, "suppression_reason": reason, "fingerprint": fp, "value": value}
	if ref != nil {
		row["suppression_ref"] = ref
	} else {
		row["suppression_ref"] = nil
	}
	return row
}

// deliveryRowsForAlert counts the delivery log rows for an alert and kind.
func m11s3aDeliveryCount(t *testing.T, orgID, alertID uuid.UUID, kind string) int {
	t.Helper()
	var n int
	err := ownerPool.QueryRow(context.Background(), `
		SELECT count(*) FROM notification_deliveries
		WHERE org_id = $1 AND alert_id = $2 AND event_kind = $3`, orgID, alertID, kind).Scan(&n)
	must(t, err)
	return n
}

// m11s3aDeviceAndSeries creates a device + series with the given metric key.
func m11s3aDeviceAndSeries(t *testing.T, orgID, siteID uuid.UUID, name, metricKey string) (uuid.UUID, int64) {
	t.Helper()
	dev := m11Device(t, orgID, siteID, name, "switch")
	series := m11Series(t, orgID, dev, metricKey, nil, "count")
	return dev, series
}

// streamFrame is one parsed SSE frame.
type streamFrame struct {
	ID    string
	Event string
	Data  map[string]any
}

// streamReader reads SSE frames from a live response body.
type streamReader struct {
	t      *testing.T
	r      *bufio.Reader
	resp   *http.Response
	closed bool
}

func newStreamReader(t *testing.T, resp *http.Response) *streamReader {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}
	return &streamReader{t: t, r: bufio.NewReader(resp.Body), resp: resp}
}

func (s *streamReader) close() {
	if s == nil || s.closed {
		return
	}
	s.closed = true
	_ = s.resp.Body.Close()
}

// next reads the next non-comment SSE frame. Heartbeat comments are skipped.
func (s *streamReader) next(deadline time.Duration) (streamFrame, bool) {
	s.t.Helper()
	type result struct {
		frame streamFrame
		ok    bool
	}
	done := make(chan result, 1)
	go func() {
		var frame streamFrame
		for {
			line, err := s.r.ReadString('\n')
			if err != nil {
				done <- result{ok: false}
				return
			}
			line = strings.TrimRight(line, "\r\n")
			switch {
			case line == "":
				if frame.Event != "" || frame.Data != nil {
					done <- result{frame: frame, ok: true}
					return
				}
			case strings.HasPrefix(line, ":"):
				// heartbeat / comment
			case strings.HasPrefix(line, "id:"):
				frame.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			case strings.HasPrefix(line, "event:"):
				frame.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				raw := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				frame.Data = map[string]any{}
				if err := json.Unmarshal([]byte(raw), &frame.Data); err != nil {
					done <- result{ok: false}
					return
				}
			}
		}
	}()
	select {
	case res := <-done:
		return res.frame, res.ok
	case <-time.After(deadline):
		return streamFrame{}, false
	}
}

// openStream connects to the SSE endpoint with the env session (no client
// timeout, so the connection stays open for the test duration).
func (e *m11s3aEnv) openStream(t *testing.T, lastEventID string) *streamReader {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, e.srv.URL+"/v1/streams/events", nil)
	must(t, err)
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	client := &http.Client{Jar: e.client.Jar}
	resp, err := client.Do(req)
	must(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return newStreamReader(t, resp)
}

// openStreamAs connects as another logged-in client (scope tests).
func openStreamAs(t *testing.T, srv *httptest.Server, client *http.Client, lastEventID string) *streamReader {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/v1/streams/events", nil)
	must(t, err)
	if lastEventID != "" {
		req.Header.Set("Last-Event-ID", lastEventID)
	}
	resp, err := (&http.Client{Jar: client.Jar}).Do(req)
	must(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	return newStreamReader(t, resp)
}

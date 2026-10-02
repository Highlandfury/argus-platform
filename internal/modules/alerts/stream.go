package alerts

// M11-S3a — the alert event stream (docs/12 §22.16, P2-AC-33): the canonical
// SSE surface the UI consumes. `GET /v1/streams/events` is authenticated by
// the session cookie, org-scoped by the session and site-filtered by the
// caller's server-side bindings. Events are the committed alert transitions
// fanned out in-process (P2-D3: no NATS), replayed on reconnect from a
// retained 10-minute buffer with a PostgreSQL fallback for older gaps, and
// heartbeated every 20 s. Each connection has a bounded buffer; overflow drops
// the event and the client recovers the gap via Last-Event-ID.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/httpx"
)

// Canonical SSE event names (docs/12 §22.16).
const (
	StreamEventFired    = "alert.fired"
	StreamEventResolved = "alert.resolved"
	StreamEventUpdated  = "alert.updated"
)

// Stream bounds (documented judgement calls where the canonical docs are
// silent; docs/12 §22.16 fixes only the 10 min retained buffer and 20 s
// heartbeat).
const (
	// StreamHeartbeat is the canonical heartbeat cadence.
	StreamHeartbeat = 20 * time.Second
	// StreamBufferTTL is the canonical retained in-memory replay window.
	StreamBufferTTL = 10 * time.Minute
	// StreamBufferMax bounds the retained buffer (events across all orgs).
	StreamBufferMax = 4096
	// StreamClientBuffer bounds one connection's pending events. Overflow
	// increments argus_alerts_stream_dropped_total{reason="buffer_full"}; the
	// event remains in the retained buffer / PG for Last-Event-ID replay.
	StreamClientBuffer = 128
	// StreamReplayMax bounds one PostgreSQL replay page.
	StreamReplayMax = 1000
)

// StreamName maps an internal alert_events kind to the canonical SSE event
// name. `alert.fired` covers activation/reactivation/reopen; `alert.resolved`
// covers automatic and manual resolution; every other lifecycle event
// (pending, updated, acknowledged, snoozed, unsnoozed, suppressed,
// unsuppressed, comment) is an `alert.updated`.
func StreamName(kind string) string {
	switch kind {
	case EventActivated, EventReactivated, EventReopened:
		return StreamEventFired
	case EventResolved, EventManualResolved:
		return StreamEventResolved
	default:
		return StreamEventUpdated
	}
}

// StreamEvent is one committed alert transition prepared for the SSE stream.
type StreamEvent struct {
	// ID is the alert_events id and the SSE `id:` line (UUIDv7, time-ordered),
	// so Last-Event-ID replay is a keyset scan from PostgreSQL.
	ID                uuid.UUID
	OrgID             uuid.UUID
	SiteID            uuid.UUID
	ResourceType      string
	ResourceID        uuid.UUID
	AlertID           uuid.UUID
	EventID           uuid.UUID
	Kind              string // internal alert_events.kind
	Name              string // canonical SSE event name
	State             string
	Severity          string
	Fingerprint       string
	Suppressed        bool
	SuppressionReason string
	SuppressionRef    *uuid.UUID
	Ts                time.Time
	Data              []byte // pre-encoded JSON object for the `data:` line
}

// StreamOptions configures a StreamHub. Zero values take documented defaults.
type StreamOptions struct {
	Now          func() time.Time
	Logger       *slog.Logger
	BufferTTL    time.Duration
	BufferMax    int
	ClientBuffer int
}

// StreamHub fans committed alert transitions out to connected SSE clients and
// retains a bounded replay buffer. Transitioned is called after the alert
// transaction commits and never blocks the state machine: a slow client's
// events are dropped, not queued unboundedly.
type StreamHub struct {
	mu     sync.Mutex
	now    func() time.Time
	logger *slog.Logger

	buf   []StreamEvent // append-only with a logical start offset
	start int

	subs map[uuid.UUID]map[*StreamSub]struct{}

	bufferTTL    time.Duration
	bufferMax    int
	clientBuffer int
}

// StreamSub is one SSE connection subscription; its private channel is
// drained by the HTTP handler in this package.
type StreamSub struct {
	orgID uuid.UUID
	ch    chan StreamEvent
}

// NewStreamHub wires the hub.
func NewStreamHub(opts StreamOptions) *StreamHub {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.BufferTTL <= 0 {
		opts.BufferTTL = StreamBufferTTL
	}
	if opts.BufferMax <= 0 {
		opts.BufferMax = StreamBufferMax
	}
	if opts.ClientBuffer <= 0 {
		opts.ClientBuffer = StreamClientBuffer
	}
	return &StreamHub{
		now:          opts.Now,
		logger:       opts.Logger,
		subs:         map[uuid.UUID]map[*StreamSub]struct{}{},
		bufferTTL:    opts.BufferTTL,
		bufferMax:    opts.BufferMax,
		clientBuffer: opts.ClientBuffer,
	}
}

// Transitioned implements TransitionSink: it publishes one SSE event for
// every committed transition. Drops on a full per-connection buffer are
// counted and recovered by replay.
func (h *StreamHub) Transitioned(_ context.Context, t Transition) {
	if h == nil {
		return
	}
	if t.Event.ID == uuid.Nil {
		return
	}
	ev := buildStreamEvent(t)
	if ev == nil {
		return
	}
	h.publish(*ev)
}

func buildStreamEvent(t Transition) *StreamEvent {
	a := t.Alert
	if a.ID == uuid.Nil {
		return nil
	}
	payload := map[string]any{
		"alert_id":           a.ID.String(),
		"event_id":           t.Event.ID.String(),
		"event_kind":         t.Event.Kind,
		"state":              a.State,
		"severity":           a.Severity,
		"rule_id":            a.RuleID.String(),
		"fingerprint":        a.Fingerprint,
		"resource_type":      a.ResourceType,
		"resource_id":        a.ResourceID.String(),
		"suppressed":         t.Suppressed,
		"suppression_reason": a.SuppressionReason,
		"incident_id":        nil, // incidents are V2
		"occurred_at":        t.Event.Ts.UTC().Format(time.RFC3339),
	}
	if a.SiteID != uuid.Nil {
		payload["site_id"] = a.SiteID.String()
	}
	if a.ResourceType == "device" {
		payload["device_id"] = a.ResourceID.String()
	}
	if a.SuppressionRef != nil {
		payload["suppression_ref"] = a.SuppressionRef.String()
	}
	if len(t.Event.Data) > 0 {
		payload["event_data"] = json.RawMessage(t.Event.Data)
	}
	return &StreamEvent{
		ID:                t.Event.ID,
		OrgID:             a.OrgID,
		SiteID:            a.SiteID,
		ResourceType:      a.ResourceType,
		ResourceID:        a.ResourceID,
		AlertID:           a.ID,
		EventID:           t.Event.ID,
		Kind:              t.Event.Kind,
		Name:              StreamName(t.Event.Kind),
		State:             a.State,
		Severity:          a.Severity,
		Fingerprint:       a.Fingerprint,
		Suppressed:        t.Suppressed,
		SuppressionReason: a.SuppressionReason,
		SuppressionRef:    a.SuppressionRef,
		Ts:                t.Event.Ts,
		Data:              mustMarshal(payload),
	}
}

// publish appends to the retained buffer and fans out to the org's clients.
func (h *StreamHub) publish(ev StreamEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf = append(h.buf, ev)
	h.pruneLocked()
	for sub := range h.subs[ev.OrgID] {
		select {
		case sub.ch <- ev:
		default:
			alertsStreamDropped.WithLabelValues("buffer_full").Inc()
			if h.logger != nil {
				h.logger.Warn("alerts stream: client buffer full; event dropped for Last-Event-ID replay",
					"component", "alerts", "org_id", ev.OrgID, "event_id", ev.ID)
			}
		}
	}
}

// pruneLocked enforces the TTL and count bounds with a logical start offset so
// publishing stays amortized O(1).
func (h *StreamHub) pruneLocked() {
	cut := h.now().UTC().Add(-h.bufferTTL)
	for h.start < len(h.buf) && h.buf[h.start].Ts.Before(cut) {
		h.start++
	}
	if h.start > 0 && (h.start >= 1024 || h.start*2 >= len(h.buf)) {
		h.buf = append([]StreamEvent(nil), h.buf[h.start:]...)
		h.start = 0
	}
	if len(h.buf)-h.start > h.bufferMax {
		h.start = len(h.buf) - h.bufferMax
		h.buf = append([]StreamEvent(nil), h.buf[h.start:]...)
		h.start = 0
	}
}

// Subscribe registers one connection for an organization. The caller must
// Unsubscribe.
func (h *StreamHub) Subscribe(orgID uuid.UUID) *StreamSub {
	h.mu.Lock()
	defer h.mu.Unlock()
	sub := &StreamSub{orgID: orgID, ch: make(chan StreamEvent, h.clientBuffer)}
	if h.subs[orgID] == nil {
		h.subs[orgID] = map[*StreamSub]struct{}{}
	}
	h.subs[orgID][sub] = struct{}{}
	alertsStreamClients.Inc()
	return sub
}

// Unsubscribe removes a connection and closes its channel.
func (h *StreamHub) Unsubscribe(sub *StreamSub) {
	if h == nil || sub == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	set, ok := h.subs[sub.orgID]
	if !ok {
		return
	}
	if _, ok := set[sub]; !ok {
		return
	}
	delete(set, sub)
	close(sub.ch)
	if len(set) == 0 {
		delete(h.subs, sub.orgID)
	}
	alertsStreamClients.Dec()
}

// Replay returns the retained events for an organization strictly after the
// given event id. found=false means the id is not in the retained buffer (the
// caller must fall back to the PostgreSQL replay for the gap).
func (h *StreamHub) Replay(orgID uuid.UUID, after uuid.UUID) ([]StreamEvent, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	idx := -1
	for i := h.start; i < len(h.buf); i++ {
		if h.buf[i].ID == after {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, false
	}
	out := make([]StreamEvent, 0, len(h.buf)-idx)
	for _, ev := range h.buf[idx+1:] {
		if ev.OrgID == orgID {
			out = append(out, ev)
		}
	}
	return out, true
}

// Clients returns the connected client count (tests/ops introspection).
func (h *StreamHub) Clients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, set := range h.subs {
		n += len(set)
	}
	return n
}

// streamEventAllowed applies the caller's scope to one event: only device
// resources with an in-scope site are delivered to restricted callers (the
// same fail-closed rule as alert reads).
func streamEventAllowed(ev StreamEvent, sc authz.Scope) bool {
	if sc.Unrestricted {
		return true
	}
	return ev.ResourceType == "device" && ev.SiteID != uuid.Nil && sc.AllowsSite(ev.SiteID)
}

// writeSSE writes one SSE frame. The data line is a single-line JSON object.
func writeSSE(w http.ResponseWriter, ev StreamEvent) error {
	if _, err := fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", ev.ID, ev.Name, ev.Data); err != nil {
		return err
	}
	alertsStreamEvents.WithLabelValues(ev.Name).Inc()
	return nil
}

// StreamEvents handles GET /v1/streams/events (alert.read capability, site
// scope). The canonical contract: session-cookie auth, `?filter[site]=`-style
// scoping is replaced here by the caller's server-side bindings (stronger than
// a client-supplied filter), 20 s heartbeats, Last-Event-ID resume.
func (h *HTTP) StreamEvents(w http.ResponseWriter, r *http.Request) {
	if h.Stream == nil {
		httpx.WriteProblem(w, r, http.StatusServiceUnavailable, "service.unavailable", "alert stream not configured")
		return
	}
	p, ok := h.principalOrg(w, r)
	if !ok {
		return
	}
	sc, ok := h.scopeFor(w, r, p)
	if !ok {
		return
	}

	// Subscribe before replay so a transition committed between the replay
	// query and the live loop is never lost; duplicates are skipped by id.
	sub := h.Stream.Subscribe(p.OrgID)
	defer h.Stream.Unsubscribe(sub)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	ctrl := http.NewResponseController(w)
	_, _ = fmt.Fprint(w, "retry: 3000\n\n")
	if err := ctrl.Flush(); err != nil {
		return
	}

	var lastSent uuid.UUID
	if raw := r.Header.Get("Last-Event-ID"); raw != "" {
		if id, err := uuid.Parse(raw); err == nil {
			replay, err := h.replayEvents(r.Context(), p.OrgID, id, sc)
			if err != nil {
				if h.Stream.logger != nil {
					h.Stream.logger.Warn("alerts stream: replay failed",
						"component", "alerts", "org_id", p.OrgID, "after", raw, "error", err)
				}
			} else {
				for _, ev := range replay {
					if !streamEventAllowed(ev, sc) {
						continue
					}
					if err := writeSSE(w, ev); err != nil {
						alertsStreamDropped.WithLabelValues("write_error").Inc()
						return
					}
					lastSent = ev.ID
				}
				if err := ctrl.Flush(); err != nil {
					return
				}
			}
		}
	}

	heartbeat := time.NewTicker(StreamHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-sub.ch:
			if !open {
				return
			}
			if lastSent != (uuid.UUID{}) && bytes.Compare(ev.ID[:], lastSent[:]) <= 0 {
				continue // already replayed
			}
			if !streamEventAllowed(ev, sc) {
				continue
			}
			if err := writeSSE(w, ev); err != nil {
				alertsStreamDropped.WithLabelValues("write_error").Inc()
				return
			}
			lastSent = ev.ID
			if err := ctrl.Flush(); err != nil {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			if err := ctrl.Flush(); err != nil {
				return
			}
		}
	}
}

// replayEvents resolves the events after Last-Event-ID from the retained
// in-memory buffer, falling back to the PostgreSQL alert_events keyset (the
// canonical "10 min buffer + replay from PG for gaps").
func (h *HTTP) replayEvents(ctx context.Context, orgID uuid.UUID, after uuid.UUID, sc authz.Scope) ([]StreamEvent, error) {
	if evs, found := h.Stream.Replay(orgID, after); found {
		return evs, nil
	}
	return h.Svc.ReplayEvents(ctx, orgID, after, sc, StreamReplayMax)
}

// ReplayEvents loads committed alert events after `after` from PostgreSQL for
// the SSE Last-Event-ID fallback. RLS plus the caller's scope filter apply.
func (s *Service) ReplayEvents(ctx context.Context, orgID uuid.UUID, after uuid.UUID, sc authz.Scope, limit int) ([]StreamEvent, error) {
	if limit <= 0 || limit > StreamReplayMax {
		limit = StreamReplayMax
	}
	var out []StreamEvent
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT e.id, e.kind, e.data, e.ts,
			       a.id, a.state, a.severity, a.fingerprint, a.resource_type, a.resource_id,
			       a.suppression_reason, a.suppression_ref, d.site_id
			FROM alert_events e
			JOIN alerts a ON a.id = e.alert_id AND a.org_id = e.org_id
			LEFT JOIN devices d
			  ON a.resource_type = 'device' AND d.id = a.resource_id AND d.org_id = a.org_id
			WHERE e.id > $1
			  AND ($2::boolean OR (a.resource_type = 'device' AND d.site_id = ANY($3::uuid[])))
			ORDER BY e.id
			LIMIT $4`, after, sc.Unrestricted, sc.Sites, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				ev      StreamEvent
				eventID uuid.UUID
				kind    string
				data    []byte
				ts      time.Time
				alertID uuid.UUID
				siteID  *uuid.UUID
				ref     *uuid.UUID
			)
			if err := rows.Scan(&eventID, &kind, &data, &ts, &alertID, &ev.State, &ev.Severity,
				&ev.Fingerprint, &ev.ResourceType, &ev.ResourceID, &ev.SuppressionReason, &ref, &siteID); err != nil {
				return err
			}
			_ = data
			ev.ID, ev.EventID, ev.AlertID = eventID, eventID, alertID
			ev.Kind, ev.Name, ev.Ts = kind, StreamName(kind), ts
			ev.OrgID = orgID
			ev.Suppressed = ev.SuppressionReason != ""
			if ref != nil {
				ev.SuppressionRef = ref
			}
			if siteID != nil {
				ev.SiteID = *siteID
			}
			payload := map[string]any{
				"alert_id":           alertID.String(),
				"event_id":           eventID.String(),
				"event_kind":         kind,
				"state":              ev.State,
				"severity":           ev.Severity,
				"fingerprint":        ev.Fingerprint,
				"resource_type":      ev.ResourceType,
				"resource_id":        ev.ResourceID.String(),
				"suppressed":         ev.Suppressed,
				"suppression_reason": ev.SuppressionReason,
				"incident_id":        nil,
				"occurred_at":        ts.UTC().Format(time.RFC3339),
			}
			if len(data) > 0 {
				payload["event_data"] = json.RawMessage(data)
			}
			if ev.SiteID != uuid.Nil {
				payload["site_id"] = ev.SiteID.String()
			}
			if ref != nil {
				payload["suppression_ref"] = ref.String()
			}
			if ev.ResourceType == "device" {
				payload["device_id"] = ev.ResourceID.String()
			}
			ev.Data = mustMarshal(payload)
			out = append(out, ev)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

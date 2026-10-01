package collectors

import (
	"sync"

	"github.com/google/uuid"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
)

// DisconnectMsg asks a live session to tell its collector to go away.
type DisconnectMsg struct {
	Code   collectorv1.Disconnect_Code
	Reason string
}

// SessionCheckBuffer bounds queued on-demand check orders per stream session
// (M10-S0). Overflow drops the push (the DB row stays pending and is bounded
// by its server-side TTL); reconnect redelivery refills up to this bound.
const SessionCheckBuffer = 64

// Session is the server-side representation of one active collector stream.
type Session struct {
	collectorID uuid.UUID
	notify      chan DisconnectMsg
	policyCh    chan *SignedPolicy
	// checkCh carries on-demand check orders (M10-S0); bounded, push-only,
	// drops when full (the DB row stays pending and is redelivered/expired).
	checkCh chan *collectorv1.CheckRequest
	// sessionKey is the collector's ephemeral X25519 public key for M9-S3
	// credential materialization (nil for collectors that do not present one).
	sessionKey []byte
}

// Notify is the disconnect request channel.
func (s *Session) Notify() <-chan DisconnectMsg { return s.notify }

// Policy is the push channel for new signed policies.
func (s *Session) Policy() <-chan *SignedPolicy { return s.policyCh }

// Checks is the push channel for on-demand check orders (M10-S0).
func (s *Session) Checks() <-chan *collectorv1.CheckRequest { return s.checkCh }

// PushCheck enqueues one check order; false when the session buffer is full
// (the check stays pending server-side and is bounded by its TTL).
func (s *Session) PushCheck(req *collectorv1.CheckRequest) bool {
	if s == nil || req == nil {
		return false
	}
	select {
	case s.checkCh <- req:
		return true
	default:
		return false
	}
}

// SessionPublicKey returns a copy of the session's ephemeral public key (nil
// when the collector did not present one).
func (s *Session) SessionPublicKey() []byte {
	if s == nil || len(s.sessionKey) == 0 {
		return nil
	}
	return append([]byte(nil), s.sessionKey...)
}

// SessionRegistry tracks live collector streams. One collector has at most one
// current session; a newer connection deterministically supersedes the older
// one (the old stream receives CODE_SUPERSEDED).
type SessionRegistry struct {
	mu       sync.Mutex
	sessions map[uuid.UUID]*Session
}

// NewSessionRegistry creates an empty registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{sessions: make(map[uuid.UUID]*Session)}
}

// Register installs a new session for the collector, notifying any previous
// session to disconnect with SUPERSEDED. Returns (session, superseded).
func (r *SessionRegistry) Register(collectorID uuid.UUID) (*Session, bool) {
	return r.RegisterWithSessionKey(collectorID, nil)
}

// RegisterWithSessionKey installs a new session advertising the collector's
// ephemeral X25519 public key for M9-S3 policy materialization (nil when the
// collector did not present one).
func (r *SessionRegistry) RegisterWithSessionKey(collectorID uuid.UUID, sessionKey []byte) (*Session, bool) {
	superseded := false
	s := &Session{
		collectorID: collectorID,
		notify:      make(chan DisconnectMsg, 1),
		policyCh:    make(chan *SignedPolicy, 4),
		checkCh:     make(chan *collectorv1.CheckRequest, SessionCheckBuffer),
		sessionKey:  append([]byte(nil), sessionKey...),
	}
	r.mu.Lock()
	if old, ok := r.sessions[collectorID]; ok {
		superseded = true
		select {
		case old.notify <- DisconnectMsg{Code: collectorv1.Disconnect_CODE_SUPERSEDED, Reason: "superseded by a newer connection"}:
		default:
		}
	}
	r.sessions[collectorID] = s
	r.mu.Unlock()
	return s, superseded
}

// SessionPublicKey returns the live session's ephemeral public key for a
// collector (nil when offline or not presented).
func (r *SessionRegistry) SessionPublicKey(collectorID uuid.UUID) []byte {
	r.mu.Lock()
	s, ok := r.sessions[collectorID]
	r.mu.Unlock()
	if !ok {
		return nil
	}
	return s.SessionPublicKey()
}

// Unregister removes the session if it is still the current one.
func (r *SessionRegistry) Unregister(collectorID uuid.UUID, s *Session) {
	r.mu.Lock()
	if cur, ok := r.sessions[collectorID]; ok && cur == s {
		delete(r.sessions, collectorID)
	}
	r.mu.Unlock()
}

// PushPolicy delivers a policy update to a live session (false if offline).
func (r *SessionRegistry) PushPolicy(collectorID uuid.UUID, sp *SignedPolicy) bool {
	r.mu.Lock()
	s, ok := r.sessions[collectorID]
	r.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case s.policyCh <- sp:
		return true
	default:
		return false
	}
}

// PushCheck delivers one on-demand check order to a live session (false if
// offline or the session buffer is full; the check stays pending).
func (r *SessionRegistry) PushCheck(collectorID uuid.UUID, req *collectorv1.CheckRequest) bool {
	r.mu.Lock()
	s, ok := r.sessions[collectorID]
	r.mu.Unlock()
	if !ok {
		return false
	}
	return s.PushCheck(req)
}

// HasSession reports whether a collector has a live stream session.
func (r *SessionRegistry) HasSession(collectorID uuid.UUID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.sessions[collectorID]
	return ok
}

// Disconnect asks one collector's live session to terminate.
func (r *SessionRegistry) Disconnect(collectorID uuid.UUID, msg DisconnectMsg) bool {
	r.mu.Lock()
	s, ok := r.sessions[collectorID]
	r.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case s.notify <- msg:
	default:
	}
	return true
}

// DisconnectAll signals every live session (server shutdown path).
func (r *SessionRegistry) DisconnectAll(msg DisconnectMsg) {
	r.mu.Lock()
	snapshot := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		snapshot = append(snapshot, s)
	}
	r.mu.Unlock()
	for _, s := range snapshot {
		select {
		case s.notify <- msg:
		default:
		}
	}
}

// ActiveCount returns the number of live sessions.
func (r *SessionRegistry) ActiveCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

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

// Session is the server-side representation of one active collector stream.
type Session struct {
	collectorID uuid.UUID
	notify      chan DisconnectMsg
	policyCh    chan *SignedPolicy
	// sessionKey is the collector's ephemeral X25519 public key for M9-S3
	// credential materialization (nil for collectors that do not present one).
	sessionKey []byte
}

// Notify is the disconnect request channel.
func (s *Session) Notify() <-chan DisconnectMsg { return s.notify }

// Policy is the push channel for new signed policies.
func (s *Session) Policy() <-chan *SignedPolicy { return s.policyCh }

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

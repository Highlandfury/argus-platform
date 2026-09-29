// Package collector hosts the collector-side runtime pieces (state machine,
// identity, policy handling, enrollment, transport).
package collector

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// State is the collector runtime lifecycle (SPEC §4.1 + M3 definition).
type State string

// Collector runtime states.
const (
	StateNew          State = "NEW"          // process start, no identity check yet
	StateEnrolling    State = "ENROLLING"    // token exchange in progress
	StateActive       State = "ACTIVE"       // authenticated stream established
	StateDisconnected State = "DISCONNECTED" // stream lost; identity intact
	StateReconnecting State = "RECONNECTING" // backoff + reconnect attempts
	StateRevoked      State = "REVOKED"      // terminal: server revoked identity
	StateFailed       State = "FAILED"       // terminal for this process run
)

// allowedTransitions is the normative state graph. Anything else is rejected.
var allowedTransitions = map[State][]State{
	StateNew:          {StateEnrolling, StateReconnecting, StateFailed},
	StateEnrolling:    {StateActive, StateReconnecting, StateRevoked, StateFailed},
	StateActive:       {StateDisconnected, StateRevoked, StateFailed},
	StateDisconnected: {StateReconnecting, StateRevoked, StateFailed},
	StateReconnecting: {StateActive, StateRevoked, StateFailed},
	StateRevoked:      {},
	StateFailed:       {},
}

// ErrInvalidTransition is returned for transitions outside the graph.
var ErrInvalidTransition = errors.New("collector: invalid state transition")

// Machine tracks and validates lifecycle transitions.
type Machine struct {
	mu    sync.Mutex
	state State
	log   *slog.Logger
}

// NewMachine starts a machine in the given state.
func NewMachine(start State, log *slog.Logger) *Machine {
	return &Machine{state: start, log: log}
}

// State returns the current state.
func (m *Machine) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Transition validates and applies a state change.
func (m *Machine) Transition(to State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, allowed := range allowedTransitions[m.state] {
		if allowed == to {
			if m.log != nil {
				m.log.Info("state transition", "from", m.state, "to", to)
			}
			m.state = to
			return nil
		}
	}
	return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, m.state, to)
}

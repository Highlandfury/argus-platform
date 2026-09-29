package collector

import (
	"errors"
	"testing"
)

func TestStateMachineValidPath(t *testing.T) {
	m := NewMachine(StateNew, nil)
	for _, next := range []State{StateEnrolling, StateActive, StateDisconnected, StateReconnecting, StateActive, StateRevoked} {
		if err := m.Transition(next); err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
	if m.State() != StateRevoked {
		t.Fatalf("final state = %s", m.State())
	}
}

func TestStateMachineRejectsInvalid(t *testing.T) {
	cases := []struct {
		from State
		to   State
	}{
		{StateNew, StateActive},
		{StateRevoked, StateActive},
		{StateFailed, StateReconnecting},
		{StateActive, StateEnrolling},
		{StateDisconnected, StateActive}, // must pass through RECONNECTING
	}
	for _, tc := range cases {
		m := NewMachine(tc.from, nil)
		if err := m.Transition(tc.to); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("%s -> %s: want ErrInvalidTransition, got %v", tc.from, tc.to, err)
		}
		if m.State() != tc.from {
			t.Fatalf("state changed on rejected transition: %s", m.State())
		}
	}
}

func TestStateMachineTerminal(t *testing.T) {
	for _, terminal := range []State{StateRevoked, StateFailed} {
		m := NewMachine(terminal, nil)
		if err := m.Transition(StateActive); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("%s must be terminal, got %v", terminal, err)
		}
	}
}

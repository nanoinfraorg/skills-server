package auth

import (
	"testing"
	"time"
)

func TestStateStore_ConsumeValidState(t *testing.T) {
	s := NewStateStore()
	state, err := s.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !s.Consume(state) {
		t.Fatalf("expected a freshly generated state to be consumable")
	}
}

func TestStateStore_ConsumeIsSingleUse(t *testing.T) {
	s := NewStateStore()
	state, err := s.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !s.Consume(state) {
		t.Fatalf("first consume should succeed")
	}
	if s.Consume(state) {
		t.Fatalf("second consume of the same state must fail (replay protection)")
	}
}

func TestStateStore_UnknownStateRejected(t *testing.T) {
	s := NewStateStore()
	if s.Consume("never-issued") {
		t.Fatalf("expected an unknown state to be rejected")
	}
}

func TestStateStore_ExpiredStateRejected(t *testing.T) {
	s := NewStateStore()
	state, err := s.New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Force the stored expiry into the past to simulate a stale state
	// value without waiting out the real stateTTL.
	s.mu.Lock()
	s.values[state] = time.Now().Add(-time.Second)
	s.mu.Unlock()

	if s.Consume(state) {
		t.Fatalf("expected an expired state to be rejected")
	}
	// And it must have been consumed (deleted) regardless of the outcome.
	s.mu.Lock()
	_, stillThere := s.values[state]
	s.mu.Unlock()
	if stillThere {
		t.Fatalf("expected the expired state to be deleted after Consume")
	}
}

package auth

import (
	"sync"
	"time"
)

// stateTTL bounds how long a generated OAuth "state" value remains valid
// and unused before a callback presenting it is rejected. This is
// intentionally short: state only needs to survive the round trip through
// Google's consent screen, not a whole browsing session.
const stateTTL = 10 * time.Minute

// StateStore holds single-use, short-lived OAuth "state" values in memory,
// keyed by the state string itself, guarded by a mutex.
//
// This is an in-memory, single-process store: state is lost on restart (a
// login started just before a restart fails at the callback and the user
// simply retries -- an acceptable v1 tradeoff) and does not work across a
// horizontally-scaled multi-process deployment with no shared session
// affinity. skills-server is deployed as a single process, so this is
// fine for now; a multi-instance deployment would need to move this into
// the shared SQLite store or an external cache instead.
type StateStore struct {
	mu     sync.Mutex
	values map[string]time.Time // state -> expiry
}

// NewStateStore creates an empty StateStore.
func NewStateStore() *StateStore {
	return &StateStore{values: make(map[string]time.Time)}
}

// New generates a fresh, cryptographically random state value, records it
// with a stateTTL expiry, and returns it for use in an AuthCodeURL.
func (s *StateStore) New() (string, error) {
	state, err := RandomToken(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[state] = time.Now().Add(stateTTL)
	return state, nil
}

// Consume reports whether state is a known, unexpired value -- and either
// way deletes it, so it can never be presented again. This makes state
// single-use: a replayed or guessed state value is rejected even if it
// was valid moments ago.
func (s *StateStore) Consume(state string) bool {
	if state == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.values[state]
	delete(s.values, state)
	if !ok {
		return false
	}
	return time.Now().Before(expiry)
}

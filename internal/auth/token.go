// Package auth implements the "Sign in with Google" server-side OAuth
// Authorization Code flow used as a second, parallel way to authenticate
// (alongside the existing X-Submitter-Token / X-Admin-Token shared
// secrets): building the oauth2.Config for Google's endpoint, verifying
// the returned ID token via go-oidc, single-use OAuth "state" tracking,
// and computing an authenticated email's role from the ADMIN_EMAILS /
// SUBMITTER_EMAILS allowlists. The actual HTTP handlers
// (GET /auth/google/login, GET /auth/google/callback, POST /auth/logout)
// live in internal/api, which orchestrates this package together with
// internal/store's Session persistence -- the same split as
// internal/github (pure integration) vs. internal/api/admin.go
// (orchestration).
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// RandomToken returns a cryptographically random, hex-encoded string built
// from nBytes of underlying entropy (so the returned string is 2*nBytes
// characters long). It is used both for OAuth "state" values (StateStore)
// and for session ids -- always crypto/rand, never math/rand.
func RandomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

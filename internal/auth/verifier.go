package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// GoogleIssuer is Google's OIDC issuer, used for provider discovery
// (fetching the JWKS endpoint and other metadata from
// https://accounts.google.com/.well-known/openid-configuration).
const GoogleIssuer = "https://accounts.google.com"

// IDTokenClaims is the subset of an ID token's claims skills-server cares
// about, extracted after signature/issuer/audience/expiry verification has
// already passed.
type IDTokenClaims struct {
	Email         string
	EmailVerified bool
}

// IDTokenVerifier verifies a raw ID token JWT string -- signature against
// the provider's JWKS, issuer, audience, and expiry -- and extracts its
// claims. NewGoogleVerifier returns the real implementation, which wraps
// go-oidc's *oidc.IDTokenVerifier (JWKS fetching/caching included); tests
// inject a fake that returns fixed claims, the same pattern
// internal/api.Publisher uses to keep the real GitHub Contents API out of
// the test suite.
type IDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*IDTokenClaims, error)
}

// oidcVerifier adapts go-oidc's *oidc.IDTokenVerifier to IDTokenVerifier.
type oidcVerifier struct {
	verifier *oidc.IDTokenVerifier
}

// NewGoogleVerifier discovers Google's OIDC configuration and returns an
// IDTokenVerifier scoped to clientID as the required audience. This makes
// a network call (OIDC discovery) and is meant to be called once at
// startup, not per-request: go-oidc's verifier internally caches and
// refreshes the JWKS key set as needed.
func NewGoogleVerifier(ctx context.Context, clientID string) (IDTokenVerifier, error) {
	provider, err := oidc.NewProvider(ctx, GoogleIssuer)
	if err != nil {
		return nil, fmt.Errorf("discover google oidc provider: %w", err)
	}
	return &oidcVerifier{verifier: provider.Verifier(&oidc.Config{ClientID: clientID})}, nil
}

func (v *oidcVerifier) Verify(ctx context.Context, rawIDToken string) (*IDTokenClaims, error) {
	idToken, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id token: %w", err)
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode id token claims: %w", err)
	}
	return &IDTokenClaims{Email: claims.Email, EmailVerified: claims.EmailVerified}, nil
}

package auth

import (
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// NewGoogleOAuthConfig builds the oauth2.Config used to drive Google's
// server-side Authorization Code flow: GET /auth/google/login redirects to
// AuthCodeURL, and GET /auth/google/callback exchanges the returned code
// via Exchange. Scopes request "openid email profile" -- openid+email is
// the minimum needed to identify the signed-in user via the ID token;
// profile is requested too so Google's consent screen shows the usual
// permission set rather than an unusually narrow one.
func NewGoogleOAuthConfig(clientID, clientSecret, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     google.Endpoint,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/auth"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// GoogleLogin starts the "Sign in with Google" server-side Authorization
// Code flow: it generates a single-use "state" value (h.StateStore),
// remembers it, and redirects the browser to Google's consent screen.
// GoogleCallback verifies state is presented back unmodified before trusting
// anything else in the callback request.
func (h *Handler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := h.StateStore.New()
	if err != nil {
		h.Logger.Error("generate oauth state", "error", err)
		writeError(w, http.StatusInternalServerError, "could not start google sign-in")
		return
	}
	http.Redirect(w, r, h.GoogleOAuthConfig.AuthCodeURL(state), http.StatusFound)
}

// GoogleCallback completes the Authorization Code flow: it validates the
// one-time state value, exchanges the authorization code for a token,
// verifies the returned ID token (via h.IDTokenVerifier -- go-oidc in
// production, a fake in tests), checks the email is verified and on the
// appropriate allowlist, and -- if everything checks out -- creates a
// session and sets its cookie.
func (h *Handler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	// Consume unconditionally, regardless of the outcome below: a state
	// value is single-use, so even a state that turns out to belong to a
	// request that then fails for some other reason (bad code, unverified
	// email, ...) must not be replayable.
	if !h.StateStore.Consume(state) {
		writeError(w, http.StatusBadRequest, "invalid, expired, or already-used oauth state")
		return
	}
	if code == "" {
		writeError(w, http.StatusBadRequest, "missing code")
		return
	}

	token, err := h.GoogleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		h.Logger.Error("oauth code exchange", "error", err)
		writeError(w, http.StatusBadGateway, "could not exchange the authorization code with google")
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		h.Logger.Error("oauth token response missing id_token")
		writeError(w, http.StatusBadGateway, "google token response did not include an id_token")
		return
	}

	claims, err := h.IDTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		h.Logger.Error("verify id token", "error", err)
		writeError(w, http.StatusUnauthorized, "could not verify the google id token")
		return
	}
	if !claims.EmailVerified {
		writeError(w, http.StatusForbidden, "google account email is not verified")
		return
	}

	role, ok := auth.DetermineRole(claims.Email, h.AdminEmails, h.SubmitterEmails)
	if !ok {
		writeError(w, http.StatusForbidden, "this google account is not authorized for skills-server")
		return
	}

	sessionID, err := auth.RandomToken(32)
	if err != nil {
		h.Logger.Error("generate session id", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create a session")
		return
	}
	// A fresh CSRF token per session (see store.Session.CSRFToken and
	// internal/web's CSRF doc comment) -- generated here, alongside the
	// session id, from the same crypto/rand source.
	csrfToken, err := auth.RandomToken(32)
	if err != nil {
		h.Logger.Error("generate csrf token", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create a session")
		return
	}
	// Deliberately time.Now() rather than h.now(): session expiry is
	// compared against real wall-clock time in store.GetSession, so the
	// session's own timestamps must come from the same clock, not the
	// test-overridable Handler.Now hook used elsewhere for deterministic
	// submission/publish timestamps.
	now := time.Now()
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	sess := store.Session{
		ID:        sessionID,
		Email:     email,
		Role:      store.SessionRole(role),
		CreatedAt: now,
		ExpiresAt: now.Add(h.SessionTTL),
		CSRFToken: csrfToken,
	}
	if err := h.Store.CreateSession(ctx, sess); err != nil {
		h.Logger.Error("create session", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create a session")
		return
	}

	// Secure is set from h.PublicBaseURL's scheme when configured (correct
	// behind a TLS-terminating reverse proxy, where r.TLS is always nil
	// regardless of what the browser used); otherwise it falls back to
	// whether this request itself arrived over TLS. See
	// Handler.secureCookie and internal/config.Config.PublicBaseURL.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sess.ID,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		MaxAge:   int(h.SessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})

	h.Logger.Info("google sign-in", "email", sess.Email, "role", sess.Role)
	// Redirect to the home page rather than returning a bare confirmation
	// string: the HTML UI (internal/web) has its own nav/welcome there, so
	// landing on it after login integrates with the rest of the UI instead
	// of dead-ending on a standalone page.
	http.Redirect(w, r, "/", http.StatusFound)
}

// Logout deletes the session named by the request's session cookie (if
// any) and clears the cookie client-side. It always succeeds, whether or
// not a session existed -- logging out an already-logged-out client is not
// an error.
//
// Response shape is content-negotiated on the Accept header: a browser
// navigating here via the web UI's nav form sends Accept: text/html,...
// by default, so it gets a 302 back to "/" instead of landing on a bare,
// blank /auth/logout page. A plain API call (curl, no Accept header, per
// docs/api.md's example) gets the original 200-no-body response, so that
// documented contract is unchanged. See TestLogout_NoSessionCookieStillReturns200
// and TestLogout_InvalidatesSession, neither of which sets Accept and both
// of which assert exactly 200.
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		if err := h.Store.DeleteSession(r.Context(), cookie.Value); err != nil {
			h.Logger.Error("delete session", "error", err)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secureCookie(r),
		SameSite: http.SameSiteLaxMode,
	})
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

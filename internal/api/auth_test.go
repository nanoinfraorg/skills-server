package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/nanoinfraorg/skills-server/internal/auth"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// fakeIDTokenVerifier stands in for go-oidc's real verifier (which fetches
// and checks signatures against Google's live JWKS -- impossible to hit in
// a unit test), returning fixed claims or a fixed error. This is the same
// "small interface, fake implementation in tests" pattern the existing
// Publisher interface uses to keep the GitHub API out of the test suite.
type fakeIDTokenVerifier struct {
	claims *auth.IDTokenClaims
	err    error
}

func (f *fakeIDTokenVerifier) Verify(_ context.Context, _ string) (*auth.IDTokenClaims, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

// fakeGoogleTokenServer stands in for Google's token endpoint (the
// "exchange code for token" leg): it always succeeds and returns a fixed
// id_token string, which the fakeIDTokenVerifier then accepts or rejects
// independent of its actual content -- the real signature/claims
// verification is exactly the step under test via IDTokenVerifier, not the
// HTTP exchange itself.
func fakeGoogleTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"id_token":     "fake-raw-id-token",
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testGoogleAuthHandler builds on testHandler, wiring up the Google OAuth
// fields with a fake token endpoint and a fake ID token verifier so the
// full GoogleLogin/GoogleCallback flow can be driven end to end without
// touching the network.
func testGoogleAuthHandler(t *testing.T, claims *auth.IDTokenClaims, adminEmails, submitterEmails []string) *Handler {
	t.Helper()
	h, _ := testHandler(t)

	tokenServer := fakeGoogleTokenServer(t)
	h.GoogleOAuthConfig = &oauth2.Config{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://example.invalid/auth", // never hit in these tests
			TokenURL: tokenServer.URL,
		},
		Scopes: []string{"openid", "email", "profile"},
	}
	h.IDTokenVerifier = &fakeIDTokenVerifier{claims: claims}
	h.StateStore = auth.NewStateStore()
	h.AdminEmails = adminEmails
	h.SubmitterEmails = submitterEmails
	h.SessionTTL = time.Hour
	return h
}

func callbackRequest(state, code string) *http.Request {
	return httptest.NewRequest(http.MethodGet, "/auth/google/callback?state="+state+"&code="+code, nil)
}

func TestGoogleCallback_StateMismatchRejected(t *testing.T) {
	h := testGoogleAuthHandler(t, &auth.IDTokenClaims{Email: "admin@example.com", EmailVerified: true}, []string{"admin@example.com"}, nil)
	mux := NewMux(h)

	// A state value that was never issued by GoogleLogin/h.StateStore.New.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, callbackRequest("never-issued-state", "some-code"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body: %s", rec.Code, rec.Body.String())
	}
}

func TestGoogleCallback_ExpiredOrReusedStateRejected(t *testing.T) {
	h := testGoogleAuthHandler(t, &auth.IDTokenClaims{Email: "admin@example.com", EmailVerified: true}, []string{"admin@example.com"}, nil)
	mux := NewMux(h)

	state, err := h.StateStore.New()
	if err != nil {
		t.Fatalf("generate state: %v", err)
	}

	// First use succeeds.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, callbackRequest(state, "some-code"))
	if rec.Code != http.StatusOK {
		t.Fatalf("first callback status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	// Reusing the same (now-consumed) state must be rejected.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, callbackRequest(state, "some-code"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("reused state status = %d, want 400, body: %s", rec.Code, rec.Body.String())
	}
}

func TestGoogleCallback_EmailNotVerifiedRejected(t *testing.T) {
	h := testGoogleAuthHandler(t, &auth.IDTokenClaims{Email: "admin@example.com", EmailVerified: false}, []string{"admin@example.com"}, nil)
	mux := NewMux(h)

	state, err := h.StateStore.New()
	if err != nil {
		t.Fatalf("generate state: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, callbackRequest(state, "some-code"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body: %s", rec.Code, rec.Body.String())
	}
}

func TestGoogleCallback_AdminEmailGetsAdminRole(t *testing.T) {
	h := testGoogleAuthHandler(t, &auth.IDTokenClaims{Email: "Admin@Example.com", EmailVerified: true}, []string{"admin@example.com"}, []string{"submitter@example.com"})
	mux := NewMux(h)

	state, err := h.StateStore.New()
	if err != nil {
		t.Fatalf("generate state: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, callbackRequest(state, "some-code"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	cookie := sessionCookieFromResponse(t, rec)
	sess, err := h.Store.GetSession(context.Background(), cookie.Value)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess.Role != store.SessionRoleAdmin || sess.Email != "admin@example.com" {
		t.Errorf("unexpected session: %+v", sess)
	}
}

func TestGoogleCallback_SubmitterEmailInAllowlistGetsSubmitterRole(t *testing.T) {
	h := testGoogleAuthHandler(t, &auth.IDTokenClaims{Email: "submitter@example.com", EmailVerified: true}, []string{"admin@example.com"}, []string{"submitter@example.com"})
	mux := NewMux(h)

	state, err := h.StateStore.New()
	if err != nil {
		t.Fatalf("generate state: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, callbackRequest(state, "some-code"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	cookie := sessionCookieFromResponse(t, rec)
	sess, err := h.Store.GetSession(context.Background(), cookie.Value)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess.Role != store.SessionRoleSubmitter {
		t.Errorf("role = %s, want submitter", sess.Role)
	}
}

func TestGoogleCallback_AnyEmailGetsSubmitterRoleWhenSubmitterEmailsUnset(t *testing.T) {
	h := testGoogleAuthHandler(t, &auth.IDTokenClaims{Email: "anyone@example.com", EmailVerified: true}, []string{"admin@example.com"}, nil)
	mux := NewMux(h)

	state, err := h.StateStore.New()
	if err != nil {
		t.Fatalf("generate state: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, callbackRequest(state, "some-code"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	cookie := sessionCookieFromResponse(t, rec)
	sess, err := h.Store.GetSession(context.Background(), cookie.Value)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if sess.Role != store.SessionRoleSubmitter {
		t.Errorf("role = %s, want submitter", sess.Role)
	}
}

func TestGoogleCallback_EmailInNeitherListRejectedWhenSubmitterEmailsSet(t *testing.T) {
	h := testGoogleAuthHandler(t, &auth.IDTokenClaims{Email: "nobody@example.com", EmailVerified: true}, []string{"admin@example.com"}, []string{"submitter@example.com"})
	mux := NewMux(h)

	state, err := h.StateStore.New()
	if err != nil {
		t.Fatalf("generate state: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, callbackRequest(state, "some-code"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body: %s", rec.Code, rec.Body.String())
	}
}

// sessionCookieFromResponse extracts the skills_server_session cookie set
// on rec, failing the test if it's missing.
func sessionCookieFromResponse(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName {
			return c
		}
	}
	t.Fatalf("expected a %s cookie to be set, got: %v", SessionCookieName, rec.Result().Cookies())
	return nil
}

// loginAsSession drives a full GoogleCallback and returns the resulting
// session cookie, ready to attach to subsequent requests.
func loginAsSession(t *testing.T, h *Handler, mux http.Handler, email string, role store.SessionRole) *http.Cookie {
	t.Helper()
	adminEmails := h.AdminEmails
	submitterEmails := h.SubmitterEmails
	if role == store.SessionRoleAdmin {
		adminEmails = []string{email}
	} else {
		submitterEmails = nil // any verified email is a submitter
	}
	h.AdminEmails = adminEmails
	h.SubmitterEmails = submitterEmails
	h.IDTokenVerifier = &fakeIDTokenVerifier{claims: &auth.IDTokenClaims{Email: email, EmailVerified: true}}

	state, err := h.StateStore.New()
	if err != nil {
		t.Fatalf("generate state: %v", err)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, callbackRequest(state, "some-code"))
	if rec.Code != http.StatusOK {
		t.Fatalf("callback status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	return sessionCookieFromResponse(t, rec)
}

func TestSessionCookie_AuthenticatesProtectedRoutesLikeTokens(t *testing.T) {
	h := testGoogleAuthHandler(t, nil, nil, nil)
	mux := NewMux(h)

	adminCookie := loginAsSession(t, h, mux, "admin@example.com", store.SessionRoleAdmin)

	// The admin session must authenticate an admin-only route exactly like
	// X-Admin-Token does today.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/submissions", nil)
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin route with admin session: status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
}

func TestSessionCookie_AdminSessionSatisfiesSubmitterRoutes(t *testing.T) {
	h := testGoogleAuthHandler(t, nil, nil, nil)
	mux := NewMux(h)

	adminCookie := loginAsSession(t, h, mux, "admin@example.com", store.SessionRoleAdmin)

	archive := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	req := submissionRequest(t, "", map[string]string{
		"skill_id":     "my-skill",
		"display_name": "Cookie Admin Submit",
		"submitter":    "ignored",
	}, archive)
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("submitter route with admin session: status = %d, want 201, body: %s", rec.Code, rec.Body.String())
	}
}

func TestSessionCookie_SubmitterSessionRejectedOnAdminRoutes(t *testing.T) {
	h := testGoogleAuthHandler(t, nil, nil, nil)
	mux := NewMux(h)

	submitterCookie := loginAsSession(t, h, mux, "submitter@example.com", store.SessionRoleSubmitter)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/submissions", nil)
	req.AddCookie(submitterCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("admin route with submitter session: status = %d, want 401, body: %s", rec.Code, rec.Body.String())
	}
}

func TestSessionCookie_ExpiredSessionRejected(t *testing.T) {
	h, _ := testHandler(t)
	mux := NewMux(h)

	sess := store.Session{
		ID:        "expired-session-id",
		Email:     "admin@example.com",
		Role:      store.SessionRoleAdmin,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	if err := h.Store.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("seed expired session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/submissions", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sess.ID})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body: %s", rec.Code, rec.Body.String())
	}
}

func TestLogout_InvalidatesSession(t *testing.T) {
	h := testGoogleAuthHandler(t, nil, nil, nil)
	mux := NewMux(h)

	adminCookie := loginAsSession(t, h, mux, "admin@example.com", store.SessionRoleAdmin)

	// Sanity check: it works before logout.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/submissions", nil)
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("before logout: status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	logoutReq.AddCookie(adminCookie)
	logoutRec := httptest.NewRecorder()
	mux.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, want 200, body: %s", logoutRec.Code, logoutRec.Body.String())
	}

	// Same cookie, after logout, must now be rejected.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/submissions", nil)
	req.AddCookie(adminCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("after logout: status = %d, want 401, body: %s", rec.Code, rec.Body.String())
	}
}

func TestLogout_NoSessionCookieStillReturns200(t *testing.T) {
	h, _ := testHandler(t)
	mux := NewMux(h)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateSubmission_SessionEmailOverridesClientSuppliedSubmitter(t *testing.T) {
	h := testGoogleAuthHandler(t, nil, nil, nil)
	mux := NewMux(h)

	submitterCookie := loginAsSession(t, h, mux, "real.person@example.com", store.SessionRoleSubmitter)

	archive := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	req := submissionRequest(t, "", map[string]string{
		"skill_id":     "my-skill",
		"display_name": "Spoof Attempt",
		"submitter":    "someone-else-entirely",
	}, archive)
	req.AddCookie(submitterCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body: %s", rec.Code, rec.Body.String())
	}

	resp := decodeJSON[map[string]string](t, rec.Body)
	sub, err := h.Store.GetSubmission(context.Background(), resp["id"])
	if err != nil {
		t.Fatalf("get submission: %v", err)
	}
	if sub.Submitter != "real.person@example.com" {
		t.Errorf("submitter = %q, want the session's authenticated email, not the client-supplied field", sub.Submitter)
	}
}

func TestGoogleLogin_RedirectsToGoogleWithState(t *testing.T) {
	h := testGoogleAuthHandler(t, nil, nil, nil)
	mux := NewMux(h)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/google/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302, body: %s", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatalf("expected a Location header redirecting to google")
	}
}

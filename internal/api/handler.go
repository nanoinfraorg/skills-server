// Package api implements the skills-server HTTP surface: submission intake,
// admin moderation, the publish pipeline trigger, and the public read-only
// catalog. It depends only on internal/store for persistence and a small
// Publisher interface for the GitHub publish step, so handlers can be
// exercised in tests with an in-memory SQLite store and a fake publisher.
package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/nanoinfraorg/skills-server/internal/auth"
	"github.com/nanoinfraorg/skills-server/internal/github"
	"github.com/nanoinfraorg/skills-server/internal/scan"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// SessionCookieName is the HTTP-only cookie set on a successful
// GET /auth/google/callback and cleared on POST /auth/logout. Its value is
// a session id looked up via Handler.Store.GetSession.
const SessionCookieName = "skills_server_session"

// sessionEmailContextKey is the request-context key GoogleCallback-derived
// (i.e. session-cookie) authentication stashes the authenticated email
// under, so downstream handlers -- currently CreateSubmission -- can make
// the authenticated identity win over any client-supplied form field.
type contextKey string

const sessionEmailContextKey contextKey = "skills_server_session_email"

// withSessionEmail returns a copy of r carrying email in its context, for
// handlers reached via a session-cookie-authenticated request.
func withSessionEmail(r *http.Request, email string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionEmailContextKey, email))
}

// sessionEmailFromContext returns the authenticated email stashed by
// withSessionEmail, if any.
func sessionEmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(sessionEmailContextKey).(string)
	return email, ok && email != ""
}

// Publisher commits a skill's validated files to the durable GitHub artifact
// store. internal/github.Client implements this; tests inject a fake.
type Publisher interface {
	PublishFiles(ctx context.Context, skillID string, files []github.File, commitMessage string) error
}

// Handler holds every dependency the HTTP handlers need. All fields are
// required; Handler is not usable with its zero value.
type Handler struct {
	Store          *store.Store
	Publisher      Publisher
	Logger         *slog.Logger
	SubmitterToken string
	AdminToken     string
	SubmissionsDir string
	PublishedDir   string
	GitHubRepo     string
	// ScanConfig configures the security scan shield's optional LLM
	// classification pass (internal/scan). Deterministic checks always run
	// regardless of this being the zero value.
	ScanConfig scan.Config
	// GoogleOAuthConfig, IDTokenVerifier, and StateStore drive the "Sign in
	// with Google" flow (GET /auth/google/login, GET
	// /auth/google/callback): building the consent-screen redirect,
	// verifying the returned ID token, and tracking single-use OAuth
	// "state" values, respectively. See internal/auth.
	GoogleOAuthConfig *oauth2.Config
	IDTokenVerifier   auth.IDTokenVerifier
	StateStore        *auth.StateStore
	// AdminEmails and SubmitterEmails are the allowlists GoogleCallback
	// checks a verified Google email against to compute the new session's
	// role (internal/auth.DetermineRole). Both are expected pre-normalized
	// (lowercased, trimmed), as internal/config.Load produces them.
	AdminEmails     []string
	SubmitterEmails []string
	// SessionTTL is how long a Google-OAuth-issued session cookie remains
	// valid.
	SessionTTL time.Duration
	// PublicBaseURL, when non-empty, is the externally-visible scheme+host
	// this server is reachable at (see internal/config.Config.PublicBaseURL
	// for the full reverse-proxy rationale). GoogleCallback uses its scheme
	// -- not the inbound request's r.TLS -- to decide the session cookie's
	// Secure attribute, when set.
	PublicBaseURL string
	// Now returns the current time; overridable in tests for deterministic
	// timestamps.
	Now func() time.Time
}

// secureCookie reports whether a session cookie set in response to r should
// carry the Secure attribute: PublicBaseURL's scheme is authoritative when
// configured (correct behind a TLS-terminating reverse proxy, where r.TLS is
// always nil regardless of what the browser used); otherwise it falls back
// to the request's own r.TLS, which is only correct when this process
// terminates TLS itself or is genuinely being accessed over plain HTTP.
func (h *Handler) secureCookie(r *http.Request) bool {
	if h.PublicBaseURL != "" {
		return strings.HasPrefix(h.PublicBaseURL, "https://")
	}
	return r.TLS != nil
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// NewMux builds the full skills-server route table.
func NewMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", h.HealthCheck)

	mux.HandleFunc("GET /auth/google/login", h.GoogleLogin)
	mux.HandleFunc("GET /auth/google/callback", h.GoogleCallback)
	mux.HandleFunc("POST /auth/logout", h.Logout)

	mux.HandleFunc("POST /api/v1/submissions", h.requireSubmitterAuth(h.CreateSubmission))

	mux.HandleFunc("GET /api/v1/admin/submissions", h.requireAdminAuth(h.ListSubmissions))
	mux.HandleFunc("POST /api/v1/admin/submissions/{id}/approve", h.requireAdminAuth(h.ApproveSubmission))
	mux.HandleFunc("POST /api/v1/admin/submissions/{id}/reject", h.requireAdminAuth(h.RejectSubmission))
	mux.HandleFunc("POST /api/v1/admin/skills/{id}/rescan", h.requireAdminAuth(h.RescanSkill))

	mux.HandleFunc("POST /api/v1/scan/{id}", h.requireEitherAuth(h.TriggerScan))
	mux.HandleFunc("GET /api/v1/scan/{id}", h.requireEitherAuth(h.GetScan))

	mux.HandleFunc("GET /api/v1/search", h.SearchSkills)
	mux.HandleFunc("GET /api/v1/trending", h.TrendingSkills)
	mux.HandleFunc("GET /api/v1/skills/{id}", h.GetSkill)
	mux.HandleFunc("GET /api/v1/skills/{id}/download", h.DownloadSkill)
	mux.HandleFunc("GET /api/v1/skills/{id}/versions", h.ListSkillVersions)
	mux.HandleFunc("GET /api/v1/skills/{id}/versions/{version}", h.GetSkillVersion)

	return mux
}

// HealthCheck is an unauthenticated liveness probe.
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// requireSubmitterAuth wraps next, accepting either a valid
// X-Submitter-Token header (existing behavior, unchanged) or a session
// cookie (from "Sign in with Google") whose role is sufficient for
// submitter-level access -- submitter or admin, since admin is the more
// privileged role. On a session-authenticated request, the authenticated
// email is stashed in the request context (see withSessionEmail) so
// CreateSubmission can make it override any client-supplied submitter
// field.
func (h *Handler) requireSubmitterAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if constantTimeEquals(r.Header.Get("X-Submitter-Token"), h.SubmitterToken) {
			next(w, r)
			return
		}
		if sess := h.sessionFromRequest(r); sess != nil && store.RoleSatisfies(sess.Role, store.SessionRoleSubmitter) {
			next(w, withSessionEmail(r, sess.Email))
			return
		}
		writeError(w, http.StatusUnauthorized, "missing or invalid X-Submitter-Token")
	}
}

// requireAdminAuth wraps next, accepting either a valid X-Admin-Token
// header (existing behavior, unchanged) or a session cookie whose role is
// admin. A submitter-role session is not sufficient here.
func (h *Handler) requireAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if constantTimeEquals(r.Header.Get("X-Admin-Token"), h.AdminToken) {
			next(w, r)
			return
		}
		if sess := h.sessionFromRequest(r); sess != nil && store.RoleSatisfies(sess.Role, store.SessionRoleAdmin) {
			next(w, withSessionEmail(r, sess.Email))
			return
		}
		writeError(w, http.StatusUnauthorized, "missing or invalid X-Admin-Token")
	}
}

// requireEitherAuth wraps next, accepting a valid X-Submitter-Token, a
// valid X-Admin-Token header, or any valid (unexpired) session cookie of
// either role. Used by the scan-preview endpoints, which a submitter
// previewing their own pending submission's shield verdict, or an admin
// doing the same before deciding, should both be able to call.
func (h *Handler) requireEitherAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		submitterOK := constantTimeEquals(r.Header.Get("X-Submitter-Token"), h.SubmitterToken)
		adminOK := constantTimeEquals(r.Header.Get("X-Admin-Token"), h.AdminToken)
		if submitterOK || adminOK {
			next(w, r)
			return
		}
		if sess := h.sessionFromRequest(r); sess != nil {
			next(w, withSessionEmail(r, sess.Email))
			return
		}
		writeError(w, http.StatusUnauthorized, "missing or invalid X-Submitter-Token or X-Admin-Token")
	}
}

// sessionFromRequest looks up the session named by SessionCookieName, if
// any, returning nil if the cookie is absent or the session is missing or
// expired (store.Store.GetSession already folds "expired" into
// ErrNotFound).
func (h *Handler) sessionFromRequest(r *http.Request) *store.Session {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}
	sess, err := h.Store.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil
	}
	return sess
}

func constantTimeEquals(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

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
	"time"

	"github.com/nanoinfraorg/skills-server/internal/github"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

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
	// Now returns the current time; overridable in tests for deterministic
	// timestamps.
	Now func() time.Time
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

	mux.HandleFunc("POST /api/v1/submissions", h.requireSubmitterAuth(h.CreateSubmission))

	mux.HandleFunc("GET /api/v1/admin/submissions", h.requireAdminAuth(h.ListSubmissions))
	mux.HandleFunc("POST /api/v1/admin/submissions/{id}/approve", h.requireAdminAuth(h.ApproveSubmission))
	mux.HandleFunc("POST /api/v1/admin/submissions/{id}/reject", h.requireAdminAuth(h.RejectSubmission))

	mux.HandleFunc("GET /api/v1/search", h.SearchSkills)
	mux.HandleFunc("GET /api/v1/trending", h.TrendingSkills)
	mux.HandleFunc("GET /api/v1/skills/{id}", h.GetSkill)
	mux.HandleFunc("GET /api/v1/skills/{id}/download", h.DownloadSkill)

	return mux
}

// HealthCheck is an unauthenticated liveness probe.
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// requireSubmitterAuth wraps next, rejecting requests whose X-Submitter-Token
// header does not match the configured shared token.
func (h *Handler) requireSubmitterAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !constantTimeEquals(r.Header.Get("X-Submitter-Token"), h.SubmitterToken) {
			writeError(w, http.StatusUnauthorized, "missing or invalid X-Submitter-Token")
			return
		}
		next(w, r)
	}
}

// requireAdminAuth wraps next, rejecting requests whose X-Admin-Token header
// does not match the configured shared token.
func (h *Handler) requireAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !constantTimeEquals(r.Header.Get("X-Admin-Token"), h.AdminToken) {
			writeError(w, http.StatusUnauthorized, "missing or invalid X-Admin-Token")
			return
		}
		next(w, r)
	}
}

func constantTimeEquals(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

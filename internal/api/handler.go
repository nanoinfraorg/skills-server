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
	"github.com/nanoinfraorg/skills-server/internal/scan"
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
	// ScanConfig configures the security scan shield's optional LLM
	// classification pass (internal/scan). Deterministic checks always run
	// regardless of this being the zero value.
	ScanConfig scan.Config
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

// requireEitherAuth wraps next, accepting either a valid X-Submitter-Token
// or a valid X-Admin-Token header. Used by the scan-preview endpoints,
// which a submitter previewing their own pending submission's shield
// verdict, or an admin doing the same before deciding, should both be able
// to call.
func (h *Handler) requireEitherAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		submitterOK := constantTimeEquals(r.Header.Get("X-Submitter-Token"), h.SubmitterToken)
		adminOK := constantTimeEquals(r.Header.Get("X-Admin-Token"), h.AdminToken)
		if !submitterOK && !adminOK {
			writeError(w, http.StatusUnauthorized, "missing or invalid X-Submitter-Token or X-Admin-Token")
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

// Package web implements the server-rendered HTML UI on top of the
// existing JSON API (internal/api) and its Google OAuth session system: a
// home page, a public skills directory and detail/version-history pages, a
// submit-a-skill form, a "my submissions" page, and an admin moderation
// dashboard. It is stdlib html/template plus a single vendored classless
// CSS file (see static/) -- no JS framework, no build step, no CDN
// dependency (see docs/web-ui.md).
//
// Every page and form action here is a thin HTTP-shaped wrapper around
// logic that already exists in internal/api and internal/store: the same
// *api.Handler.Store queries the JSON API's read endpoints use, and the
// same *api.Handler "Core" functions (CreateSubmissionCore,
// ApproveSubmissionCore, RejectSubmissionCore, RescanSkillCore) the JSON
// API's write endpoints call. Nothing here re-implements validation,
// publishing, scanning, or persistence.
package web

import (
	"bytes"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/nanoinfraorg/skills-server/internal/api"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// Handler holds every dependency the HTML handlers need.
type Handler struct {
	// API is the same Handler the JSON API (internal/api) uses. The HTML
	// handlers reach through it for store queries (h.API.Store...) and the
	// shared "Core" business-logic functions -- see the package doc
	// comment.
	API    *api.Handler
	Logger *slog.Logger

	templates map[string]*template.Template
}

// New builds a Handler with its templates parsed and ready. api must be
// fully configured (same instance passed to api.NewMux).
func New(apiHandler *api.Handler, logger *slog.Logger) *Handler {
	return &Handler{API: apiHandler, Logger: logger, templates: loadTemplates()}
}

// Register wires every HTML route onto mux, alongside (not instead of) the
// JSON API's own routes -- see cmd/skills-server/main.go, which registers
// both api.NewMux's routes and these onto one *http.ServeMux. There is no
// path collision to resolve: the JSON API lives entirely under /api/v1/*
// and /auth/*, and this package takes every other route.
func Register(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("GET /{$}", h.Home)

	mux.HandleFunc("GET /skills", h.Skills)
	mux.HandleFunc("GET /skills/{id}", h.SkillDetail)

	mux.HandleFunc("GET /submit", h.SubmitForm)
	mux.HandleFunc("POST /submit", h.SubmitCreate)

	mux.HandleFunc("GET /my/submissions", h.MySubmissions)

	mux.HandleFunc("GET /admin", h.Admin)
	mux.HandleFunc("POST /admin/submissions/{id}/approve", h.AdminApprove)
	mux.HandleFunc("POST /admin/submissions/{id}/reject", h.AdminReject)
	mux.HandleFunc("POST /admin/skills/{id}/rescan", h.AdminRescan)

	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFiles)))
}

// NavUser is the current session's identity, as shown in every page's nav
// bar (see layout.html). A nil *NavUser means "not signed in".
type NavUser struct {
	Email   string
	Role    store.SessionRole
	IsAdmin bool
}

func navUser(sess *store.Session) *NavUser {
	if sess == nil {
		return nil
	}
	return &NavUser{Email: sess.Email, Role: sess.Role, IsAdmin: sess.Role == store.SessionRoleAdmin}
}

// basePage is embedded (by value) in every page's template data, giving
// every template access to .Title and .User regardless of what
// page-specific fields ride alongside it.
type basePage struct {
	Title string
	User  *NavUser
}

// sessionFromRequest looks up the session named by the same cookie
// internal/api's GoogleCallback sets (api.SessionCookieName), returning nil
// if it's absent, unknown, or expired -- store.Store.GetSession already
// folds "expired" into ErrNotFound. This mirrors api.Handler's own
// unexported sessionFromRequest exactly, but is re-declared here (rather
// than exported from internal/api) since it's a two-line lookup against
// already-exported pieces (api.SessionCookieName, h.API.Store.GetSession),
// not business logic worth threading a shared function through.
func (h *Handler) sessionFromRequest(r *http.Request) *store.Session {
	cookie, err := r.Cookie(api.SessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}
	sess, err := h.API.Store.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil
	}
	return sess
}

// requireSession gates a page behind an authenticated session satisfying
// at least minRole (store.RoleSatisfies -- the same admin-satisfies-
// submitter hierarchy the JSON API's requireAdminAuth/requireSubmitterAuth
// enforce). A request with no session is redirected to Google login (there
// is no separate HTML login form; signing in with Google *is* the login
// flow -- see docs/authentication.md). A session that exists but is
// insufficiently privileged renders a 403 page instead: redirecting an
// already-logged-in submitter to "log in" again would be a confusing loop.
func (h *Handler) requireSession(w http.ResponseWriter, r *http.Request, minRole store.SessionRole) (*store.Session, bool) {
	sess := h.sessionFromRequest(r)
	if sess == nil {
		http.Redirect(w, r, "/auth/google/login", http.StatusFound)
		return nil, false
	}
	if !store.RoleSatisfies(sess.Role, minRole) {
		h.renderMessage(w, http.StatusForbidden, sess, "Forbidden", "Your account does not have access to this page.")
		return nil, false
	}
	return sess, true
}

// render executes the named page's template (see loadTemplates) into w. The
// page is buffered into memory first so a template execution error (a bug,
// not a user-facing condition) can still produce a clean 500 instead of a
// half-written page.
func (h *Handler) render(w http.ResponseWriter, status int, page string, data any) {
	tmpl, ok := h.templates[page]
	if !ok {
		h.Logger.Error("render: unknown template", "page", page)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout.html", data); err != nil {
		h.Logger.Error("render template", "page", page, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// messagePage is the data shape for the generic single-message page
// (message.html), used for 403s, 404s, and other simple informational
// responses that don't need a dedicated template.
type messagePage struct {
	basePage
	Message string
}

func (h *Handler) renderMessage(w http.ResponseWriter, status int, sess *store.Session, title, message string) {
	h.render(w, status, "message.html", messagePage{
		basePage: basePage{Title: title, User: navUser(sess)},
		Message:  message,
	})
}

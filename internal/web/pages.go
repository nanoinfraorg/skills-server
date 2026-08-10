package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/api"
	"github.com/nanoinfraorg/skills-server/internal/pipeline"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

// directoryLimit caps how many skills the directory page shows for a
// default (no query) listing or a search's results -- mirrors
// internal/api's own trendingLimit constant for the JSON
// /api/v1/search and /api/v1/trending endpoints (unexported there, so
// re-declared here rather than shared; it's a display cap, not business
// logic, and both packages derive it from nothing more meaningful than
// "a reasonable page size").
const directoryLimit = 20

// maxUploadBytes caps the whole multipart submit-form request body,
// mirroring internal/api's own identically-named, identically-computed var
// -- both are derived directly from the exported pipeline.MaxArchiveBytes,
// so a change there is picked up by both without this package needing to
// reach into api's unexported var.
var maxUploadBytes = pipeline.MaxArchiveBytes + 1<<20

// Home renders the "/" page: a brief description and "Sign in with
// Google" for a signed-out visitor, or a short welcome plus links to the
// rest of the UI (including "Admin dashboard" only for an admin session)
// for a signed-in one.
func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	sess := h.sessionFromRequest(r)
	h.render(w, http.StatusOK, "home.html", basePage{Title: "skills-server", User: navUser(sess)})
}

// skillsPageData is the data shape for skills.html (the public directory).
type skillsPageData struct {
	basePage
	Query    string
	Skills   []store.SkillDetail
	Trending bool // true when Query is empty and Skills is the default trending listing
}

// Skills renders "/skills": a search box, and either search results for
// ?q=... or a default trending listing when there's no query. Both use the
// exact store queries the JSON API's own GET /api/v1/search and
// GET /api/v1/trending call.
func (h *Handler) Skills(w http.ResponseWriter, r *http.Request) {
	sess := h.sessionFromRequest(r)
	query := strings.TrimSpace(r.URL.Query().Get("q"))

	var (
		skills []store.SkillDetail
		err    error
	)
	if query != "" {
		skills, err = h.API.Store.SearchSkills(r.Context(), query, directoryLimit)
	} else {
		skills, err = h.API.Store.TrendingSkills(r.Context(), directoryLimit)
	}
	if err != nil {
		h.Logger.Error("list skills for directory page", "error", err, "query", query)
		h.renderMessage(w, http.StatusInternalServerError, sess, "Error", "Could not load skills.")
		return
	}

	h.render(w, http.StatusOK, "skills.html", skillsPageData{
		basePage: basePage{Title: "Browse skills", User: navUser(sess)},
		Query:    query,
		Skills:   skills,
		Trending: query == "",
	})
}

// skillDetailPageData is the data shape for skill_detail.html.
type skillDetailPageData struct {
	basePage
	Skill    store.SkillDetail
	Versions []store.SkillVersion
}

// SkillDetail renders "/skills/{id}": the current version's description,
// download link, and full version history, all from the same store
// queries GET /api/v1/skills/{id} and GET /api/v1/skills/{id}/versions
// use. A quarantined current version is shown, clearly marked, exactly
// like the JSON API's own detail endpoint does -- not hidden.
func (h *Handler) SkillDetail(w http.ResponseWriter, r *http.Request) {
	sess := h.sessionFromRequest(r)
	id := r.PathValue("id")

	skill, err := h.API.Store.GetSkillDetail(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		h.renderMessage(w, http.StatusNotFound, sess, "Not found", "No such skill.")
		return
	}
	if err != nil {
		h.Logger.Error("get skill detail", "error", err, "skill_id", id)
		h.renderMessage(w, http.StatusInternalServerError, sess, "Error", "Could not load this skill.")
		return
	}

	versions, err := h.API.Store.ListSkillVersions(r.Context(), id)
	if err != nil {
		h.Logger.Error("list skill versions", "error", err, "skill_id", id)
		h.renderMessage(w, http.StatusInternalServerError, sess, "Error", "Could not load this skill's version history.")
		return
	}

	h.render(w, http.StatusOK, "skill_detail.html", skillDetailPageData{
		basePage: basePage{Title: skill.DisplayName, User: navUser(sess)},
		Skill:    *skill,
		Versions: versions,
	})
}

// submitPageData is the data shape for submit.html.
type submitPageData struct {
	basePage
	CSRFToken   string
	SkillID     string
	DisplayName string
	Error       string
}

// SubmitForm renders "/submit" (GET): the upload form. Requires a
// submitter-or-admin session (store.SessionRoleSubmitter); an unauthenticated
// visitor is redirected to Google login, since there's no separate
// "sign up" flow -- the first Google login already grants submitter access
// per the permissive-by-default SUBMITTER_EMAILS policy (see
// docs/authentication.md).
func (h *Handler) SubmitForm(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.requireSession(w, r, store.SessionRoleSubmitter)
	if !ok {
		return
	}
	h.renderSubmitForm(w, http.StatusOK, sess, submitPageData{})
}

func (h *Handler) renderSubmitForm(w http.ResponseWriter, status int, sess *store.Session, data submitPageData) {
	data.basePage = basePage{Title: "Submit a skill", User: navUser(sess)}
	data.CSRFToken = sess.CSRFToken
	h.render(w, status, "submit.html", data)
}

// SubmitCreate handles "/submit" (POST): validates and creates the
// submission via api.Handler.CreateSubmissionCore -- the exact same
// validate-then-store logic the JSON API's POST /api/v1/submissions uses,
// just fed from an HTML multipart form instead of a client's own multipart
// request. The submitter is always the logged-in session's verified email,
// never a form field (there is no submitter field on this form at all,
// matching the override behavior CreateSubmission already applies to a
// session-authenticated JSON request).
//
// On success, redirects to "/my/submissions" so the submitter immediately
// sees their new pending submission. On failure, re-renders the form with
// the same inline error text the JSON API would have returned, at the same
// HTTP status.
func (h *Handler) SubmitCreate(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.requireSession(w, r, store.SessionRoleSubmitter)
	if !ok {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		h.renderSubmitForm(w, http.StatusBadRequest, sess, submitPageData{
			Error: "request body is not a valid multipart form or exceeds the size limit",
		})
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	skillID := strings.TrimSpace(r.FormValue("skill_id"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))

	if !validCSRF(r, sess) {
		http.Error(w, "invalid or missing csrf token", http.StatusForbidden)
		return
	}

	file, _, err := r.FormFile("archive")
	if err != nil {
		h.renderSubmitForm(w, http.StatusBadRequest, sess, submitPageData{
			SkillID: skillID, DisplayName: displayName,
			Error: "a .zip archive is required",
		})
		return
	}
	defer file.Close()

	_, subErr := h.API.CreateSubmissionCore(r.Context(), api.SubmissionInput{
		SkillID:     skillID,
		DisplayName: displayName,
		Submitter:   sess.Email,
		Archive:     file,
	})
	if subErr != nil {
		h.renderSubmitForm(w, subErr.Status, sess, submitPageData{
			SkillID: skillID, DisplayName: displayName, Error: subErr.Message,
		})
		return
	}

	http.Redirect(w, r, "/my/submissions", http.StatusSeeOther)
}

// submissionRow is a template-friendly view of a store.Submission, used by
// both my_submissions.html and admin.html. store.Submission.RejectionReason
// is a *string (nil when there isn't one yet); html/template's default
// printing of a pointer-to-string prints its address, not its contents, so
// this flattens it to a plain string (empty when nil) before it ever
// reaches a template.
type submissionRow struct {
	ID              string
	SkillID         string
	DisplayName     string
	Submitter       string
	Status          store.SubmissionStatus
	RejectionReason string
	CreatedAt       time.Time
}

func toSubmissionRow(sub store.Submission) submissionRow {
	row := submissionRow{
		ID: sub.ID, SkillID: sub.SkillID, DisplayName: sub.DisplayName,
		Submitter: sub.Submitter, Status: sub.Status, CreatedAt: sub.CreatedAt,
	}
	if sub.RejectionReason != nil {
		row.RejectionReason = *sub.RejectionReason
	}
	return row
}

func toSubmissionRows(subs []store.Submission) []submissionRow {
	out := make([]submissionRow, 0, len(subs))
	for _, sub := range subs {
		out = append(out, toSubmissionRow(sub))
	}
	return out
}

// mySubmissionsPageData is the data shape for my_submissions.html.
type mySubmissionsPageData struct {
	basePage
	Submissions []submissionRow
}

// MySubmissions renders "/my/submissions": the logged-in session's own
// submissions and their status, via the new
// store.Store.ListSubmissionsBySubmitter query (added for this page --
// nothing existing already listed a submitter's own history).
func (h *Handler) MySubmissions(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.requireSession(w, r, store.SessionRoleSubmitter)
	if !ok {
		return
	}
	subs, err := h.API.Store.ListSubmissionsBySubmitter(r.Context(), sess.Email)
	if err != nil {
		h.Logger.Error("list submissions by submitter", "error", err, "email", sess.Email)
		h.renderMessage(w, http.StatusInternalServerError, sess, "Error", "Could not load your submissions.")
		return
	}
	h.render(w, http.StatusOK, "my_submissions.html", mySubmissionsPageData{
		basePage:    basePage{Title: "My submissions", User: navUser(sess)},
		Submissions: toSubmissionRows(subs),
	})
}

// outcomeBanner is a one-shot result banner shown at the top of the admin
// dashboard right after an approve/reject/rescan action redirects back to
// it (see redirectWithOutcome) -- carried in the redirect's query string
// rather than server-side state, since there's no session-scoped flash
// message store in this codebase and one action's outcome doesn't need to
// survive more than the one redirect.
type outcomeBanner struct {
	Kind    string // "published", "rejected", "rescanned", or "error"
	Message string
}

func outcomeFromQuery(q url.Values) *outcomeBanner {
	switch q.Get("outcome") {
	case "published":
		return &outcomeBanner{Kind: "published", Message: fmt.Sprintf(
			"Published %s v%s (scan verdict: %s).", q.Get("skill_id"), q.Get("version"), q.Get("scan_verdict"))}
	case "rejected":
		return &outcomeBanner{Kind: "rejected", Message: "Rejected: " + q.Get("reason")}
	case "rescanned":
		status := "still published"
		if q.Get("quarantined") == "true" {
			status = "quarantined"
		}
		return &outcomeBanner{Kind: "rescanned", Message: fmt.Sprintf(
			"Rescanned %s (verdict: %s) -- %s.", q.Get("skill_id"), q.Get("verdict"), status)}
	case "error":
		return &outcomeBanner{Kind: "error", Message: q.Get("message")}
	default:
		return nil
	}
}

func redirectWithOutcome(w http.ResponseWriter, r *http.Request, q url.Values) {
	http.Redirect(w, r, "/admin?"+q.Encode(), http.StatusSeeOther)
}

// adminSubmissionRow pairs a pending submission (flattened via
// toSubmissionRow -- see its doc comment) with its latest scan report (if
// any has run yet), for the dashboard's "view scan reports" requirement.
type adminSubmissionRow struct {
	submissionRow
	Scan *store.Scan
}

// adminPageData is the data shape for admin.html.
type adminPageData struct {
	basePage
	CSRFToken string
	Outcome   *outcomeBanner
	Pending   []adminSubmissionRow
	Skills    []store.SkillDetail
}

// Admin renders "/admin": pending submissions (each with its latest scan
// report, if one has run) with approve/reject actions, and every published
// skill with a rescan action and its quarantine status. Requires an admin
// session -- a submitter-role session gets a 403 page, matching the JSON
// API's own admin-only role precedence (store.RoleSatisfies).
func (h *Handler) Admin(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.requireSession(w, r, store.SessionRoleAdmin)
	if !ok {
		return
	}
	ctx := r.Context()

	pending, err := h.API.Store.ListSubmissions(ctx, string(store.StatusPending))
	if err != nil {
		h.Logger.Error("list pending submissions", "error", err)
		h.renderMessage(w, http.StatusInternalServerError, sess, "Error", "Could not load pending submissions.")
		return
	}
	rows := make([]adminSubmissionRow, 0, len(pending))
	for _, sub := range pending {
		row := adminSubmissionRow{submissionRow: toSubmissionRow(sub)}
		if sc, err := h.API.Store.GetLatestScan(ctx, store.ScanTargetSubmission, sub.ID); err == nil {
			row.Scan = sc
		} else if !errors.Is(err, store.ErrNotFound) {
			h.Logger.Error("get latest scan for pending submission", "error", err, "submission_id", sub.ID)
		}
		rows = append(rows, row)
	}

	skills, err := h.API.Store.ListAllSkillDetails(ctx)
	if err != nil {
		h.Logger.Error("list all skill details", "error", err)
		h.renderMessage(w, http.StatusInternalServerError, sess, "Error", "Could not load published skills.")
		return
	}

	h.render(w, http.StatusOK, "admin.html", adminPageData{
		basePage:  basePage{Title: "Admin dashboard", User: navUser(sess)},
		CSRFToken: sess.CSRFToken,
		Outcome:   outcomeFromQuery(r.URL.Query()),
		Pending:   rows,
		Skills:    skills,
	})
}

// AdminApprove handles "/admin/submissions/{id}/approve" (POST): CSRF-checks
// the form, then calls the exact same api.Handler.ApproveSubmissionCore the
// JSON API's POST /api/v1/admin/submissions/{id}/approve calls, and
// redirects back to "/admin" with the outcome (published+version+verdict,
// or rejected+reason) as a query-string banner.
func (h *Handler) AdminApprove(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.requireSession(w, r, store.SessionRoleAdmin)
	if !ok {
		return
	}
	if !validCSRF(r, sess) {
		http.Error(w, "invalid or missing csrf token", http.StatusForbidden)
		return
	}

	outcome, subErr := h.API.ApproveSubmissionCore(r.Context(), r.PathValue("id"))
	if subErr != nil {
		redirectWithOutcome(w, r, url.Values{"outcome": {"error"}, "message": {subErr.Message}})
		return
	}
	if outcome.Published {
		redirectWithOutcome(w, r, url.Values{
			"outcome": {"published"}, "skill_id": {outcome.SkillID},
			"version": {strconv.FormatInt(outcome.Version, 10)}, "scan_verdict": {string(outcome.ScanVerdict)},
		})
		return
	}
	redirectWithOutcome(w, r, url.Values{"outcome": {"rejected"}, "reason": {outcome.Reason}})
}

// AdminReject handles "/admin/submissions/{id}/reject" (POST): CSRF-checks
// the form, then calls the exact same api.Handler.RejectSubmissionCore the
// JSON API's POST /api/v1/admin/submissions/{id}/reject calls, with the
// reason taken from the form field of the same name instead of a JSON
// body.
func (h *Handler) AdminReject(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.requireSession(w, r, store.SessionRoleAdmin)
	if !ok {
		return
	}
	if !validCSRF(r, sess) {
		http.Error(w, "invalid or missing csrf token", http.StatusForbidden)
		return
	}

	reason, subErr := h.API.RejectSubmissionCore(r.Context(), r.PathValue("id"), r.FormValue("reason"))
	if subErr != nil {
		redirectWithOutcome(w, r, url.Values{"outcome": {"error"}, "message": {subErr.Message}})
		return
	}
	redirectWithOutcome(w, r, url.Values{"outcome": {"rejected"}, "reason": {reason}})
}

// AdminRescan handles "/admin/skills/{id}/rescan" (POST): CSRF-checks the
// form, then calls the exact same api.Handler.RescanSkillCore the JSON
// API's POST /api/v1/admin/skills/{id}/rescan calls.
func (h *Handler) AdminRescan(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.requireSession(w, r, store.SessionRoleAdmin)
	if !ok {
		return
	}
	if !validCSRF(r, sess) {
		http.Error(w, "invalid or missing csrf token", http.StatusForbidden)
		return
	}

	id := r.PathValue("id")
	dto, quarantined, subErr := h.API.RescanSkillCore(r.Context(), id)
	if subErr != nil {
		redirectWithOutcome(w, r, url.Values{"outcome": {"error"}, "message": {subErr.Message}})
		return
	}
	redirectWithOutcome(w, r, url.Values{
		"outcome": {"rescanned"}, "skill_id": {id}, "verdict": {dto.Verdict},
		"quarantined": {strconv.FormatBool(quarantined)},
	})
}

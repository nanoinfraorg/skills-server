package web

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/api"
	"github.com/nanoinfraorg/skills-server/internal/pipeline"
	"github.com/nanoinfraorg/skills-server/internal/scan"
	"github.com/nanoinfraorg/skills-server/internal/store"
	"github.com/nanoinfraorg/skills-server/internal/virustotal"
)

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
	h.render(w, http.StatusOK, "home.html", basePage{User: navUser(sess)})
}

// directoryPageSize is how many rows the public directory shows per page.
const directoryPageSize = 50

// skillsSortLink is one clickable column heading. The URL is assembled here
// rather than in the template: a template that concatenates query strings is
// where escaping bugs live.
type skillsSortLink struct {
	Key    string
	Label  string
	URL    string
	Active bool
	Desc   bool // the direction currently in effect, only meaningful when Active
}

// skillsPageData is the data shape for skills.html (the public directory).
type skillsPageData struct {
	basePage
	Query string
	// Kind is the active filter, empty for every kind. Kinds are the tabs.
	Kind     string
	Kinds    []skillsKindLink
	Skills   []store.SkillDetail
	Trending bool // true when Query is empty, so the page can say so
	Total    int
	Page     int
	Pages    int
	From     int // 1-based index of the first row on this page
	To       int
	Sorts    []skillsSortLink
	PrevURL  string
	NextURL  string
}

// directorySorts is the whitelist of orderings the directory exposes, in the
// order their headings appear.
var directorySorts = []struct {
	Key         store.SkillSort
	Label       string
	DefaultDesc bool
}{
	{store.SkillSortName, "Skill", false},
	{store.SkillSortDownloads, "Downloads", true},
	{store.SkillSortRecent, "Published", true},
}

// directoryURL builds a /skills link preserving the parameters that are not
// being changed. Empty and default values are omitted so the common case stays
// a clean "/skills".
// directoryKinds are the tabs the directory offers. One entry per package kind
// plus "All", because a catalog that carries three kinds and offers no way to
// see one of them is a catalog whose third kind is hard to find.
var directoryKinds = []struct {
	Key   string
	Label string
}{
	{Key: "", Label: "All"},
	{Key: "skill", Label: "Skills"},
	{Key: pipeline.KindConnector, Label: "Connectors"},
	{Key: pipeline.KindAgentPlugin, Label: "Plugins"},
}

func directoryKindKnown(kind string) bool {
	for _, k := range directoryKinds {
		if k.Key == kind && k.Key != "" {
			return true
		}
	}
	return false
}

// directoryTitle names the page after what it is showing, so a filtered view
// does not keep a title that contradicts the rows under it.
func directoryTitle(kind string) string {
	switch kind {
	case pipeline.KindConnector:
		return "Browse connectors"
	case pipeline.KindAgentPlugin:
		return "Browse plugins"
	case "skill":
		return "Browse skills"
	default:
		return "Browse the catalog"
	}
}

// skillsKindLink is one kind tab, rendered by skills.html.
type skillsKindLink struct {
	Label  string
	URL    string
	Active bool
}

func directoryURL(query, kind string, sort store.SkillSort, desc bool, page int) string {
	values := url.Values{}
	if query != "" {
		values.Set("q", query)
	}
	if kind != "" {
		values.Set("kind", kind)
	}
	if sort != store.SkillSortDownloads {
		values.Set("sort", string(sort))
	}
	if !desc {
		values.Set("dir", "asc")
	}
	if page > 1 {
		values.Set("page", strconv.Itoa(page))
	}
	if len(values) == 0 {
		return "/skills"
	}
	return "/skills?" + values.Encode()
}

// Skills renders "/skills": a search box, and either search results for
// ?q=... or a default trending listing when there's no query. Both use the
// exact store queries the JSON API's own GET /api/v1/search and
// GET /api/v1/trending call.
func (h *Handler) Skills(w http.ResponseWriter, r *http.Request) {
	sess := h.sessionFromRequest(r)
	q := r.URL.Query()
	query := strings.TrimSpace(q.Get("q"))

	// An unknown kind falls back to every kind, for the same reason an unknown
	// sort key does: this page is reached from shared links, and a bogus value
	// should show the catalog rather than an error.
	kind := q.Get("kind")
	if !directoryKindKnown(kind) {
		kind = ""
	}

	// An unknown sort key falls back to downloads rather than erroring: this is
	// a public page reached from shared links, and the store maps the value to a
	// fixed ORDER BY, so a bogus one is harmless.
	sort := store.SkillSort(q.Get("sort"))
	defaultDesc := true
	known := false
	for _, s := range directorySorts {
		if s.Key == sort {
			defaultDesc, known = s.DefaultDesc, true
			break
		}
	}
	if !known {
		sort, defaultDesc = store.SkillSortDownloads, true
	}
	desc := defaultDesc
	switch q.Get("dir") {
	case "asc":
		desc = false
	case "desc":
		desc = true
	}

	page, err := strconv.Atoi(q.Get("page"))
	if err != nil || page < 1 {
		page = 1
	}

	result, err := h.API.Store.ListPublishedSkillsOfKind(
		r.Context(), query, kind, sort, desc, directoryPageSize, (page-1)*directoryPageSize,
	)
	if err != nil {
		h.Logger.Error("list skills for directory page", "error", err, "query", query)
		h.renderMessage(w, http.StatusInternalServerError, sess, "Error", "Could not load skills.")
		return
	}

	pages := (result.Total + directoryPageSize - 1) / directoryPageSize
	if pages < 1 {
		pages = 1
	}
	// A page number past the end would render an empty table with a working
	// pager, which reads as "the catalog is empty". Send it to the last page.
	if page > pages {
		http.Redirect(w, r, directoryURL(query, kind, sort, desc, pages), http.StatusSeeOther)
		return
	}

	sorts := make([]skillsSortLink, 0, len(directorySorts))
	for _, s := range directorySorts {
		active := s.Key == sort
		// Clicking the active heading flips direction; clicking another starts
		// at that column's natural direction.
		next := s.DefaultDesc
		if active {
			next = !desc
		}
		sorts = append(sorts, skillsSortLink{
			Key:    string(s.Key),
			Label:  s.Label,
			URL:    directoryURL(query, kind, s.Key, next, 1),
			Active: active,
			Desc:   desc,
		})
	}

	from, to := 0, 0
	if len(result.Skills) > 0 {
		from = (page-1)*directoryPageSize + 1
		to = from + len(result.Skills) - 1
	}
	prev, nextURL := "", ""
	if page > 1 {
		prev = directoryURL(query, kind, sort, desc, page-1)
	}
	if page < pages {
		nextURL = directoryURL(query, kind, sort, desc, page+1)
	}

	kinds := make([]skillsKindLink, 0, len(directoryKinds))
	for _, k := range directoryKinds {
		kinds = append(kinds, skillsKindLink{
			Label:  k.Label,
			URL:    directoryURL(query, k.Key, sort, desc, 1),
			Active: k.Key == kind,
		})
	}

	h.render(w, http.StatusOK, "skills.html", skillsPageData{
		basePage: basePage{Title: directoryTitle(kind), User: navUser(sess)},
		Query:    query,
		Kind:     kind,
		Kinds:    kinds,
		Skills:   result.Skills,
		Trending: query == "",
		Total:    result.Total,
		Page:     page,
		Pages:    pages,
		From:     from,
		To:       to,
		Sorts:    sorts,
		PrevURL:  prev,
		NextURL:  nextURL,
	})
}

// skillDetailPageData is the data shape for skill_detail.html.
type skillDetailPageData struct {
	basePage
	Skill    store.SkillDetail
	Versions []store.SkillVersion
	// Content is the current version's SKILL.md text, read straight out of
	// the locally-archived zip copy (see skillMDAndFiles). Rendered
	// verbatim in a <pre> block by default ("raw" view) -- html/template
	// auto-escapes it, so that view needs no Markdown rendering or
	// sanitization step at all. An opt-in "preview" view (see PreviewView
	// and PreviewHTML below, and docs/design-choices.md on why both exist)
	// renders this same text as sanitized Markdown-to-HTML instead. Empty
	// if the archive couldn't be read.
	Content string
	// PreviewView is true when the visitor asked for the Markdown-rendered
	// "preview" view (?view=preview) rather than the default, always-safe
	// "raw" view -- any other or missing ?view value leaves this false, so
	// garbage input silently falls back to "raw" instead of erroring. Drives
	// which of Content (raw) or PreviewHTML (rendered) skill_detail.html
	// shows, and which of the "raw"/"preview" toggle links is the inert
	// "currently active" one.
	PreviewView bool
	// PreviewHTML is Content rendered as sanitized HTML via
	// renderMarkdownPreview (see internal/web/markdown.go for the actual
	// safety mechanism: raw HTML is dropped, and every link/image URL is
	// checked against an explicit scheme allowlist, before this is ever
	// wrapped in template.HTML). Only computed when PreviewView is true --
	// there's no reason to pay for a goldmark render on every single
	// request to this page when the vast majority never ask for it. Empty
	// otherwise, or if rendering failed (logged; the page falls back to
	// showing nothing in the preview pane rather than erroring the whole
	// page over a cosmetic feature).
	PreviewHTML template.HTML
	// Files lists every entry (path + size) in that same archive -- SKILL.md
	// itself plus any scripts/references/assets -- so a visitor can see the
	// skill's actual shape without downloading and unzipping it. Nil if the
	// archive couldn't be read.
	Files []pipeline.Entry
	// SecurityAudits lists every named security check run against this
	// version, each with a PASS/WARN/FAIL/PENDING-style status: our own scan
	// shield ("NanoInfra Scanner"), always present, plus a second
	// "VirusTotal" entry -- only when VirusTotal is configured
	// (VIRUSTOTAL_API_KEY set) and an upload was actually attempted for
	// this version (see virusTotalAudit's doc comment for exactly when
	// that second entry does or doesn't appear).
	SecurityAudits []securityAudit
	// RepoLink is a link to this skill's own path in the published GitHub
	// repository, shown as part of the "Skill Card" section's static
	// license/terms notice -- this server has no license-metadata system of
	// its own, so it points visitors at the skill's own repository/SKILL.md
	// instead of collecting an unverified license string. Empty if
	// h.API.GitHubRepo isn't configured, in which case the template falls
	// back to a non-linked version of the same sentence.
	RepoLink string
	// Grants is what installing this package would allow, read from the
	// published archive rather than from a stored summary -- the archive is
	// what a visitor downloads, and a summary can drift from it.
	//
	// It is on the public page and not only the admin one because for a
	// connector this *is* the card: the badge tells a reader there is
	// something to check, and without the operations, their capability
	// classes, the hosts a token could reach and the scopes it would carry,
	// checking would mean downloading the zip.
	Grants *pipeline.Grants
}

// securityAudit is one named security check's result, for the detail
// page's "Security Audits" panel.
type securityAudit struct {
	Name string
	// Status is "pass", "warn", "fail", or "pending" -- drives the badge's
	// color in skill_detail.html.
	Status string
	Detail string
	// Permalink, when set, is an external URL to this audit's own full
	// report -- currently only VirusTotal sets this (its GUI page with the
	// complete per-engine breakdown; see virustotal.Analysis.Permalink).
	// Empty for NanoInfra Scanner (no external report to link to) and for
	// a VirusTotal entry that isn't yet "completed".
	Permalink string
}

// nanoinfraScannerAudit maps our own scan shield's verdict (see
// internal/scan.ComputeVerdict) to the detail page's badge vocabulary.
// "flagged" (an LLM-only, informational finding -- see scan.ComputeVerdict's
// doc comment on why that verdict can never come from the deterministic
// checks alone) maps to "warn", not "fail": it's exactly the same
// human-review distinction the scan shield itself already draws.
func nanoinfraScannerAudit(sc *store.Scan) securityAudit {
	if sc == nil {
		return securityAudit{Name: "NanoInfra Scanner", Status: "pending", Detail: "not yet scanned"}
	}
	switch sc.Verdict {
	case store.ScanVerdict(scan.VerdictPass):
		return securityAudit{Name: "NanoInfra Scanner", Status: "pass", Detail: "no issues found"}
	case store.ScanVerdict(scan.VerdictFlagged):
		return securityAudit{Name: "NanoInfra Scanner", Status: "warn", Detail: "flagged for human review"}
	case store.ScanVerdict(scan.VerdictBlocked):
		return securityAudit{Name: "NanoInfra Scanner", Status: "fail", Detail: "blocked, quarantined"}
	default:
		return securityAudit{Name: "NanoInfra Scanner", Status: "pending", Detail: string(sc.Verdict)}
	}
}

// virusTotalAudit maps a VirusTotal analysis row (see internal/virustotal)
// to the detail page's badge vocabulary, or returns nil when there is
// nothing to show at all: vt is nil whenever VirusTotal isn't configured, or
// is configured but the fire-and-forget upload for this version never
// created a row (an upload failure -- see UploadAndRecord's doc comment).
// Either way the panel shows no VirusTotal entry, not a placeholder --
// exactly like the scan shield's own optional LLM classification pass has
// no "not configured" row today.
//
// The public error_detail text is deliberately not surfaced here even for
// a store.VirusTotalScanError row: it may contain raw client-library error
// text, which isn't something to show on a page anyone can load
// unauthenticated.
func virusTotalAudit(vt *store.VirusTotalScan) *securityAudit {
	if vt == nil {
		return nil
	}
	switch vt.Status {
	case store.VirusTotalScanPending:
		return &securityAudit{Name: "VirusTotal", Status: "pending", Detail: "queued for analysis"}
	case store.VirusTotalScanCompleted:
		malicious := int64Value(vt.MaliciousCount)
		suspicious := int64Value(vt.SuspiciousCount)
		harmless := int64Value(vt.HarmlessCount)
		undetected := int64Value(vt.UndetectedCount)
		flagged := malicious + suspicious
		total := flagged + harmless + undetected
		detail := fmt.Sprintf("%d/%d engines flagged this file", flagged, total)
		if flagged == 0 {
			detail = "no engines flagged this file"
		}
		permalink := ""
		if vt.Permalink != nil {
			permalink = *vt.Permalink
		}
		return &securityAudit{Name: "VirusTotal", Status: virustotal.ComputeVerdict(malicious, suspicious), Detail: detail, Permalink: permalink}
	default: // store.VirusTotalScanError, or any future/unrecognized status
		return &securityAudit{Name: "VirusTotal", Status: "warn", Detail: "analysis could not be completed"}
	}
}

// int64Value returns *p, or 0 if p is nil -- used for VirusTotalScan's
// count fields, which are nil until the analysis completes.
func int64Value(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// SkillDetail renders "/skills/{id}": the current version's description,
// download link, full version history, the current version's actual
// SKILL.md content, and a listing of every file in its archive, all from
// the same store queries GET /api/v1/skills/{id} and
// GET /api/v1/skills/{id}/versions use, plus a local read of the archived
// zip (see skillMDAndFiles). A quarantined current version is shown,
// clearly marked, exactly like the JSON API's own detail endpoint does --
// not hidden.
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

	// A missing/unreadable archive is not fatal to the page -- the metadata
	// above still renders -- but is logged, since it shouldn't happen for
	// any skill that has actually been published (see docs/design-choices.md
	// on the local archived copy being the durable read path).
	content, files, err := h.skillMDAndFiles(skill.SkillID)
	if err != nil {
		h.Logger.Warn("load skill contents for detail page", "error", err, "skill_id", id)
	}

	// What installing it would allow. Same source as the file listing above, so
	// one unreadable archive costs both rather than one of them silently.
	grants := h.publishedGrants(skill.SkillID)

	// The current version's row id (not its user-facing version number) is
	// what scans.target_id and virustotal_scans.skill_version_id actually
	// store -- find it in the already-fetched version history rather than
	// an extra store round trip.
	var currentScan *store.Scan
	var currentVTScan *store.VirusTotalScan
	for _, v := range versions {
		if v.Version == skill.Version {
			sc, scanErr := h.API.Store.GetLatestScan(r.Context(), store.ScanTargetSkillVersion, api.ScanIDString(v.ID))
			if scanErr == nil {
				currentScan = sc
			} else if !errors.Is(scanErr, store.ErrNotFound) {
				h.Logger.Error("get latest scan for skill detail page", "error", scanErr, "skill_id", id)
			}
			vtScan, vtErr := h.API.Store.GetLatestVirusTotalScan(r.Context(), v.ID)
			if vtErr == nil {
				currentVTScan = vtScan
			} else if !errors.Is(vtErr, store.ErrNotFound) {
				h.Logger.Error("get latest virustotal scan for skill detail page", "error", vtErr, "skill_id", id)
			}
			break
		}
	}

	audits := []securityAudit{nanoinfraScannerAudit(currentScan)}
	if vtAudit := virusTotalAudit(currentVTScan); vtAudit != nil {
		audits = append(audits, *vtAudit)
	}

	// ?view=preview opts into the Markdown-rendered view of SKILL.md;
	// anything else (missing, "raw", or garbage) is the default, always-safe
	// "raw" view -- see skillDetailPageData.PreviewView's doc comment. The
	// goldmark render only happens when actually requested.
	previewView := r.URL.Query().Get("view") == "preview"
	var previewHTML template.HTML
	if previewView && content != "" {
		rendered, rerr := renderMarkdownPreview(stripFrontmatter(content))
		if rerr != nil {
			h.Logger.Error("render markdown preview for skill detail page", "error", rerr, "skill_id", id)
		} else {
			previewHTML = rendered
		}
	}

	h.render(w, http.StatusOK, "skill_detail.html", skillDetailPageData{
		basePage:       basePage{Title: skill.DisplayName, User: navUser(sess)},
		Skill:          *skill,
		Versions:       versions,
		Content:        content,
		PreviewView:    previewView,
		PreviewHTML:    previewHTML,
		Files:          files,
		SecurityAudits: audits,
		RepoLink:       repoLink(h.API.GitHubRepo, skill.GitHubPath),
		Grants:         grants,
	})
}

// publishedGrants reads what a published package would allow from its archived
// copy. Nil when the archive cannot be read, which the template renders as
// nothing rather than as an empty table -- an absent answer and "grants
// nothing" are different statements.
func (h *Handler) publishedGrants(skillID string) *pipeline.Grants {
	archivePath := filepath.Join(h.API.PublishedDir, skillID+".zip")
	result, err := pipeline.ValidateArchive(archivePath, "")
	if err != nil {
		h.Logger.Warn("describe published archive", "error", err, "skill_id", skillID)
		return nil
	}
	grants := result.Describe()
	return &grants
}

// repoLink builds a link to a skill's own path in the published GitHub
// repository (ghRepo is "owner/repo", e.g. "nanoinfraorg/skills";
// githubPath is the skill's path within it, e.g. "my-skill/" -- see
// ApproveSubmissionCore, which sets it to skill_id+"/"). Returns "" if
// ghRepo isn't configured, since there's nothing to link to.
func repoLink(ghRepo, githubPath string) string {
	if ghRepo == "" {
		return ""
	}
	return "https://github.com/" + ghRepo + "/tree/main/" + strings.TrimSuffix(githubPath, "/")
}

// skillMDAndFiles reads a published skill's locally-archived zip copy
// (PublishedDir/<skill_id>.zip -- the same file DownloadSkill already
// serves) and returns its current SKILL.md content plus a flat listing of
// every entry in the archive. It reuses internal/pipeline's existing
// zip-reading helpers -- ValidateArchive for the path-safe entry listing,
// ReadFiles for full content -- rather than opening the zip a second,
// independent way.
//
// Used by SkillDetail (to show a skill's actual contents, not just its
// metadata) and by the edit-prefill path in SubmitForm (to pre-populate the
// submit form's textarea with the current version's content).
func (h *Handler) skillMDAndFiles(skillID string) (content string, files []pipeline.Entry, err error) {
	archivePath := filepath.Join(h.API.PublishedDir, skillID+".zip")

	// expectedSkillID is passed as "" -- this is a read for display, not a
	// re-validation of a new submission, so there's no separate "expected"
	// id to check the frontmatter against.
	result, err := pipeline.ValidateArchive(archivePath, "")
	if err != nil {
		return "", nil, err
	}

	var mdEntry *pipeline.Entry
	for i := range result.Entries {
		if result.Entries[i].Name == pipeline.RootSkillFile {
			mdEntry = &result.Entries[i]
			break
		}
	}
	if mdEntry == nil {
		// ValidateArchive already guarantees a root SKILL.md exists;
		// unreachable in practice, kept as a defensive fallback.
		return "", result.Entries, fmt.Errorf("archive does not contain a root %s", pipeline.RootSkillFile)
	}

	contents, err := pipeline.ReadFiles(archivePath, []pipeline.Entry{*mdEntry})
	if err != nil || len(contents) != 1 {
		return "", result.Entries, fmt.Errorf("could not read %s: %w", pipeline.RootSkillFile, err)
	}
	return string(contents[0].Content), result.Entries, nil
}

// submitPageData is the data shape for submit.html.
type submitPageData struct {
	basePage
	CSRFToken string
	SkillID   string
	// SkillIDLocked is true when the form was reached via the "Edit / submit
	// new version" link on an existing skill's detail page (?skill_id=...),
	// so the skill_id field is rendered read-only: changing it here would
	// silently start a *different* skill instead of a new version of this
	// one. It's a UI guard only (the server does not special-case an "edit"
	// submission -- see SubmitCreate's doc comment), so it's false for a
	// fresh submission where the field is freely editable.
	SkillIDLocked bool
	DisplayName   string
	// Owner and Risks are the two optional "Skill Card" free-text fields
	// (see submissionDTO/skillVersionDetailDTO's doc comments in
	// internal/api/json.go for the full rationale): pre-filled the same way
	// as DisplayName -- the current version's values when editing, or
	// whatever the visitor last typed if a previous POST to this same page
	// failed validation. Owner additionally defaults to the logged-in
	// session's own email on a fresh form, or an edit of a version that
	// never set one (see SubmitForm) -- a visible, fully editable
	// suggestion against an accidentally-blank field, not a server-side
	// default: clearing it before submitting still stores an empty value.
	Owner string
	Risks string
	// SkillMD is the textarea's pre-filled content: empty for a fresh
	// submission, or the current version's actual SKILL.md text when
	// editing (see SubmitForm), or whatever the visitor last typed if a
	// previous POST to this same page failed validation.
	SkillMD string
	Error   string
}

// SubmitForm renders "/submit" (GET): the upload form. Requires a
// submitter-or-admin session (store.SessionRoleSubmitter); an unauthenticated
// visitor is redirected to Google login, since there's no separate
// "sign up" flow -- the first Google login already grants submitter access
// per the permissive-by-default SUBMITTER_EMAILS policy (see
// docs/authentication.md).
//
// An optional ?skill_id=<id> query parameter is the edit entry point linked
// from the skill detail page: when it names an existing published skill,
// the form is pre-filled with that skill's display name, its current
// version's actual SKILL.md content (via skillMDAndFiles), and its current
// version's Owner/Risks values, and the skill_id field is locked
// (SkillIDLocked) so the edit can't accidentally turn into a new skill
// under a different id. There is no separate
// "edit" concept beyond this pre-fill -- the resulting POST is a normal
// submission for an existing skill_id, handled identically to any other
// (see SubmitCreate). An id that doesn't resolve to a real skill falls
// through to a plain, unlocked form: there's nothing yet to edit.
//
// Separately, whenever the resolved Owner value is still blank at this
// point (a fresh submission, or an edit of a version that never set one),
// it's suggested-filled with the logged-in session's own verified email --
// see submitPageData.Owner's doc comment for why this is a visible,
// editable nudge rather than a silent server-side default.
func (h *Handler) SubmitForm(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.requireSession(w, r, store.SessionRoleSubmitter)
	if !ok {
		return
	}

	data := submitPageData{}
	if editID := strings.TrimSpace(r.URL.Query().Get("skill_id")); editID != "" {
		if skill, err := h.API.Store.GetSkillDetail(r.Context(), editID); err == nil {
			data.SkillID = editID
			data.DisplayName = skill.DisplayName
			data.Owner = skill.Owner
			data.Risks = skill.Risks
			data.SkillIDLocked = true
			if content, _, cerr := h.skillMDAndFiles(editID); cerr == nil {
				data.SkillMD = content
			} else {
				h.Logger.Warn("load current SKILL.md for edit prefill", "error", cerr, "skill_id", editID)
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			h.Logger.Error("get skill detail for edit prefill", "error", err, "skill_id", editID)
		}
	}

	// Owner is deliberately "beyond the submitter's auth identity" (see
	// submitPageData's doc comment) -- it can name a different person or a
	// whole team -- so there is no server-side default when it's left
	// blank; an omitted Owner is stored as empty, same as today. But a
	// fresh form (or an edit of a version that never set one) suggesting
	// the logged-in submitter's own verified email as a starting point is a
	// reasonable nudge against an accidentally-blank field: it's visible
	// and fully editable before the visitor ever submits, and clearing it
	// still submits an empty value, exactly like leaving it untouched on a
	// form that never suggested anything would.
	if data.Owner == "" {
		data.Owner = sess.Email
	}

	h.renderSubmitForm(w, http.StatusOK, sess, data)
}

func (h *Handler) renderSubmitForm(w http.ResponseWriter, status int, sess *store.Session, data submitPageData) {
	data.basePage = basePage{Title: "Submit a skill", User: navUser(sess)}
	data.CSRFToken = sess.CSRFToken
	h.render(w, status, "submit.html", data)
}

// SubmitCreate handles "/submit" (POST): validates and creates the
// submission via api.Handler.CreateSubmissionCore -- the exact same
// validate-then-store logic the JSON API's POST /api/v1/submissions uses,
// just fed from an HTML form instead of a client's own multipart request.
// The submitter is always the logged-in session's verified email, never a
// form field (there is no submitter field on this form at all, matching
// the override behavior CreateSubmission already applies to a
// session-authenticated JSON request).
//
// Two input modes converge here on one archive io.Reader before either
// ever reaches CreateSubmissionCore: a real uploaded .zip file (the
// "archive" form field), or -- if none was attached -- a pasted/edited
// SKILL.md string (the "skill_md" textarea field) materialized into an
// equivalent single-entry zip by buildSkillMDZip. From CreateSubmissionCore's
// perspective the two are indistinguishable: it only ever sees "an
// io.Reader over zip bytes", exactly as it does for the JSON API's own
// multipart upload. There is no second validation or pipeline path for
// "text mode".
//
// This is also how editing an existing skill works: there is no separate
// "edit" submission kind. The skill detail page's "Edit / submit new
// version" link (see SkillDetail) just pre-fills this same form (see
// SubmitForm) with the current version's content; submitting it is a
// perfectly normal call to CreateSubmissionCore for an already-published
// skill_id, exactly like re-uploading a changed zip already works.
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
	owner := strings.TrimSpace(r.FormValue("owner"))
	risks := strings.TrimSpace(r.FormValue("risks"))
	skillMD := r.FormValue("skill_md")

	if !validCSRF(r, sess) {
		http.Error(w, "invalid or missing csrf token", http.StatusForbidden)
		return
	}

	var archive io.Reader
	if file, _, err := r.FormFile("archive"); err == nil {
		defer file.Close()
		archive = file
	} else if strings.TrimSpace(skillMD) != "" {
		zipBytes, zerr := buildSkillMDZip(skillMD)
		if zerr != nil {
			h.Logger.Error("build in-memory zip from pasted SKILL.md", "error", zerr)
			h.renderSubmitForm(w, http.StatusInternalServerError, sess, submitPageData{
				SkillID: skillID, DisplayName: displayName, Owner: owner, Risks: risks, SkillMD: skillMD,
				Error: "could not process the pasted SKILL.md content",
			})
			return
		}
		archive = bytes.NewReader(zipBytes)
	} else {
		h.renderSubmitForm(w, http.StatusBadRequest, sess, submitPageData{
			SkillID: skillID, DisplayName: displayName, Owner: owner, Risks: risks,
			Error: "either a .zip archive or SKILL.md text is required",
		})
		return
	}

	_, subErr := h.API.CreateSubmissionCore(r.Context(), api.SubmissionInput{
		SkillID:     skillID,
		DisplayName: displayName,
		Submitter:   sess.Email,
		Owner:       owner,
		Risks:       risks,
		Archive:     archive,
	})
	if subErr != nil {
		h.renderSubmitForm(w, subErr.Status, sess, submitPageData{
			SkillID: skillID, DisplayName: displayName, Owner: owner, Risks: risks, SkillMD: skillMD, Error: subErr.Message,
		})
		return
	}

	http.Redirect(w, r, "/my/submissions", http.StatusSeeOther)
}

// buildSkillMDZip materializes a pasted/edited SKILL.md string into an
// in-memory zip archive containing exactly one entry (SKILL.md), entirely
// in a bytes.Buffer -- no temp file. This is the only piece of code
// specific to the textarea input mode; everything downstream of it
// (validation, storage, the pending queue, publish) is the exact same path
// a real uploaded zip already goes through, fed from the resulting
// *bytes.Reader wrapped as the same io.Reader shape CreateSubmissionCore
// already accepts.
func buildSkillMDZip(content string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	entry, err := zw.Create(pipeline.RootSkillFile)
	if err != nil {
		return nil, err
	}
	if _, err := entry.Write([]byte(content)); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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
	Kind    string // "published", "publishing", "rejected", "rescanned", or "error"
	Message string
}

func outcomeFromQuery(q url.Values) *outcomeBanner {
	switch q.Get("outcome") {
	case "published":
		return &outcomeBanner{Kind: "published", Message: fmt.Sprintf(
			"Published %s v%s (scan verdict: %s).", q.Get("skill_id"), q.Get("version"), q.Get("scan_verdict"))}
	case "rejected":
		return &outcomeBanner{Kind: "rejected", Message: "Rejected: " + q.Get("reason")}
	case "publishing":
		// Deliberately not "Published": the work is running, and a banner that
		// claimed otherwise would be wrong for the seconds that matter.
		return &outcomeBanner{
			Kind: "publishing",
			Message: "Publishing in the background. The row leaves Pending when it finishes, " +
				"or comes back with a reason if it did not.",
		}
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
	// Publishing is true while the background work runs. Such a row shows its
	// state instead of approve/reject buttons: the decision is already taken,
	// and a second click on it is a click that can do nothing.
	Publishing bool
	Scan       *store.Scan
	// What approving this submission would allow, read from the archive itself.
	// Nil when the archive could not be read -- the row still renders, because
	// an unreadable archive is a thing an admin needs to see rather than a
	// reason to hide the submission.
	Grants *pipeline.Grants
}

// adminPageData is the data shape for admin.html.
type adminPageData struct {
	basePage
	CSRFToken string
	Outcome   *outcomeBanner
	Pending   []adminSubmissionRow
	Skills    []store.SkillDetail
	// AnyPublishing drives a short meta-refresh, so a row that finishes in the
	// background stops being stale without the admin reloading by hand.
	AnyPublishing bool
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
	// The rows mid-publish belong on this page too. Without them an approved
	// submission vanishes for the seconds the work takes and reappears only if
	// it failed, which reads as "did my click land?".
	publishing, err := h.API.Store.ListPublishingSubmissions(ctx)
	if err != nil {
		h.Logger.Error("list publishing submissions", "error", err)
	}
	pending = append(publishing, pending...)
	rows := make([]adminSubmissionRow, 0, len(pending))
	for _, sub := range pending {
		row := adminSubmissionRow{
			submissionRow: toSubmissionRow(sub),
			Publishing:    sub.Status == store.StatusPublishing,
		}
		// Re-read from the pending archive rather than from a stored summary:
		// the archive is what would be published, and a summary can drift.
		if result, err := pipeline.ValidateArchive(sub.ArchivePath, ""); err == nil {
			grants := result.Describe()
			row.Grants = &grants
		} else {
			h.Logger.Warn("could not describe pending archive", "error", err, "submission_id", sub.ID)
		}
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
		basePage:      basePage{Title: "Admin dashboard", User: navUser(sess)},
		CSRFToken:     sess.CSRFToken,
		Outcome:       outcomeFromQuery(r.URL.Query()),
		Pending:       rows,
		Skills:        skills,
		AnyPublishing: len(publishing) > 0,
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

	// Claims the row and returns. The scan and the GitHub publish run behind
	// it, so approving ten submissions is ten clicks rather than ten waits --
	// the request used to stay open for an LLM call with a 30-second timeout
	// followed by a GitHub round trip.
	if _, subErr := h.API.ApproveSubmissionAsync(r.Context(), r.PathValue("id")); subErr != nil {
		redirectWithOutcome(w, r, url.Values{"outcome": {"error"}, "message": {subErr.Message}})
		return
	}
	redirectWithOutcome(w, r, url.Values{"outcome": {"publishing"}})
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

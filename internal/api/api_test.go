package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/github"
	"github.com/nanoinfraorg/skills-server/internal/store"
)

const testValidSkillMD = "---\nname: my-skill\ndescription: Does a useful thing.\n---\n\nBody.\n"

// fakePublisher records publish calls and lets tests inject a failure,
// standing in for internal/github.Client so tests never touch the network.
type fakePublisher struct {
	calls   []fakePublishCall
	failErr error
}

type fakePublishCall struct {
	skillID string
	files   []github.File
	message string
}

func (f *fakePublisher) PublishFiles(_ context.Context, skillID string, files []github.File, message string) error {
	if f.failErr != nil {
		return f.failErr
	}
	f.calls = append(f.calls, fakePublishCall{skillID: skillID, files: files, message: message})
	return nil
}

// testHandler wires a fresh in-memory-backed Handler (SQLite on a temp file,
// since modernc.org/sqlite has no ":memory:"-only mode needed here) plus a
// fake publisher for a single test.
func testHandler(t *testing.T) (*Handler, *fakePublisher) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	pub := &fakePublisher{}
	h := &Handler{
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
	if err := os.MkdirAll(h.SubmissionsDir, 0o755); err != nil {
		t.Fatalf("mkdir submissions: %v", err)
	}
	if err := os.MkdirAll(h.PublishedDir, 0o755); err != nil {
		t.Fatalf("mkdir published: %v", err)
	}
	return h, pub
}

// buildZip creates an in-memory zip archive from name->content pairs.
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

// submissionRequest builds a multipart POST /api/v1/submissions request.
func submissionRequest(t *testing.T, token string, fields map[string]string, archive []byte) *http.Request {
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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submissions", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if token != "" {
		req.Header.Set("X-Submitter-Token", token)
	}
	return req
}

func decodeJSON[T any](t *testing.T, body *bytes.Buffer) T {
	t.Helper()
	var out T
	if err := json.NewDecoder(body).Decode(&out); err != nil {
		t.Fatalf("decode json response: %v (body: %s)", err, body.String())
	}
	return out
}

func TestCreateSubmission_HappyPath(t *testing.T) {
	h, _ := testHandler(t)
	mux := NewMux(h)

	archive := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	req := submissionRequest(t, "submitter-secret", map[string]string{
		"skill_id":     "my-skill",
		"display_name": "My Skill",
		"submitter":    "alice",
	}, archive)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body: %s", rec.Code, rec.Body.String())
	}
	resp := decodeJSON[map[string]string](t, rec.Body)
	if resp["status"] != "pending" {
		t.Errorf("status field = %q, want pending", resp["status"])
	}
	if resp["id"] == "" {
		t.Errorf("expected non-empty submission id")
	}

	submissions, err := h.Store.ListSubmissions(context.Background(), "pending")
	if err != nil || len(submissions) != 1 {
		t.Fatalf("expected 1 pending submission, err=%v list=%+v", err, submissions)
	}
}

func TestCreateSubmission_BadAuth(t *testing.T) {
	h, _ := testHandler(t)
	mux := NewMux(h)

	archive := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	req := submissionRequest(t, "wrong-token", map[string]string{
		"skill_id":     "my-skill",
		"display_name": "My Skill",
		"submitter":    "alice",
	}, archive)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateSubmission_MissingArchiveToken(t *testing.T) {
	h, _ := testHandler(t)
	mux := NewMux(h)

	req := submissionRequest(t, "submitter-secret", map[string]string{
		"skill_id":     "my-skill",
		"display_name": "My Skill",
		"submitter":    "alice",
	}, nil)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateSubmission_InvalidSkillID(t *testing.T) {
	h, _ := testHandler(t)
	mux := NewMux(h)

	archive := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	req := submissionRequest(t, "submitter-secret", map[string]string{
		"skill_id":     "Not_A_Valid_ID",
		"display_name": "My Skill",
		"submitter":    "alice",
	}, archive)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body: %s", rec.Code, rec.Body.String())
	}
}

func TestCreateSubmission_MissingSkillMDRejected(t *testing.T) {
	h, _ := testHandler(t)
	mux := NewMux(h)

	archive := buildZip(t, map[string]string{"README.md": "no skill here"})
	req := submissionRequest(t, "submitter-secret", map[string]string{
		"skill_id":     "my-skill",
		"display_name": "My Skill",
		"submitter":    "alice",
	}, archive)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422, body: %s", rec.Code, rec.Body.String())
	}
}

// createPendingSubmission is a test helper that drives the real
// CreateSubmission handler to seed a pending submission, returning its id.
func createPendingSubmission(t *testing.T, h *Handler, mux http.Handler, skillID string, archive []byte) string {
	t.Helper()
	req := submissionRequest(t, h.SubmitterToken, map[string]string{
		"skill_id":     skillID,
		"display_name": "Display " + skillID,
		"submitter":    "alice",
	}, archive)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed submission failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeJSON[map[string]string](t, rec.Body)
	return resp["id"]
}

func adminRequest(method, path, token string, body []byte) *http.Request {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("X-Admin-Token", token)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestApproveSubmission_HappyPathPublishes(t *testing.T) {
	h, pub := testHandler(t)
	mux := NewMux(h)

	skillMD := "---\nname: approve-me\ndescription: A skill worth approving.\n---\n\nBody.\n"
	archive := buildZip(t, map[string]string{
		"SKILL.md":       skillMD,
		"scripts/run.py": "print('ok')\n",
	})
	id := createPendingSubmission(t, h, mux, "approve-me", archive)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, adminRequest(http.MethodPost, "/api/v1/admin/submissions/"+id+"/approve", "admin-secret", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	resp := decodeJSON[map[string]any](t, rec.Body)
	if resp["outcome"] != "published" {
		t.Fatalf("outcome = %v, want published (body: %s)", resp["outcome"], rec.Body.String())
	}

	if len(pub.calls) != 1 {
		t.Fatalf("expected 1 publish call, got %d", len(pub.calls))
	}
	if pub.calls[0].skillID != "approve-me" {
		t.Errorf("published skillID = %q, want approve-me", pub.calls[0].skillID)
	}
	if len(pub.calls[0].files) != 2 {
		t.Errorf("expected 2 published files, got %d", len(pub.calls[0].files))
	}

	skill, err := h.Store.GetSkill(context.Background(), "approve-me")
	if err != nil {
		t.Fatalf("get published skill: %v", err)
	}
	if skill.Version != 1 || skill.Description != "A skill worth approving." {
		t.Errorf("unexpected published skill: %+v", skill)
	}

	// The locally-archived copy used for downloads must exist.
	if _, err := os.Stat(filepath.Join(h.PublishedDir, "approve-me.zip")); err != nil {
		t.Errorf("expected published archive copy to exist: %v", err)
	}

	sub, err := h.Store.GetSubmission(context.Background(), id)
	if err != nil {
		t.Fatalf("get submission: %v", err)
	}
	if sub.Status != store.StatusApproved {
		t.Errorf("submission status = %s, want approved", sub.Status)
	}
}

func TestApproveSubmission_PipelineFailureAutoRejects(t *testing.T) {
	h, pub := testHandler(t)
	mux := NewMux(h)

	// Build an archive that passes the submission-time check (has a root
	// SKILL.md) but fails the pipeline's *published entries* re-check
	// because the frontmatter name won't match "traversal-skill" — a stand
	// in for "the pipeline finds something the light submission check
	// didn't". We simulate this by tampering with the stored archive after
	// the initial, passing submission.
	archive := buildZip(t, map[string]string{
		"SKILL.md": "---\nname: traversal-skill\ndescription: fine for now.\n---\n\nBody.\n",
	})
	id := createPendingSubmission(t, h, mux, "traversal-skill", archive)

	sub, err := h.Store.GetSubmission(context.Background(), id)
	if err != nil {
		t.Fatalf("get submission: %v", err)
	}
	tampered := buildZip(t, map[string]string{
		"SKILL.md":      "---\nname: traversal-skill\ndescription: fine.\n---\n\nBody.\n",
		"../outside.sh": "malicious",
	})
	if err := os.WriteFile(sub.ArchivePath, tampered, 0o644); err != nil {
		t.Fatalf("tamper archive: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, adminRequest(http.MethodPost, "/api/v1/admin/submissions/"+id+"/approve", "admin-secret", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (approve endpoint reports rejection in-band), body: %s", rec.Code, rec.Body.String())
	}
	resp := decodeJSON[map[string]any](t, rec.Body)
	if resp["outcome"] != "rejected" {
		t.Fatalf("outcome = %v, want rejected", resp["outcome"])
	}
	if resp["reason"] == "" || resp["reason"] == nil {
		t.Errorf("expected non-empty rejection reason")
	}

	if len(pub.calls) != 0 {
		t.Errorf("expected no publish calls for a rejected pipeline run, got %d", len(pub.calls))
	}

	sub, err = h.Store.GetSubmission(context.Background(), id)
	if err != nil {
		t.Fatalf("get submission after rejection: %v", err)
	}
	if sub.Status != store.StatusRejected {
		t.Errorf("submission status = %s, want rejected", sub.Status)
	}

	if _, err := h.Store.GetSkill(context.Background(), "traversal-skill"); err != store.ErrNotFound {
		t.Errorf("expected skill to not be published, got err=%v", err)
	}
}

func TestApproveSubmission_BadAdminAuth(t *testing.T) {
	h, _ := testHandler(t)
	mux := NewMux(h)
	archive := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	id := createPendingSubmission(t, h, mux, "my-skill", archive)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, adminRequest(http.MethodPost, "/api/v1/admin/submissions/"+id+"/approve", "wrong-token", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body: %s", rec.Code, rec.Body.String())
	}
}

func TestRejectSubmission_HappyPath(t *testing.T) {
	h, pub := testHandler(t)
	mux := NewMux(h)
	archive := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	id := createPendingSubmission(t, h, mux, "my-skill", archive)

	body, _ := json.Marshal(map[string]string{"reason": "not a good fit for the catalog"})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, adminRequest(http.MethodPost, "/api/v1/admin/submissions/"+id+"/reject", "admin-secret", body))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	if len(pub.calls) != 0 {
		t.Errorf("reject must not trigger a publish, got %d calls", len(pub.calls))
	}

	sub, err := h.Store.GetSubmission(context.Background(), id)
	if err != nil {
		t.Fatalf("get submission: %v", err)
	}
	if sub.Status != store.StatusRejected {
		t.Errorf("status = %s, want rejected", sub.Status)
	}
	if sub.RejectionReason == nil || *sub.RejectionReason != "not a good fit for the catalog" {
		t.Errorf("unexpected rejection reason: %v", sub.RejectionReason)
	}
}

func TestSearchTrendingAndDetail(t *testing.T) {
	h, _ := testHandler(t)
	mux := NewMux(h)
	ctx := context.Background()

	if err := h.Store.UpsertSkill(ctx, store.Skill{
		SkillID: "alpha", DisplayName: "Alpha", Description: "first skill",
		Version: 1, Submitter: "alice", PublishedAt: time.Now(), GitHubPath: "alpha/",
	}); err != nil {
		t.Fatalf("seed alpha: %v", err)
	}
	if err := h.Store.UpsertSkill(ctx, store.Skill{
		SkillID: "beta", DisplayName: "Beta", Description: "second skill",
		Version: 1, Submitter: "alice", PublishedAt: time.Now(), GitHubPath: "beta/",
	}); err != nil {
		t.Fatalf("seed beta: %v", err)
	}
	if err := h.Store.IncrementDownloads(ctx, "beta"); err != nil {
		t.Fatalf("bump beta downloads: %v", err)
	}

	// search
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/search?q=alpha", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("search status = %d, body: %s", rec.Code, rec.Body.String())
	}
	searchResp := decodeJSON[map[string]any](t, rec.Body)
	skills, _ := searchResp["skills"].([]any)
	if len(skills) != 1 {
		t.Fatalf("expected 1 search result, got %+v", searchResp)
	}

	// trending: beta has more downloads, should be first
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/trending", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("trending status = %d, body: %s", rec.Code, rec.Body.String())
	}
	trendingResp := decodeJSON[map[string]any](t, rec.Body)
	trendingSkills, _ := trendingResp["skills"].([]any)
	if len(trendingSkills) != 2 {
		t.Fatalf("expected 2 trending skills, got %+v", trendingResp)
	}
	first := trendingSkills[0].(map[string]any)
	if first["skill_id"] != "beta" {
		t.Errorf("expected beta to be first in trending, got %v", first["skill_id"])
	}

	// detail
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/skills/alpha", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("detail status = %d, body: %s", rec.Code, rec.Body.String())
	}
	detail := decodeJSON[map[string]any](t, rec.Body)
	if detail["skill_id"] != "alpha" {
		t.Errorf("detail skill_id = %v, want alpha", detail["skill_id"])
	}

	// detail 404
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/skills/does-not-exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("detail 404 status = %d, body: %s", rec.Code, rec.Body.String())
	}
}

func TestDownloadSkill_StreamsArchiveAndIncrementsDownloads(t *testing.T) {
	h, _ := testHandler(t)
	mux := NewMux(h)
	ctx := context.Background()

	archiveBytes := buildZip(t, map[string]string{"SKILL.md": testValidSkillMD})
	if err := os.WriteFile(filepath.Join(h.PublishedDir, "downloadable.zip"), archiveBytes, 0o644); err != nil {
		t.Fatalf("seed published archive: %v", err)
	}
	if err := h.Store.UpsertSkill(ctx, store.Skill{
		SkillID: "downloadable", DisplayName: "Downloadable", Description: "d",
		Version: 1, Submitter: "alice", PublishedAt: time.Now(), GitHubPath: "downloadable/",
	}); err != nil {
		t.Fatalf("seed skill: %v", err)
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/skills/downloadable/download", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("download status = %d, body: %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), archiveBytes) {
		t.Errorf("downloaded bytes do not match published archive")
	}

	skill, err := h.Store.GetSkill(ctx, "downloadable")
	if err != nil {
		t.Fatalf("get skill: %v", err)
	}
	if skill.Downloads != 1 {
		t.Errorf("downloads = %d, want 1", skill.Downloads)
	}
}

func TestHealthz(t *testing.T) {
	h, _ := testHandler(t)
	mux := NewMux(h)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

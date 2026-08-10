package virustotal

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/nanoinfraorg/skills-server/internal/store"
)

// fakeClient stands in for the real VirusTotal API, exactly like
// internal/api's fakePublisher and internal/auth's fake IDTokenVerifier
// stand in for their respective third parties -- no test in this package
// may ever make a real network call to VirusTotal.
type fakeClient struct {
	// uploadAnalysisID is returned by Upload on success; if uploadErr is
	// set, Upload fails instead and uploadAnalysisID is never used.
	uploadAnalysisID string
	uploadErr        error
	uploadCalls      int

	// analyses maps an analysis id to either a canned *Analysis or an
	// error to return from GetAnalysis, so a single fake can simulate
	// several different in-flight analyses across one poll pass.
	analyses    map[string]*Analysis
	analysisErr map[string]error
	getCalls    int
}

func (f *fakeClient) Upload(_ context.Context, r io.Reader, _ string) (string, error) {
	f.uploadCalls++
	if f.uploadErr != nil {
		return "", f.uploadErr
	}
	// Drain r, mirroring the real client actually reading the archive.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return "", err
	}
	return f.uploadAnalysisID, nil
}

func (f *fakeClient) GetAnalysis(_ context.Context, analysisID string) (*Analysis, error) {
	f.getCalls++
	if err, ok := f.analysisErr[analysisID]; ok {
		return nil, err
	}
	if a, ok := f.analyses[analysisID]; ok {
		return a, nil
	}
	return nil, errors.New("fakeClient: no canned analysis for " + analysisID)
}

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// seedSkillVersion inserts a minimal skill_versions row and returns its id,
// so ListPendingVirusTotalScans/GetLatestVirusTotalScan's foreign
// skill_version_id has something plausible to point at (the schema doesn't
// enforce the foreign key, but a real row makes the test's intent clearer).
func seedSkillVersion(t *testing.T, s *store.Store, skillID string) int64 {
	t.Helper()
	id, err := s.CreateSkillVersion(context.Background(), store.SkillVersion{
		SkillID: skillID, Version: 1, SubmissionID: "sub-" + skillID,
		DisplayName: skillID, Description: "test", GitHubPath: skillID + "/",
		PublishedAt: time.Now(), Status: store.SkillVersionPublished,
	})
	if err != nil {
		t.Fatalf("seed skill version: %v", err)
	}
	return id
}

func TestComputeVerdict(t *testing.T) {
	tests := []struct {
		name       string
		malicious  int64
		suspicious int64
		want       string
	}{
		{"clean", 0, 0, "pass"},
		{"suspicious-only", 0, 3, "warn"},
		{"malicious-outranks-suspicious", 2, 5, "fail"},
		{"malicious-only", 1, 0, "fail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeVerdict(tt.malicious, tt.suspicious)
			if got != tt.want {
				t.Errorf("ComputeVerdict(%d, %d) = %q, want %q", tt.malicious, tt.suspicious, got, tt.want)
			}
		})
	}
}

func TestUploadAndRecord_SuccessCreatesPendingRow(t *testing.T) {
	s := newTestStore(t)
	svID := seedSkillVersion(t, s, "uploaded-skill")
	client := &fakeClient{uploadAnalysisID: "analysis-abc"}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	UploadAndRecord(context.Background(), client, s, testLogger(), func() time.Time { return now }, svID, []byte("fake zip bytes"), "uploaded-skill.zip")

	if client.uploadCalls != 1 {
		t.Fatalf("expected 1 upload call, got %d", client.uploadCalls)
	}
	got, err := s.GetLatestVirusTotalScan(context.Background(), svID)
	if err != nil {
		t.Fatalf("get latest virustotal scan: %v", err)
	}
	if got.AnalysisID != "analysis-abc" || got.Status != store.VirusTotalScanPending {
		t.Errorf("unexpected row: %+v", got)
	}
}

func TestUploadAndRecord_UploadFailureCreatesNoRowAndDoesNotPanic(t *testing.T) {
	s := newTestStore(t)
	svID := seedSkillVersion(t, s, "failed-upload-skill")
	client := &fakeClient{uploadErr: errors.New("connection refused")}

	// Must not panic, and must not block -- this exercises the exact same
	// call shape ApproveSubmissionCore makes from its own goroutine.
	UploadAndRecord(context.Background(), client, s, testLogger(), time.Now, svID, []byte("fake zip bytes"), "failed-upload-skill.zip")

	if client.uploadCalls != 1 {
		t.Fatalf("expected 1 upload call, got %d", client.uploadCalls)
	}
	if _, err := s.GetLatestVirusTotalScan(context.Background(), svID); err != store.ErrNotFound {
		t.Fatalf("expected no row to be created on upload failure, got err=%v", err)
	}
}

func TestRunOnce_StillQueuedLeavesRowPending(t *testing.T) {
	s := newTestStore(t)
	svID := seedSkillVersion(t, s, "queued-skill")
	id, err := s.CreateVirusTotalScan(context.Background(), svID, "analysis-queued", time.Now())
	if err != nil {
		t.Fatalf("seed pending scan: %v", err)
	}

	client := &fakeClient{analyses: map[string]*Analysis{
		"analysis-queued": {Status: StatusQueued},
	}}
	RunOnce(context.Background(), Deps{Store: s, Client: client, Logger: testLogger()})

	got, err := s.GetLatestVirusTotalScan(context.Background(), svID)
	if err != nil {
		t.Fatalf("get latest virustotal scan: %v", err)
	}
	if got.ID != id || got.Status != store.VirusTotalScanPending {
		t.Errorf("expected the row to remain pending while queued, got %+v", got)
	}
}

func TestRunOnce_CompletedVerdictMappings(t *testing.T) {
	tests := []struct {
		name        string
		malicious   int64
		suspicious  int64
		harmless    int64
		undetected  int64
		wantVerdict string
	}{
		{"clean", 0, 0, 70, 5, "pass"},
		{"suspicious-only", 0, 2, 65, 5, "warn"},
		{"malicious", 3, 1, 60, 6, "fail"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStore(t)
			svID := seedSkillVersion(t, s, "completed-"+tt.name)
			analysisID := "analysis-" + tt.name
			if _, err := s.CreateVirusTotalScan(context.Background(), svID, analysisID, time.Now()); err != nil {
				t.Fatalf("seed pending scan: %v", err)
			}

			client := &fakeClient{analyses: map[string]*Analysis{
				analysisID: {
					Status:     StatusCompleted,
					Malicious:  tt.malicious,
					Suspicious: tt.suspicious,
					Harmless:   tt.harmless,
					Undetected: tt.undetected,
					Permalink:  "https://www.virustotal.com/gui/file-analysis/" + analysisID,
				},
			}}
			RunOnce(context.Background(), Deps{Store: s, Client: client, Logger: testLogger()})

			got, err := s.GetLatestVirusTotalScan(context.Background(), svID)
			if err != nil {
				t.Fatalf("get latest virustotal scan: %v", err)
			}
			if got.Status != store.VirusTotalScanCompleted {
				t.Fatalf("status = %s, want completed", got.Status)
			}
			verdict := ComputeVerdict(*got.MaliciousCount, *got.SuspiciousCount)
			if verdict != tt.wantVerdict {
				t.Errorf("verdict = %s, want %s (malicious=%d suspicious=%d)", verdict, tt.wantVerdict, *got.MaliciousCount, *got.SuspiciousCount)
			}
			if *got.HarmlessCount != tt.harmless || *got.UndetectedCount != tt.undetected {
				t.Errorf("unexpected counts: %+v", got)
			}
			if got.Permalink == nil || *got.Permalink == "" {
				t.Errorf("expected a permalink to be recorded")
			}
		})
	}
}

func TestRunOnce_RateLimitErrorLeavesRowPendingAndDoesNotCrash(t *testing.T) {
	s := newTestStore(t)
	svID := seedSkillVersion(t, s, "rate-limited-skill")
	id, err := s.CreateVirusTotalScan(context.Background(), svID, "analysis-rl", time.Now())
	if err != nil {
		t.Fatalf("seed pending scan: %v", err)
	}

	client := &fakeClient{analysisErr: map[string]error{
		"analysis-rl": errors.New("429 Too Many Requests"),
	}}

	// Must not panic; a single bad row must not stop the pass.
	RunOnce(context.Background(), Deps{Store: s, Client: client, Logger: testLogger()})

	got, err := s.GetLatestVirusTotalScan(context.Background(), svID)
	if err != nil {
		t.Fatalf("get latest virustotal scan: %v", err)
	}
	if got.ID != id || got.Status != store.VirusTotalScanPending {
		t.Errorf("expected the row to remain pending after a rate-limit error, got %+v", got)
	}
	pending, err := s.ListPendingVirusTotalScans(context.Background())
	if err != nil || len(pending) != 1 {
		t.Fatalf("expected the row to still be listed as pending for the next tick, got %+v (err=%v)", pending, err)
	}
}

func TestRunOnce_MalformedAnalysisMarksErrorAndStopsPolling(t *testing.T) {
	s := newTestStore(t)
	svID := seedSkillVersion(t, s, "malformed-skill")
	if _, err := s.CreateVirusTotalScan(context.Background(), svID, "analysis-malformed", time.Now()); err != nil {
		t.Fatalf("seed pending scan: %v", err)
	}

	client := &fakeClient{analysisErr: map[string]error{
		"analysis-malformed": ErrMalformedAnalysis,
	}}
	RunOnce(context.Background(), Deps{Store: s, Client: client, Logger: testLogger()})

	got, err := s.GetLatestVirusTotalScan(context.Background(), svID)
	if err != nil {
		t.Fatalf("get latest virustotal scan: %v", err)
	}
	if got.Status != store.VirusTotalScanError {
		t.Errorf("status = %s, want error", got.Status)
	}
	if got.ErrorDetail == nil || *got.ErrorDetail == "" {
		t.Errorf("expected an error detail to be recorded")
	}

	// Must no longer be picked up by future poll passes.
	pending, err := s.ListPendingVirusTotalScans(context.Background())
	if err != nil || len(pending) != 0 {
		t.Fatalf("expected the malformed row to no longer be pending, got %+v (err=%v)", pending, err)
	}
}

func TestRunOnce_OneBadRowDoesNotStopOthersInTheSamePass(t *testing.T) {
	s := newTestStore(t)
	badSV := seedSkillVersion(t, s, "bad-skill")
	goodSV := seedSkillVersion(t, s, "good-skill")
	if _, err := s.CreateVirusTotalScan(context.Background(), badSV, "analysis-bad", time.Now()); err != nil {
		t.Fatalf("seed bad scan: %v", err)
	}
	if _, err := s.CreateVirusTotalScan(context.Background(), goodSV, "analysis-good", time.Now()); err != nil {
		t.Fatalf("seed good scan: %v", err)
	}

	client := &fakeClient{
		analysisErr: map[string]error{"analysis-bad": errors.New("network error")},
		analyses: map[string]*Analysis{
			"analysis-good": {Status: StatusCompleted, Malicious: 0, Suspicious: 0, Harmless: 70, Undetected: 3, Permalink: "https://example.com"},
		},
	}
	RunOnce(context.Background(), Deps{Store: s, Client: client, Logger: testLogger()})

	goodResult, err := s.GetLatestVirusTotalScan(context.Background(), goodSV)
	if err != nil {
		t.Fatalf("get latest virustotal scan for good skill: %v", err)
	}
	if goodResult.Status != store.VirusTotalScanCompleted {
		t.Errorf("expected the good row to complete despite the bad row's error, got %+v", goodResult)
	}
}

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSubmissionLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	created := time.Now().Truncate(time.Second)

	sub := Submission{
		ID:          "sub-1",
		SkillID:     "my-skill",
		DisplayName: "My Skill",
		Submitter:   "alice",
		Status:      StatusPending,
		ArchivePath: "/tmp/sub-1.zip",
		CreatedAt:   created,
	}
	if err := s.CreateSubmission(ctx, sub); err != nil {
		t.Fatalf("create submission: %v", err)
	}

	got, err := s.GetSubmission(ctx, "sub-1")
	if err != nil {
		t.Fatalf("get submission: %v", err)
	}
	if got.SkillID != "my-skill" || got.Status != StatusPending {
		t.Errorf("unexpected submission: %+v", got)
	}
	if got.RejectionReason != nil {
		t.Errorf("expected nil rejection reason, got %v", *got.RejectionReason)
	}

	list, err := s.ListSubmissions(ctx, string(StatusPending))
	if err != nil {
		t.Fatalf("list submissions: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 pending submission, got %d", len(list))
	}

	reason := "unsafe path detected"
	decidedAt := created.Add(time.Minute)
	if err := s.DecideSubmission(ctx, "sub-1", StatusRejected, &reason, decidedAt); err != nil {
		t.Fatalf("decide submission: %v", err)
	}

	got, err = s.GetSubmission(ctx, "sub-1")
	if err != nil {
		t.Fatalf("get submission after decision: %v", err)
	}
	if got.Status != StatusRejected {
		t.Errorf("status = %s, want rejected", got.Status)
	}
	if got.RejectionReason == nil || *got.RejectionReason != reason {
		t.Errorf("rejection reason = %v, want %q", got.RejectionReason, reason)
	}
	if got.DecidedAt == nil {
		t.Fatal("expected decided_at to be set")
	}

	list, err = s.ListSubmissions(ctx, string(StatusPending))
	if err != nil {
		t.Fatalf("list pending after decision: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 pending submissions after rejection, got %d", len(list))
	}
}

func TestGetSubmissionNotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetSubmission(context.Background(), "missing"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// publishVersion is a test helper that drives CreateSkillVersion +
// SetSkillPointer together, mirroring what the approve handler does on a
// successful publish.
func publishVersion(t *testing.T, s *Store, skillID, displayName, description string, version int64, publishedAt time.Time) int64 {
	t.Helper()
	ctx := context.Background()
	id, err := s.CreateSkillVersion(ctx, SkillVersion{
		SkillID:      skillID,
		Version:      version,
		SubmissionID: "sub-" + skillID,
		DisplayName:  displayName,
		Description:  description,
		GitHubPath:   skillID + "/",
		PublishedAt:  publishedAt,
		Status:       SkillVersionPublished,
	})
	if err != nil {
		t.Fatalf("create skill version: %v", err)
	}
	if err := s.SetSkillPointer(ctx, skillID, version, publishedAt); err != nil {
		t.Fatalf("set skill pointer: %v", err)
	}
	return id
}

func TestSkillPublishAndVersioning(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	v, err := s.MaxVersion(ctx, "my-skill")
	if err != nil {
		t.Fatalf("max version: %v", err)
	}
	if v != 0 {
		t.Fatalf("expected max version 0 for an unpublished skill, got %d", v)
	}

	publishVersion(t, s, "my-skill", "My Skill", "Does a thing", 1, time.Now())

	got, err := s.GetSkill(ctx, "my-skill")
	if err != nil {
		t.Fatalf("get skill: %v", err)
	}
	if got.CurrentVersion != 1 || got.Downloads != 0 {
		t.Errorf("unexpected skill: %+v", got)
	}

	detail, err := s.GetSkillDetail(ctx, "my-skill")
	if err != nil {
		t.Fatalf("get skill detail: %v", err)
	}
	if detail.Version != 1 || detail.Description != "Does a thing" {
		t.Errorf("unexpected skill detail: %+v", detail)
	}

	// Republishing the same skill_id should bump the version and leave
	// version 1 in the history.
	v2, err := s.MaxVersion(ctx, "my-skill")
	if err != nil {
		t.Fatalf("max version 2: %v", err)
	}
	if v2 != 1 {
		t.Fatalf("expected max version 1 before the second publish, got %d", v2)
	}
	publishVersion(t, s, "my-skill", "My Skill", "Does an even better thing", v2+1, time.Now())

	got, err = s.GetSkill(ctx, "my-skill")
	if err != nil {
		t.Fatalf("get skill after republish: %v", err)
	}
	if got.CurrentVersion != 2 {
		t.Errorf("current version = %d, want 2", got.CurrentVersion)
	}
	detail, err = s.GetSkillDetail(ctx, "my-skill")
	if err != nil {
		t.Fatalf("get skill detail after republish: %v", err)
	}
	if detail.Version != 2 || detail.Description != "Does an even better thing" {
		t.Errorf("unexpected skill detail after republish: %+v", detail)
	}

	versions, err := s.ListSkillVersions(ctx, "my-skill")
	if err != nil {
		t.Fatalf("list skill versions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions in history, got %d", len(versions))
	}
	if versions[0].Version != 2 || versions[1].Version != 1 {
		t.Errorf("expected versions newest-first [2,1], got %+v", versions)
	}

	v1, err := s.GetSkillVersion(ctx, "my-skill", 1)
	if err != nil {
		t.Fatalf("get skill version 1: %v", err)
	}
	if v1.Description != "Does a thing" {
		t.Errorf("version 1 description = %q, want %q", v1.Description, "Does a thing")
	}

	if err := s.IncrementDownloads(ctx, "my-skill"); err != nil {
		t.Fatalf("increment downloads: %v", err)
	}
	got, err = s.GetSkill(ctx, "my-skill")
	if err != nil {
		t.Fatalf("get skill after download: %v", err)
	}
	if got.Downloads != 1 {
		t.Errorf("downloads = %d, want 1", got.Downloads)
	}
}

func TestIncrementDownloadsNotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.IncrementDownloads(context.Background(), "nope"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func seedSkill(t *testing.T, s *Store, skillID, displayName, description string, downloads int64) {
	t.Helper()
	ctx := context.Background()
	publishVersion(t, s, skillID, displayName, description, 1, time.Now())
	for i := int64(0); i < downloads; i++ {
		if err := s.IncrementDownloads(ctx, skillID); err != nil {
			t.Fatalf("seed downloads for %s: %v", skillID, err)
		}
	}
}

func TestSearchSkills(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedSkill(t, s, "pdf-editor", "PDF Editor", "Edit PDF documents", 0)
	seedSkill(t, s, "weather", "Weather", "Get the current weather forecast", 0)

	results, err := s.SearchSkills(ctx, "pdf", 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 1 || results[0].SkillID != "pdf-editor" {
		t.Fatalf("unexpected search results: %+v", results)
	}

	results, err = s.SearchSkills(ctx, "forecast", 10)
	if err != nil {
		t.Fatalf("search description: %v", err)
	}
	if len(results) != 1 || results[0].SkillID != "weather" {
		t.Fatalf("unexpected search results for description match: %+v", results)
	}

	results, err = s.SearchSkills(ctx, "nonexistent", 10)
	if err != nil {
		t.Fatalf("search nonexistent: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected no results, got %+v", results)
	}
}

func TestTrendingSkillsOrdersByDownloads(t *testing.T) {
	s := newTestStore(t)
	seedSkill(t, s, "low", "Low", "low downloads", 1)
	seedSkill(t, s, "high", "High", "high downloads", 10)
	seedSkill(t, s, "mid", "Mid", "mid downloads", 5)

	results, err := s.TrendingSkills(context.Background(), 20)
	if err != nil {
		t.Fatalf("trending: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	order := []string{results[0].SkillID, results[1].SkillID, results[2].SkillID}
	want := []string{"high", "mid", "low"}
	for i := range want {
		if order[i] != want[i] {
			t.Errorf("trending order = %v, want %v", order, want)
		}
	}
}

func TestQuarantineExcludesFromSearchAndTrendingButNotDetail(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedSkill(t, s, "sketchy", "Sketchy", "a skill with a hidden problem", 0)

	if err := s.SetSkillVersionStatus(ctx, "sketchy", 1, SkillVersionQuarantined); err != nil {
		t.Fatalf("quarantine: %v", err)
	}

	results, err := s.SearchSkills(ctx, "sketchy", 10)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected quarantined skill to be excluded from search, got %+v", results)
	}

	trending, err := s.TrendingSkills(ctx, 10)
	if err != nil {
		t.Fatalf("trending: %v", err)
	}
	for _, r := range trending {
		if r.SkillID == "sketchy" {
			t.Errorf("expected quarantined skill to be excluded from trending, found %+v", r)
		}
	}

	active, err := s.ListActiveSkillDetails(ctx)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	for _, r := range active {
		if r.SkillID == "sketchy" {
			t.Errorf("expected quarantined skill to be excluded from ListActiveSkillDetails, found %+v", r)
		}
	}

	// Detail and versions endpoints still surface it, clearly marked.
	detail, err := s.GetSkillDetail(ctx, "sketchy")
	if err != nil {
		t.Fatalf("get skill detail: %v", err)
	}
	if detail.Status != SkillVersionQuarantined {
		t.Errorf("detail status = %s, want quarantined", detail.Status)
	}

	versions, err := s.ListSkillVersions(ctx, "sketchy")
	if err != nil {
		t.Fatalf("list skill versions: %v", err)
	}
	if len(versions) != 1 || versions[0].Status != SkillVersionQuarantined {
		t.Errorf("unexpected versions: %+v", versions)
	}
}

func TestSetSkillVersionStatusNotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetSkillVersionStatus(context.Background(), "nope", 1, SkillVersionQuarantined); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestScanCreateAndGetLatest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.GetLatestScan(ctx, ScanTargetSubmission, "sub-1"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound before any scan exists, got %v", err)
	}

	first := Scan{
		TargetType:                ScanTargetSubmission,
		TargetID:                  "sub-1",
		Trigger:                   ScanTriggerPipeline,
		Verdict:                   ScanVerdictPass,
		TextOnlyOK:                true,
		HiddenCharsFindingsJSON:   "[]",
		StaticPatternFindingsJSON: "[]",
		ScannedAt:                 time.Now(),
	}
	if _, err := s.CreateScan(ctx, first); err != nil {
		t.Fatalf("create first scan: %v", err)
	}

	llm := `{"risk":"suspicious","explanation":"looks odd"}`
	second := Scan{
		TargetType:                ScanTargetSubmission,
		TargetID:                  "sub-1",
		Trigger:                   ScanTriggerManual,
		Verdict:                   ScanVerdictFlagged,
		TextOnlyOK:                true,
		HiddenCharsFindingsJSON:   "[]",
		StaticPatternFindingsJSON: "[]",
		LLMAssessmentJSON:         &llm,
		ScannedAt:                 time.Now().Add(time.Minute),
	}
	secondID, err := s.CreateScan(ctx, second)
	if err != nil {
		t.Fatalf("create second scan: %v", err)
	}

	got, err := s.GetLatestScan(ctx, ScanTargetSubmission, "sub-1")
	if err != nil {
		t.Fatalf("get latest scan: %v", err)
	}
	if got.ID != secondID {
		t.Errorf("latest scan id = %d, want %d (the most recently created)", got.ID, secondID)
	}
	if got.Verdict != ScanVerdictFlagged || got.Trigger != ScanTriggerManual {
		t.Errorf("unexpected latest scan: %+v", got)
	}
	if got.LLMAssessmentJSON == nil || *got.LLMAssessmentJSON != llm {
		t.Errorf("llm assessment json = %v, want %q", got.LLMAssessmentJSON, llm)
	}

	// A scan against a different target type must not be conflated.
	if _, err := s.GetLatestScan(ctx, ScanTargetSkillVersion, "sub-1"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound for a different target type, got %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	sess := Session{
		ID:        "session-1",
		Email:     "alice@example.com",
		Role:      SessionRoleSubmitter,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	got, err := s.GetSession(ctx, "session-1")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if got.Email != "alice@example.com" || got.Role != SessionRoleSubmitter {
		t.Errorf("unexpected session: %+v", got)
	}

	if err := s.DeleteSession(ctx, "session-1"); err != nil {
		t.Fatalf("delete session: %v", err)
	}
	if _, err := s.GetSession(ctx, "session-1"); err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}

	// Deleting an id that was never created (or already deleted) is not an
	// error -- logout must always succeed.
	if err := s.DeleteSession(ctx, "never-existed"); err != nil {
		t.Errorf("delete of a nonexistent session id should not error, got %v", err)
	}
}

func TestSessionLifecycle_ExpiredTreatedAsNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	sess := Session{
		ID:        "expired-session",
		Email:     "bob@example.com",
		Role:      SessionRoleAdmin,
		CreatedAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour), // already in the past
	}
	if err := s.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	if _, err := s.GetSession(ctx, "expired-session"); err != ErrNotFound {
		t.Errorf("expected an expired session to be treated as not found, got %v", err)
	}
}

func TestRoleSatisfies(t *testing.T) {
	cases := []struct {
		have, need SessionRole
		want       bool
	}{
		{SessionRoleAdmin, SessionRoleAdmin, true},
		{SessionRoleAdmin, SessionRoleSubmitter, true},
		{SessionRoleSubmitter, SessionRoleSubmitter, true},
		{SessionRoleSubmitter, SessionRoleAdmin, false},
	}
	for _, c := range cases {
		if got := RoleSatisfies(c.have, c.need); got != c.want {
			t.Errorf("RoleSatisfies(%s, %s) = %v, want %v", c.have, c.need, got, c.want)
		}
	}
}

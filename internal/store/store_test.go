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

func TestSkillPublishAndVersioning(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	v, err := s.NextVersion(ctx, "my-skill")
	if err != nil {
		t.Fatalf("next version: %v", err)
	}
	if v != 1 {
		t.Fatalf("expected first version to be 1, got %d", v)
	}

	skill := Skill{
		SkillID:     "my-skill",
		DisplayName: "My Skill",
		Description: "Does a thing",
		Version:     v,
		Submitter:   "alice",
		PublishedAt: time.Now(),
		GitHubPath:  "my-skill/",
	}
	if err := s.UpsertSkill(ctx, skill); err != nil {
		t.Fatalf("upsert skill: %v", err)
	}

	got, err := s.GetSkill(ctx, "my-skill")
	if err != nil {
		t.Fatalf("get skill: %v", err)
	}
	if got.Version != 1 || got.Downloads != 0 {
		t.Errorf("unexpected skill: %+v", got)
	}

	// Republishing the same skill_id should bump the version.
	v2, err := s.NextVersion(ctx, "my-skill")
	if err != nil {
		t.Fatalf("next version 2: %v", err)
	}
	if v2 != 2 {
		t.Fatalf("expected second version to be 2, got %d", v2)
	}
	skill.Version = v2
	skill.Description = "Does an even better thing"
	if err := s.UpsertSkill(ctx, skill); err != nil {
		t.Fatalf("upsert skill v2: %v", err)
	}
	got, err = s.GetSkill(ctx, "my-skill")
	if err != nil {
		t.Fatalf("get skill after republish: %v", err)
	}
	if got.Version != 2 || got.Description != "Does an even better thing" {
		t.Errorf("unexpected skill after republish: %+v", got)
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
	if err := s.UpsertSkill(ctx, Skill{
		SkillID:     skillID,
		DisplayName: displayName,
		Description: description,
		Version:     1,
		Submitter:   "alice",
		PublishedAt: time.Now(),
		GitHubPath:  skillID + "/",
	}); err != nil {
		t.Fatalf("seed skill %s: %v", skillID, err)
	}
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
